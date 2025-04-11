package rpc

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"

	"github.com/fxamacker/cbor/v2"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type encodedConn interface {
	readMessage(v any) error
	writeMessage(v any) error
}

type cborStream struct {
	conn      io.ReadWriter
	encBuffer bytes.Buffer
	dec       *cbor.Decoder
}

func newCborStream(conn io.ReadWriter) *cborStream {
	return &cborStream{
		dec:  cbor.NewDecoder(conn),
		conn: conn,
	}
}

func (c *cborStream) writeMessage(v any) error {
	c.encBuffer.Reset()
	if err := cbor.MarshalToBuffer(v, &c.encBuffer); err != nil {
		return err
	}
	_, err := c.conn.Write(c.encBuffer.Bytes())
	return err
}

func (c *cborStream) readMessage(v any) error { return c.dec.Decode(v) }

func exchange[T any](c encodedConn, data *T) (out *T, err error) {
	out = new(T)
	errCh := make(chan error)
	go func() {
		errCh <- c.writeMessage(data)
	}()
	go func() {
		errCh <- c.readMessage(out)
	}()
	for range 2 {
		e := <-errCh
		if err == nil {
			err = e
		}
	}
	return
}

func curve() ecdh.Curve { return ecdh.X25519() }

func combineKeys(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("inconsistent key lengths")
	}
	out := make([]byte, len(a))
	for i := range len(a) {
		out[i] = a[i] ^ b[i]
	}
	return out
}

const (
	tagSecret  = "X25519Secret"
	tagEphKeys = "Curve25519EphemeralPublicKeysXorCombined"
	tagAuth    = "AuthenticationPublicKeysXorCombined"
	tagLen     = "SignatorySecureConnectionLengthKey"
	tagPayload = "SignatorySecureConnectionPayloadKey"
)

type sessionKeys struct {
	rdLen, rdPl, wrLen, wrPl []byte
}

// We don't need a counter mode here because desired key length is 32 bytes. So it's not even an expansion --Eugene
func genSingle(prk []byte, info []byte, tag string) []byte {
	kdf, _ := blake2b.New256(prk)
	kdf.Write([]byte(tag))
	kdf.Write(info)
	return kdf.Sum(nil)
}

func generateKeys(localEph, remoteEph *ecdh.PublicKey, secret []byte) sessionKeys {
	// Reinterpret public keys' raw bytes as big endian integers and subtract them.
	// It just looks a bit more elegant than comparing keys or doing some other branching to decide
	// who is a "client" and who is a "server" --Eugene

	loc := new(big.Int).SetBytes(localEph.Bytes())
	rem := new(big.Int).SetBytes(remoteEph.Bytes())

	rDiff := new(big.Int).Sub(loc, rem)
	wDiff := new(big.Int).Neg(rDiff)

	rBytes := rDiff.Bytes()
	wBytes := wDiff.Bytes()

	prk := blake2b.Sum256(secret)

	return sessionKeys{
		rdLen: genSingle(prk[:], rBytes, tagLen),
		rdPl:  genSingle(prk[:], rBytes, tagPayload),
		wrLen: genSingle(prk[:], wBytes, tagLen),
		wrPl:  genSingle(prk[:], wBytes, tagPayload),
	}
}

type helloMessage struct {
	_                  struct{} `cbor:",toarray"`
	EphemeralPublicKey []byte
	AuthPublicKey      *ed25519.PublicKey
}

type authMessage struct {
	_                  struct{} `cbor:",toarray"`
	ChallengeSignature *ed25519.Signature
}

func NewConnection(transport net.Conn, localKey *ed25519.PrivateKey) (*Conn, error) {
	eph, err := curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}
	rawConn := newCborStream(transport)

	var localPub *ed25519.PublicKey
	if localKey != nil {
		localPub = localKey.Public().(*ed25519.PublicKey)
	}
	helloResult, err := exchange(rawConn, &helloMessage{
		EphemeralPublicKey: eph.PublicKey().Bytes(),
		AuthPublicKey:      localPub,
	})
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}
	if helloResult.AuthPublicKey == nil && localKey != nil || helloResult.AuthPublicKey != nil && localKey == nil {
		return nil, errors.New("rpc: inconsistent authentication settings")
	}
	authenticate := localKey != nil

	remoteEphPub, err := curve().NewPublicKey(helloResult.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}

	secret, err := eph.ECDH(remoteEphPub)
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}

	keys := generateKeys(eph.PublicKey(), remoteEphPub, secret)
	rplc, err := chacha20poly1305.New(keys.rdPl)
	if err != nil {
		panic(err)
	}
	wplc, err := chacha20poly1305.New(keys.wrPl)
	if err != nil {
		panic(err)
	}
	conn := &Conn{
		conn: transport,
		readCipher: packetCipher{
			lenKey:   keys.rdLen,
			plCipher: rplc,
		},
		writeCipher: packetCipher{
			lenKey:   keys.wrLen,
			plCipher: wplc,
		},
	}

	if !authenticate {
		return conn, nil
	}
	conn.remotePub = helloResult.AuthPublicKey
	combinedEphKeys := combineKeys(eph.PublicKey().Bytes(), remoteEphPub.Bytes())
	combinedAuthKeys := combineKeys(localPub[:], conn.remotePub[:])

	ch, _ := blake2b.New256(nil)
	ch.Write([]byte(tagEphKeys))
	ch.Write(combinedEphKeys)
	ch.Write([]byte(tagAuth))
	ch.Write(combinedAuthKeys)
	ch.Write([]byte(tagSecret))
	ch.Write(secret)
	challenge := ch.Sum(nil)

	s, err := localKey.SignMessage(challenge, nil)
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}
	sig := s.(*ed25519.Signature)

	authResult, err := exchange(conn, &authMessage{
		ChallengeSignature: sig,
	})
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}
	if !conn.remotePub.VerifyMessageSignature(authResult.ChallengeSignature, challenge, nil) {
		return nil, errors.New("rpc: authentication error")
	}
	return conn, nil
}

// This is almost identical to chacha20-poly1305@openssh.com suite except the length covers the entire packet
// including MAC and the padding is arbitrary sized.

type packetCipher struct {
	lenKey   []byte
	plCipher cipher.AEAD
	buf      []byte
	nonce    uint64
}

const minimalBufferSize = 4 + 4 + chacha20poly1305.Overhead

func (p *packetCipher) readPacket(r io.Reader) ([]byte, error) {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:], p.nonce)

	if len(p.buf) < minimalBufferSize {
		p.buf = make([]byte, minimalBufferSize)
	}
	if _, err := io.ReadFull(r, p.buf[:4]); err != nil {
		return nil, err
	}
	lc, err := chacha20.NewUnauthenticatedCipher(p.lenKey, nonce[:])
	if err != nil {
		panic(err)
	}
	var lengthBuf [4]byte
	lc.XORKeyStream(lengthBuf[:], p.buf[:4])
	length := int(binary.BigEndian.Uint32(lengthBuf[:]))

	if length < chacha20poly1305.Overhead+4 {
		return nil, errors.New("packet is too short")
	}
	if len(p.buf) < 4+length {
		p.buf = make([]byte, 4+length)
	}
	payload := p.buf[4 : 4+length]
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	if _, err = p.plCipher.Open(payload[:0], nonce[:], payload, p.buf[:4]); err != nil {
		return nil, err
	}
	p.nonce++
	unpaddedLength := int(binary.BigEndian.Uint32(payload[:4]))
	if unpaddedLength > length-4-chacha20poly1305.Overhead {
		return nil, errors.New("invalid unpadded length")
	}
	return payload[4 : 4+unpaddedLength], nil
}

func (p *packetCipher) writePacket(w io.Writer, data []byte, paddingLen int) error {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:], p.nonce)

	dataLen := 4 + len(data) + paddingLen
	length := dataLen + chacha20poly1305.Overhead
	if len(p.buf) < 4+length {
		p.buf = make([]byte, 4+length)
	}

	lc, err := chacha20.NewUnauthenticatedCipher(p.lenKey, nonce[:])
	if err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint32(p.buf[:4], uint32(length))
	lc.XORKeyStream(p.buf[:4], p.buf[:4])

	payload := p.buf[4 : 4+dataLen]
	binary.BigEndian.PutUint32(payload[:4], uint32(len(data)))
	copy(payload[4:], data)
	toPad := payload[4+len(data) : dataLen]
	if len(toPad) != 0 {
		rand.Read(toPad)
	}
	p.plCipher.Seal(payload[:0], nonce[:], payload, p.buf[:4])
	packet := p.buf[:4+length]
	if _, err = w.Write(packet); err != nil {
		return err
	}
	p.nonce++
	return nil
}

type Conn struct {
	conn                    net.Conn
	readCipher, writeCipher packetCipher
	encBuffer               bytes.Buffer
	remotePub               *ed25519.PublicKey
}

const granularity = 8

func (c *Conn) readPacket() ([]byte, error) { return c.readCipher.readPacket(c.conn) }

func (c *Conn) writePacket(data []byte) error {
	total := 4 + 4 + len(data) + chacha20poly1305.Overhead
	padded := (total + granularity - 1) &^ (granularity - 1)
	return c.writeCipher.writePacket(c.conn, data, padded-total)
}

func (c *Conn) readMessage(v any) error {
	packet, err := c.readPacket()
	if err != nil {
		return err
	}
	return cbor.Unmarshal(packet, v)
}

func (c *Conn) writeMessage(v any) error {
	c.encBuffer.Reset()
	if err := cbor.MarshalToBuffer(v, &c.encBuffer); err != nil {
		return err
	}
	return c.writePacket(c.encBuffer.Bytes())
}
