package secure

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/rpc/conn"
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type encodedReadWriter interface {
	ReadMessage(v any) error
	WriteMessage(v any) error
}

func exchange[T any, C encodedReadWriter](c C, data *T) (out *T, err error) {
	out = new(T)
	errCh := make(chan error)
	go func() {
		errCh <- c.WriteMessage(data)
	}()
	go func() {
		errCh <- c.ReadMessage(out)
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
	tagSuite   = "SIGNATORY_SECURE_CONNECTION_X25519_ED25519"
	tagSecret  = "DH_SECRET"
	tagEphKeys = "EPHEMERAL_PUBLIC_KEYS_XOR_COMBINED"
	tagAuth    = "AUTHENTICATION_PUBLIC_KEYS_XOR_COMBINED"
	tagLen     = "SIGNATORY_SECURE_CONNECTION_LENGTH_KEY"
	tagPayload = "SIGNATORY_SECURE_CONNECTION_PAYLOAD_KEY"
)

type sessionKeys struct {
	rdLength  []byte
	rdPayload []byte
	wrLength  []byte
	wrPayload []byte
}

// We don't need a counter mode here because desired key length is 32 bytes. So it's not even an expansion --Eugene
func genSingle(prk []byte, info []byte, tag string) []byte {
	kdf, _ := blake2b.New256(prk)
	kdf.Write([]byte(tag))
	kdf.Write(info)
	return kdf.Sum(nil)
}

func twoComplementSub(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("inconsistent key lengths")
	}
	out := make([]byte, len(a))
	var borrow uint
	for i := len(a) - 1; i >= 0; i-- {
		diff := uint(a[i]) - uint(b[i]) - borrow
		out[i] = byte(diff)
		borrow = (diff >> 8) & 1
	}
	return out
}

func generateKeys(localEph, remoteEph *ecdh.PublicKey, secret []byte) sessionKeys {
	// Reinterpret public keys' raw bytes as big endian integers and subtract them.
	// It just looks a bit more elegant than comparing keys or doing some other branching to decide
	// who is a "client" and who is a "server" --Eugene

	rBytes := twoComplementSub(localEph.Bytes(), remoteEph.Bytes())
	wBytes := twoComplementSub(remoteEph.Bytes(), localEph.Bytes())

	prk := blake2b.Sum256(secret)

	return sessionKeys{
		rdLength:  genSingle(prk[:], rBytes, tagLen),
		rdPayload: genSingle(prk[:], rBytes, tagPayload),
		wrLength:  genSingle(prk[:], wBytes, tagLen),
		wrPayload: genSingle(prk[:], wBytes, tagPayload),
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

type Authenticator interface {
	// IsConnectionAllowed is called right after key exchange with optional unauthenticated peer key
	IsConnectionAllowed(remoteAddr net.Addr, unauthenticatedRemoteKey *ed25519.PublicKey) bool
	IsAuthenticatedPeerAllowed(remoteAddr net.Addr, authenticatedRemoteKey *ed25519.PublicKey) bool
}

func NewSecureConn(transport net.Conn, localKey *ed25519.PrivateKey, auth Authenticator) (*SecureConn, error) {
	eph, err := curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}
	rawConn := conn.NewEncodedStreamConn[codec.CBOR](transport)

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
	if helloResult.AuthPublicKey == nil || helloResult.EphemeralPublicKey == nil {
		return nil, errors.New("rpc: invalid handshake message")
	}
	if auth != nil && !auth.IsConnectionAllowed(transport.RemoteAddr(), helloResult.AuthPublicKey) {
		return nil, errors.New("rpc: connection disallowed")
	}

	remoteEphPub, err := curve().NewPublicKey(helloResult.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}
	remotePub := helloResult.AuthPublicKey

	secret, err := eph.ECDH(remoteEphPub)
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}

	combinedEphKeys := combineKeys(eph.PublicKey().Bytes(), remoteEphPub.Bytes())
	combinedAuthKeys := combineKeys(localPub[:], remotePub[:])

	ch, _ := blake2b.New256(nil)
	ch.Write([]byte(tagSuite))
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

	authResult, err := exchange(rawConn, &authMessage{
		ChallengeSignature: sig,
	})
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}
	if authResult.ChallengeSignature == nil {
		return nil, errors.New("rpc: invalid handshake message")
	}
	if !remotePub.VerifyMessageSignature(authResult.ChallengeSignature, challenge, nil) {
		return nil, errors.New("rpc: authentication error")
	}
	if auth != nil && !auth.IsAuthenticatedPeerAllowed(transport.RemoteAddr(), remotePub) {
		return nil, errors.New("rpc: authentication error")
	}

	keys := generateKeys(eph.PublicKey(), remoteEphPub, secret)
	conn := &SecureConn{
		conn:        transport,
		readCipher:  newPacketCipher(keys.rdLength, keys.rdPayload),
		writeCipher: newPacketCipher(keys.wrLength, keys.wrPayload),
		remotePub:   helloResult.AuthPublicKey,
		sessionID:   challenge,
	}

	return conn, nil
}

// This is almost identical to chacha20-poly1305@openssh.com suite except the length covers the entire packet
// including MAC and the padding is arbitrary sized.

type packetCipher struct {
	lengthKey     []byte
	payloadCipher cipher.AEAD
	buf           []byte
	nonce         uint64
}

func newPacketCipher(lengthKey, payloadKey []byte) packetCipher {
	plCipher, err := chacha20poly1305.New(payloadKey)
	if err != nil {
		panic(err)
	}
	return packetCipher{
		lengthKey:     lengthKey,
		payloadCipher: plCipher,
	}
}

func (p *packetCipher) readPacket(r io.Reader) ([]byte, error) {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:], p.nonce)

	var encLenghtBuf [4]byte
	if _, err := io.ReadFull(r, encLenghtBuf[:]); err != nil {
		return nil, err
	}
	lc, err := chacha20.NewUnauthenticatedCipher(p.lengthKey, nonce[:])
	if err != nil {
		panic(err)
	}
	var lengthBuf [4]byte
	lc.XORKeyStream(lengthBuf[:], encLenghtBuf[:])
	length := int(binary.BigEndian.Uint32(lengthBuf[:]))

	if length < chacha20poly1305.Overhead+4 {
		return nil, errors.New("packet is too short")
	}
	if len(p.buf) < length {
		p.buf = make([]byte, length)
	}
	payload := p.buf[:length]
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	if _, err = p.payloadCipher.Open(payload[:0], nonce[:], payload, encLenghtBuf[:]); err != nil {
		return nil, err
	}
	p.nonce++
	unpaddedLength := int(binary.BigEndian.Uint32(payload[:4]))
	if unpaddedLength > length-4-chacha20poly1305.Overhead {
		return nil, errors.New("invalid unpadded length")
	}
	return payload[4 : 4+unpaddedLength], nil
}

const granularity = 64

func (p *packetCipher) writePacket(w io.Writer, data []byte) error {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:], p.nonce)

	total := 4 + 4 + len(data) + chacha20poly1305.Overhead
	padded := (total + granularity - 1) &^ (granularity - 1)
	if len(p.buf) < padded {
		p.buf = make([]byte, padded)
	}
	length := padded - 4
	dataLen := length - chacha20poly1305.Overhead

	lc, err := chacha20.NewUnauthenticatedCipher(p.lengthKey, nonce[:])
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
	p.payloadCipher.Seal(payload[:0], nonce[:], payload, p.buf[:4])
	packet := p.buf[:padded]
	if _, err = w.Write(packet); err != nil {
		return err
	}
	p.nonce++
	return nil
}

type SecureConn struct {
	conn                    net.Conn
	readCipher, writeCipher packetCipher
	remotePub               *ed25519.PublicKey
	sessionID               []byte
}

func (c *SecureConn) ReadPacket() ([]byte, error)   { return c.readCipher.readPacket(c.conn) }
func (c *SecureConn) WritePacket(data []byte) error { return c.writeCipher.writePacket(c.conn, data) }

type AuthenticatedConn interface {
	SessionID() []byte
	RemotePublicKey() *ed25519.PublicKey
}

func (c *SecureConn) RemotePublicKey() *ed25519.PublicKey { return c.remotePub }
func (c *SecureConn) SessionID() []byte                   { return c.sessionID }
func (c *SecureConn) Close() error                        { return c.conn.Close() }
func (c *SecureConn) SetDeadline(t time.Time) error       { return c.conn.SetDeadline(t) }
func (c *SecureConn) LocalAddr() net.Addr                 { return c.conn.LocalAddr() }
func (c *SecureConn) RemoteAddr() net.Addr                { return c.conn.RemoteAddr() }

var (
	_ AuthenticatedConn = (*SecureConn)(nil)
)
