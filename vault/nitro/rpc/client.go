package rpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/signatory-io/signatory-core/logger"
)

const maxMessageSize = 2 * 1024 * 1024 // 2 MiB, aligned with tee-signer

type Client[C any] struct {
	conn net.Conn
	log  logger.Logger
}

func NewClient[C any](conn net.Conn, log logger.Logger) *Client[C] {
	return &Client[C]{conn: conn, log: log}
}

func (c *Client[C]) Close() error {
	return c.conn.Close()
}

var aLongTimeAgo = time.Unix(1, 0)

func RoundTripRaw[T, C any](ctx context.Context, conn net.Conn, log logger.Logger, req *Request[C]) (r T, err error) {
	var res T
	reqBuf, err := cbor.Marshal(req)
	if err != nil {
		return res, err
	}
	if log != nil {
		log.With("type", reqType(req)).Debug("nitro rpc request")
	}

	intErr := make(chan error)
	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			conn.SetDeadline(aLongTimeAgo)
			intErr <- ctx.Err()
		case <-done:
			intErr <- nil
		}
	}()

	defer func() {
		close(done)
		if e := <-intErr; e != nil {
			err = e
		}
		conn.SetDeadline(time.Time{})
	}()

	wrBuf := make([]byte, len(reqBuf)+4)
	binary.BigEndian.PutUint32(wrBuf, uint32(len(reqBuf)))
	copy(wrBuf[4:], reqBuf)
	if _, err := conn.Write(wrBuf); err != nil {
		return res, err
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return res, err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf[:])
	if msgLen > maxMessageSize {
		return res, fmt.Errorf("response size %d exceeds maximum %d", msgLen, maxMessageSize)
	}
	rBuf := make([]byte, int(msgLen))
	if _, err := io.ReadFull(conn, rBuf); err != nil {
		return res, err
	}
	err = cbor.Unmarshal(rBuf, &res)
	return res, err
}

func RoundTrip[T, C any](ctx context.Context, conn net.Conn, log logger.Logger, req *Request[C]) (r Result[*T], err error) {
	return RoundTripRaw[Result[*T]](ctx, conn, log, req)
}

func (c *Client[C]) Initialize(ctx context.Context, cred *C) error {
	res, err := RoundTrip[struct{}](ctx, c.conn, c.log, &Request[C]{Initialize: cred})
	if err != nil {
		return err
	}
	return res.Error()
}

func (c *Client[C]) Load(ctx context.Context, keyData []byte) (*LoadResult, error) {
	res, err := RoundTrip[LoadResult](ctx, c.conn, c.log, &Request[C]{Import: keyData})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}

func (c *Client[C]) Import(ctx context.Context, priv *PrivateKey) (*ImportResult, error) {
	res, err := RoundTrip[ImportResult](ctx, c.conn, c.log, &Request[C]{ImportUnencrypted: priv})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}

func (c *Client[C]) Generate(ctx context.Context, keyType KeyType) (*GenerateResult, error) {
	res, err := RoundTrip[GenerateResult](ctx, c.conn, c.log, &Request[C]{Generate: &keyType})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}

func (c *Client[C]) SignDigest(ctx context.Context, handle uint64, digest []byte) (*RPCSignature, error) {
	res, err := RoundTrip[RPCSignature](ctx, c.conn, c.log, &Request[C]{
		SignDigest: &SignDigestRequest{Handle: handle, Digest: digest},
	})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}

func reqType[C any](req *Request[C]) string {
	switch {
	case req.Initialize != nil:
		return "Initialize"
	case req.Import != nil:
		return "Import"
	case req.ImportUnencrypted != nil:
		return "ImportUnencrypted"
	case req.Generate != nil:
		return "Generate"
	case req.Sign != nil:
		return "Sign"
	case req.SignDigest != nil:
		return "SignDigest"
	default:
		return "unknown"
	}
}
