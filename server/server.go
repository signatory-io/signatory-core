package server

import (
	"context"
	"sync"

	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/protocol"
)

type Server[E protocol.Layout[C, M], C codec.Codec, M protocol.Message[C], T conn.EncodedConn[C, protocol.RPC[C, M], M], L conn.Listener[T]] struct {
	Handler  *transport.Handler
	cancel   chan<- struct{}
	done     <-chan struct{}
	listener L
}

func NewServer[E protocol.Layout[C, M], M protocol.Message[C], C codec.Codec, T conn.EncodedConn[C, protocol.RPC[C, M], M], L conn.Listener[T]](h *transport.Handler) *Server[E, C, M, T, L] {
	return &Server[E, C, M, T, L]{
		Handler: h,
	}
}

func (s *Server[E, C, M, T, L]) Shutdown(ctx context.Context) error {
	if err := s.listener.Close(); err != nil {
		return err
	}
	close(s.cancel)
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server[E, C, M, T, L]) ServeRPC(l L) (err error) {
	cancel := make(chan struct{})
	done := make(chan struct{})

	s.listener = l
	s.cancel = cancel
	s.done = done

	var wg sync.WaitGroup
	for {
		var conn T
		if conn, err = l.Accept(); err != nil {
			break
		}
		wg.Add(1)
		go func() {
			rpc := transport.New[E, C, M, T, protocol.RPC[C, M]](conn, s.Handler)
			select {
			case <-rpc.Done():
			case <-cancel:
				rpc.Close()
			}
			wg.Done()
		}()
	}
	wg.Wait()
	close(done)
	return
}
