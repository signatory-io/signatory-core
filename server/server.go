package server

import (
	"context"
	"sync"

	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
)

type Server[E transport.Layout[C, M], M transport.Message[C], C codec.Codec, T conn.EncodedConn[C], L conn.Listener[T]] struct {
	Handler  *transport.Handler
	cancel   chan<- struct{}
	done     <-chan struct{}
	listener L
}

func NewServer[E transport.Layout[C, M], M transport.Message[C], C codec.Codec, T conn.EncodedConn[C], L conn.Listener[T]](h *transport.Handler) *Server[E, M, C, T, L] {
	return &Server[E, M, C, T, L]{
		Handler: h,
	}
}

func (s *Server[E, M, C, T, L]) Shutdown(ctx context.Context) error {
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

func (s *Server[E, M, C, T, L]) ServeRPC(l L) (err error) {
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
			rpc := transport.New[E, M, C, T](conn, s.Handler)
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
