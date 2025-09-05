package server

import (
	"context"
	"sync"

	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/rpc"
)

type Server[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], C codec.Codec, Q rpc.RPCRequest, S transport.Response[C], T conn.EncodedConn[M, Q, S, C], L conn.Listener[T]] struct {
	Handler  *rpc.Handler
	cancel   chan<- struct{}
	done     <-chan struct{}
	listener L
}

func NewServer[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], C codec.Codec, Q rpc.RPCRequest, S transport.Response[C], T conn.EncodedConn[M, Q, S, C], L conn.Listener[T]](h *rpc.Handler) *Server[E, M, C, Q, S, T, L] {
	return &Server[E, M, C, Q, S, T, L]{
		Handler: h,
	}
}

func (s *Server[E, M, C, Q, S, T, L]) Shutdown(ctx context.Context) error {
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

func (s *Server[E, M, C, Q, S, T, L]) ServeRPC(l L) (err error) {
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
			rpc := rpc.New[E](conn, s.Handler)
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
