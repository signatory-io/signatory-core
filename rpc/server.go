package rpc

import (
	"context"
	"sync"

	"github.com/signatory-io/signatory-core/rpc/types"
)

type Server struct {
	handler  *Handler
	cancel   chan<- struct{}
	done     <-chan struct{}
	listener types.EncodedListener
}

func (s *Server) Shutdown(ctx context.Context) error {
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

func (s *Server) Serve(l types.EncodedListener) (err error) {
	cancel := make(chan struct{})
	done := make(chan struct{})

	s.listener = l
	s.cancel = cancel
	s.done = done

	var wg sync.WaitGroup
	for {
		var conn types.EncodedConn
		if conn, err = l.Accept(); err != nil {
			break
		}
		wg.Add(1)
		go func() {
			rpc := New(conn, s.handler)
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
