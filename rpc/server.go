package rpc

import (
	"context"
	"sync"

	"github.com/signatory-io/signatory-core/rpc/types"
)

type Server struct {
	handler *Handler
	cancel  chan<- struct{}
	done    <-chan struct{}
}

func (s *Server) Shutdown(ctx context.Context) error {
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
	s.cancel = cancel
	s.done = done

	go func() {
		<-cancel
		l.Close()
	}()

	var wg sync.WaitGroup
	for {
		var conn types.EncodedConnection
		if conn, err = l.Accept(); err != nil {
			break
		}
		wg.Add(1)
		go func() {
			rpc := NewRPC(conn, s.handler)
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
