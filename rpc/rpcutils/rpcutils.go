package rpcutils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/signatory-io/signatory-core/logger"
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/conn"
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
	"github.com/signatory-io/signatory-core/rpc/conn/secure"
	"github.com/signatory-io/signatory-core/utils"
)

type Service interface {
	Shutdown(ctx context.Context) error
}

type svc[E rpc.Layout[C, M], M rpc.Message[C], C codec.Codec, T conn.EncodedConn[C], L conn.Listener[T]] struct {
	log logger.Logger
	srv *rpc.Server[E, M, C, T, L]
}

func (s *svc[E, M, C, T, L]) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

type httpSvc struct {
	log logger.Logger
	srv *http.Server
}

func (s *httpSvc) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func NewRPCService[E rpc.Layout[C, M], M rpc.Message[C], C codec.Codec](endpointURL string, h *rpc.Handler, log logger.Logger, g utils.GlobalOptions) (Service, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return nil, err
	}
	l := log.With("address", u.Host)

	switch u.Scheme {
	case "tcp":
		tl, err := net.Listen("tcp", u.Host)
		if err != nil {
			return nil, err
		}
		listener := conn.NewEncodedStreamListener[C](tl)
		srv := rpc.NewServer[E, M, C, *conn.EncodedStreamConn[C], *conn.EncodedStreamListener[C, net.Listener]](h)

		go func() {
			if err := srv.Serve(listener); err != nil {
				l.Error(err)
			}
		}()

		return &svc[E, M, C, *conn.EncodedStreamConn[C], *conn.EncodedStreamListener[C, net.Listener]]{
			srv: srv,
			log: l,
		}, nil

	case "secure":
		key, err := utils.LoadIdentity(utils.GetPath(u.Fragment, g))
		if err != nil {
			return nil, err
		}
		tl, err := net.Listen("tcp", u.Host)
		if err != nil {
			return nil, err
		}
		listener := conn.NewEncodedPacketListener[C](&secure.SecureListener{
			Listener:   tl,
			PrivateKey: key,
			// TODO: Authenticator
		})
		srv := rpc.NewServer[E, M, C, *conn.EncodedPacketConn[C, *secure.SecureConn], *conn.EncodedPacketListener[C, *secure.SecureListener, *secure.SecureConn]](h)
		go func() {
			if err := srv.Serve(&listener); err != nil {
				l.Error(err)
			}
		}()

		return &svc[E, M, C, *conn.EncodedPacketConn[C, *secure.SecureConn], *conn.EncodedPacketListener[C, *secure.SecureListener, *secure.SecureConn]]{
			srv: srv,
			log: l,
		}, nil

	case "http":
		srv := http.Server{
			Addr:    u.Host,
			Handler: rpc.NewHTTPHandler[E](h),
			// TODO: TLS
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				l.Error(err)
			}
		}()
		return &httpSvc{
			srv: &srv,
			log: l,
		}, nil

	default:
		return nil, fmt.Errorf("unknown RPC transport: %s", u.Scheme)
	}
}

type httpWrapper[L rpc.Layout[C, M], C codec.Codec, M rpc.Message[C]] struct {
	*rpc.HTTPClient[L, C, M]
}

func (h httpWrapper[L, C, M]) Close() error { return nil }

type CallerCloser interface {
	rpc.Caller
	Close() error
}

func NewRPCClient[E rpc.Layout[C, M], M rpc.Message[C], C codec.Codec](ctx context.Context, endpointURL string, h *rpc.Handler, g utils.GlobalOptions) (CallerCloser, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "tcp":
		var d net.Dialer
		tcpConn, err := d.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return nil, err
		}
		c := conn.NewEncodedStreamConn[C](tcpConn)
		return rpc.New[E](c, h), nil

	case "secure":
		var d net.Dialer
		tcpConn, err := d.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return nil, err
		}
		key, err := utils.LoadIdentity(utils.GetPath(u.Fragment, g))
		if err != nil {
			return nil, err
		}
		secureConn, err := secure.NewSecureConn(tcpConn, key, nil)
		if err != nil {
			return nil, err
		}
		c := conn.NewEncodedPacketConn[C](secureConn)
		return rpc.New[E](c, h), nil

	case "http":
		return httpWrapper[E, C, M]{rpc.NewHTTPClient[E](endpointURL, nil)}, nil

	default:
		return nil, fmt.Errorf("unknown RPC transport: %s", u.Scheme)
	}
}
