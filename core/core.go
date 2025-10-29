package core

import (
	"context"

	"github.com/signatory-io/signatory-core/logger"
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/cbor"
	"github.com/signatory-io/signatory-core/rpc/rpcutils"
	"github.com/signatory-io/signatory-core/signer"
	signerapi "github.com/signatory-io/signatory-core/signer/api"
)

type Service struct {
	rpc    rpcutils.Service
	api    *signerapi.API
	logger logger.Logger
}

func New(ctx context.Context, conf *Config, logger logger.Logger) (*Service, error) {
	signer, err := signer.NewWithConfig(ctx, conf)
	if err != nil {
		return nil, err
	}
	api := signerapi.API{Signer: signer}
	handler := rpc.NewHandler()
	handler.Register(&api)
	l := logger.With("address", conf.RPCAddress)
	l.Info("Starting utility RPC service")
	rpc, err := rpcutils.NewRPCService[cbor.Layout](conf.RPCAddress, handler, logger, conf)
	if err != nil {
		return nil, err
	}
	return &Service{
		rpc:    rpc,
		api:    &api,
		logger: l,
	}, nil
}

func (s *Service) Signer() *signer.Signer { return s.api.Signer }
func (s *Service) Shutdown(ctx context.Context) error {
	s.logger.Info("Stopping utility RPC service")
	return s.rpc.Shutdown(ctx)
}
