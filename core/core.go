package core

import (
	"context"

	"github.com/signatory-io/signatory-core/logger"
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/cbor"
	"github.com/signatory-io/signatory-core/rpc/rpcutils"
	"github.com/signatory-io/signatory-core/signer"
	signerapi "github.com/signatory-io/signatory-core/signer/api"
	"github.com/sirupsen/logrus"
)

type CoreService struct {
	rpc rpcutils.Service
	api *signerapi.API
}

func New(ctx context.Context, conf *Config, logger logger.Logger) (*CoreService, error) {
	if logger == nil {
		logger = LogrusAdapter{Logger: logrus.StandardLogger()}
	}
	signer, err := signer.NewWithConfig(ctx, conf)
	if err != nil {
		return nil, err
	}
	api := signerapi.API{Signer: signer}
	handler := rpc.NewHandler()
	handler.Register(&api)
	rpc, err := rpcutils.NewRPCService[cbor.Layout](conf.RPCAddress, handler, logger, conf)
	if err != nil {
		return nil, err
	}
	return &CoreService{
		rpc: rpc,
		api: &api,
	}, nil
}

func (s *CoreService) Signer() *signer.Signer             { return s.api.Signer }
func (s *CoreService) Shutdown(ctx context.Context) error { return s.rpc.Shutdown(ctx) }
