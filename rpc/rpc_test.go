package rpc

import (
	"context"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestMethodCall(t *testing.T) {
	f1 := func(_ context.Context, x int) (int, error) {
		return x, nil
	}
	m1 := NewMethod(f1)
	arg := int(1)
	v, _ := cbor.Marshal(&arg)
	res, err := m1.call(context.Background(), []cbor.RawMessage{v})
	require.NoError(t, err)

	var r int
	require.NoError(t, cbor.Unmarshal(res.Result, &r))
	require.Equal(t, arg, r)
}

func TestMethodCallErr(t *testing.T) {
	f1 := func(_ context.Context, x int) (int, error) {
		return 0, errors.New("error")
	}
	m1 := NewMethod(f1)
	arg := int(1)
	v, _ := cbor.Marshal(&arg)
	res, err := m1.call(context.Background(), []cbor.RawMessage{v})
	require.NoError(t, err)

	require.Equal(t, &response{Error: &errorResponse{Message: "error"}}, res)
}
