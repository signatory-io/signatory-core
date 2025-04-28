package json

import (
	"encoding/json"
	"testing"

	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
	"github.com/stretchr/testify/require"
)

func TestNilResponse(t *testing.T) {
	var l Layout
	msg := l.NewResponse(0, &rpc.Response[codec.JSON]{
		Result: nil,
	})
	require.Equal(t, &Message{
		ID:      0,
		Version: "2.0",
		Result:  json.RawMessage("null"),
	}, &msg)
	buf, err := json.Marshal(&msg)
	require.NoError(t, err)
	require.Equal(t, []byte("{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":null}"), buf)
}

func TestNonNilResponse(t *testing.T) {
	var l Layout
	msg := l.NewResponse(0, &rpc.Response[codec.JSON]{
		Result: []byte("\"text\""),
	})
	require.Equal(t, &Message{
		ID:      0,
		Version: "2.0",
		Result:  json.RawMessage("\"text\""),
	}, &msg)
	buf, err := json.Marshal(&msg)
	require.NoError(t, err)
	require.Equal(t, []byte("{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":\"text\"}"), buf)
}

func TestErrResponse(t *testing.T) {
	var l Layout
	msg := l.NewResponse(0, &rpc.Response[codec.JSON]{
		Error: &rpc.ErrorResponse[codec.JSON]{Code: 1, Message: "msg"},
	})
	buf, err := json.Marshal(&msg)
	require.NoError(t, err)
	require.Equal(t, []byte("{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{\"code\":1,\"message\":\"msg\"}}"), buf)
}

func TestParseNilResponse(t *testing.T) {
	src := []byte("{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":null}")
	var m Message
	err := json.Unmarshal(src, &m)
	require.NoError(t, err)
	require.True(t, m.IsValid())

	res := m.GetResponse()
	require.NotNil(t, res)
}

func TestParseInvalidResponse(t *testing.T) {
	src := []byte("{\"jsonrpc\":\"2.0\",\"id\":0}")
	var m Message
	err := json.Unmarshal(src, &m)
	require.NoError(t, err)
	require.False(t, m.IsValid())

	res := m.GetResponse()
	require.Nil(t, res)
}
