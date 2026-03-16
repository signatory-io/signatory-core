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
	require.Equal(t, uint64(0), msg.GetID())
	require.Equal(t, json.RawMessage("null"), msg.Result)
	buf, err := json.Marshal(&msg)
	require.NoError(t, err)
	require.Equal(t, []byte("{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":null}"), buf)
}

func TestNonNilResponse(t *testing.T) {
	var l Layout
	msg := l.NewResponse(0, &rpc.Response[codec.JSON]{
		Result: []byte("\"text\""),
	})
	require.Equal(t, uint64(0), msg.GetID())
	require.Equal(t, json.RawMessage("\"text\""), msg.Result)
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

func TestStringIDPreserved(t *testing.T) {
	src := []byte(`{"jsonrpc":"2.0","id":"abc-123","method":"eth_sign","params":["0xdeadbeef"]}`)
	var m Message
	err := json.Unmarshal(src, &m)
	require.NoError(t, err)
	require.True(t, m.IsValid())
	require.NotNil(t, m.GetRequest())
	require.NotZero(t, m.GetID())

	var l Layout
	resp := l.NewResponseFrom(m, &rpc.Response[codec.JSON]{
		Result: []byte("\"0xsignature\""),
	})
	buf, err := json.Marshal(&resp)
	require.NoError(t, err)
	require.Equal(t, []byte(`{"jsonrpc":"2.0","id":"abc-123","result":"0xsignature"}`), buf)
}

func TestNumericStringIDPreserved(t *testing.T) {
	src := []byte(`{"jsonrpc":"2.0","id":"42","method":"eth_sign","params":["0xdeadbeef"]}`)
	var m Message
	err := json.Unmarshal(src, &m)
	require.NoError(t, err)
	require.Equal(t, uint64(42), m.GetID())

	var l Layout
	resp := l.NewResponseFrom(m, &rpc.Response[codec.JSON]{
		Result: []byte("\"0xsignature\""),
	})
	buf, err := json.Marshal(&resp)
	require.NoError(t, err)
	require.Equal(t, []byte(`{"jsonrpc":"2.0","id":"42","result":"0xsignature"}`), buf)
}

func TestNumericIDPreserved(t *testing.T) {
	src := []byte(`{"jsonrpc":"2.0","id":42,"method":"eth_sign","params":["0xdeadbeef"]}`)
	var m Message
	err := json.Unmarshal(src, &m)
	require.NoError(t, err)
	require.Equal(t, uint64(42), m.GetID())

	var l Layout
	resp := l.NewResponseFrom(m, &rpc.Response[codec.JSON]{
		Result: []byte("\"0xsignature\""),
	})
	buf, err := json.Marshal(&resp)
	require.NoError(t, err)
	require.Equal(t, []byte(`{"jsonrpc":"2.0","id":42,"result":"0xsignature"}`), buf)
}

func TestNewResponseUsesNumericID(t *testing.T) {
	var l Layout
	resp := l.NewResponse(99, &rpc.Response[codec.JSON]{
		Result: []byte("\"ok\""),
	})
	buf, err := json.Marshal(&resp)
	require.NoError(t, err)
	require.Equal(t, []byte(`{"jsonrpc":"2.0","id":99,"result":"ok"}`), buf)
}
