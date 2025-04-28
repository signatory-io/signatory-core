package rpc

import (
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

type Encodong[C codec.Codec, M Message[C]] interface {
	NewRequest(id uint64, r *Request) M
	NewResponse(id uint64, r *Response[C]) M
	Codec() C
}

type Message[C codec.Codec] interface {
	GetID() uint64
	GetRequest() *Request
	GetResponse() *Response[C]
}

type Request struct {
	Path       []string
	Method     string
	Parameters [][]byte
}

type Response[C codec.Codec] struct {
	Result []byte
	Error  *ErrorResponse[C]
}

type ErrorResponse[C codec.Codec] struct {
	Code    int
	Message string
	Content []byte
}

func (e *ErrorResponse[C]) Error() string  { return e.Message }
func (e *ErrorResponse[C]) ErrorCode() int { return e.Code }

func (e *ErrorResponse[C]) ErrorContent(v any) (ok bool, err error) {
	if e.Content == nil {
		return false, nil
	}
	var codec C
	if err = codec.Unmarshal(e.Content, v); err != nil {
		return false, err
	}
	return true, nil
}
