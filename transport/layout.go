package transport

import (
	"github.com/signatory-io/signatory-core/transport/codec"
)

type Layout[M Message[Q, S, C], Q Request, S Response[C], C codec.Codec] interface {
	NewRequest(path string, method string, args ...any) (*Q, error)
	NewResponse(result []byte) (*S, error)
	NewErrorResponse(err error, code int) (*S, error)
	NewMessageFromRequest(id uint64, req *Request) M
	NewMessageFromResponse(id uint64, res *Response[C]) M
	Codec() C
}

type Message[Q Request, S Response[C], C codec.Codec] interface {
	IsValid() bool
	GetID() uint64
	GetRequest() *Q
	GetResponse() *S
}

type Request interface {
	GetPath() []string
	GetMethod() string
}

type Response[C codec.Codec] interface {
	GetResult() []byte
	GetError() *ErrorResponse[C]
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
