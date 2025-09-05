package cbor

import (
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
)

type Request struct {
	Path       []string          `cbor:"0,keyasint,omitempty"`
	Method     string            `cbor:"1,keyasint"`
	Parameters []cbor.RawMessage `cbor:"2,keyasint,omitempty"`
}

func (r Request) GetPath() []string { return r.Path }
func (r Request) GetMethod() string { return r.Method }
func (r Request) GetParameters() [][]byte {
	params := make([][]byte, len(r.Parameters))
	for i, p := range r.Parameters {
		params[i] = []byte(p)
	}
	return params
}

type Response struct {
	Result cbor.RawMessage `cbor:"0,keyasint,omitempty"`
	Error  *Error          `cbor:"1,keyasint,omitempty"`
}

func (r Response) GetResult() []byte { return r.Result }
func (r Response) GetError() *transport.ErrorResponse[codec.CBOR] {
	if r.Error == nil {
		return nil
	}
	return &transport.ErrorResponse[codec.CBOR]{
		Code:    r.Error.Code,
		Message: r.Error.Message,
		Content: r.Error.Content,
	}
}

type Error struct {
	Code    int             `cbor:"0,keyasint,omitempty"`
	Message string          `cbor:"1,keyasint,omitempty"`
	Content cbor.RawMessage `cbor:"2,keyasint,omitempty"`
}

type Message struct {
	ID       uint64    `cbor:"0,keyasint"`
	Request  *Request  `cbor:"1,keyasint,omitempty"`
	Response *Response `cbor:"2,keyasint,omitempty"`
}

func (m Message) IsValid() bool {
	return m.Request != nil && m.Response == nil ||
		m.Request == nil || m.Response != nil
}

func (m Message) GetID() uint64 { return m.ID }

func (m Message) GetRequest() *Request {
	if q := m.Request; q != nil {
		var params []cbor.RawMessage
		if len(q.Parameters) != 0 {
			params = make([]cbor.RawMessage, len(q.Parameters))
			for i, p := range q.Parameters {
				params[i] = cbor.RawMessage(p)
			}
		}
		return &Request{
			Path:       q.Path,
			Method:     q.Method,
			Parameters: params,
		}
	}
	return nil
}

func (m Message) GetResponse() *Response {
	if r := m.Response; r != nil {
		if e := r.GetError(); e != nil {
			return &Response{
				Error: &Error{
					Code:    e.Code,
					Message: e.Message,
					Content: cbor.RawMessage(e.Content),
				},
			}
		} else {
			return &Response{
				Result: []byte(r.Result),
			}
		}
	}
	return nil
}

type Layout struct{}

func (Layout) NewRequest(path string, method string, args ...any) (*Request, error) {
	params := make([]cbor.RawMessage, len(args))
	var codec codec.CBOR
	var err error
	for i, arg := range args {
		if params[i], err = codec.Marshal(arg); err != nil {
			return &Request{}, err
		}
	}
	return &Request{
		Path:       strings.Split(path, "/"),
		Method:     method,
		Parameters: params,
	}, nil
}

func (Layout) NewResponse(result []byte) (*Response, error) {
	return &Response{
		Result: cbor.RawMessage(result),
	}, nil
}

func (Layout) NewErrorResponse(err error, code int) (*Response, error) {
	var content cbor.RawMessage
	var cod codec.CBOR
	if err, ok := err.(transport.Error); ok {
		code = err.ErrorCode()
		if err, ok := err.(transport.ErrorEx); ok {
			if c, err := cod.Marshal(err.ErrorContent()); err == nil {
				content = c
			}
		}
	}
	if code == 0 {
		code = transport.CodeDefault
	}
	return &Response{
		Error: &Error{
			Code:    code,
			Message: err.Error(),
			Content: content,
		},
	}, nil
}

func (Layout) NewMessageFromRequest(id uint64, r *transport.Request) Message {
	var par []cbor.RawMessage
	if r, ok := (*r).(Request); ok {
		if len(r.GetParameters()) != 0 {
			par = make([]cbor.RawMessage, len(r.GetParameters()))
			for i, p := range r.GetParameters() {
				par[i] = cbor.RawMessage(p)
			}
		}
	}
	return Message{
		ID: id,
		Request: &Request{
			Path:       (*r).GetPath(),
			Method:     (*r).GetMethod(),
			Parameters: par,
		},
	}
}

func (Layout) NewMessageFromResponse(id uint64, res *transport.Response[codec.CBOR]) Message {
	var r Response
	if e := (*res).GetError(); e != nil {
		r.Error = &Error{
			Code:    e.Code,
			Message: e.Message,
			Content: cbor.RawMessage(e.Content),
		}
	} else {
		r.Result = cbor.RawMessage((*res).GetResult())
	}
	return Message{
		ID:       id,
		Response: &r,
	}
}

func (Layout) Codec() codec.CBOR { return codec.CBOR{} }
