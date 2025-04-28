package cbor

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

type Message struct {
	ID       uint64    `cbor:"0,keyasint"`
	Request  *Request  `cbor:"1,keyasint,omitempty"`
	Response *Response `cbor:"2,keyasint,omitempty"`
}

func (m Message) GetID() uint64 { return m.ID }

func (m Message) GetRequest() *rpc.Request {
	if q := m.Request; q != nil {
		params := make([][]byte, len(q.Parameters))
		for i, p := range q.Parameters {
			params[i] = []byte(p)
		}
		return &rpc.Request{
			Path:       q.Path,
			Method:     q.Method,
			Parameters: params,
		}
	}
	return nil
}

func (m Message) GetResponse() *rpc.Response[codec.CBOR] {
	if r := m.Response; r != nil {
		out := &rpc.Response[codec.CBOR]{
			Result: []byte(r.Result),
		}
		if e := r.Error; e != nil {
			out.Error = &rpc.ErrorResponse[codec.CBOR]{
				Code:    e.Code,
				Message: e.Message,
				Content: []byte(e.Content),
			}
		}
		return out
	}
	return nil
}

type Request struct {
	Path       []string          `cbor:"0,keyasint,omitempty"`
	Method     string            `cbor:"1,keyasint"`
	Parameters []cbor.RawMessage `cbor:"2,keyasint,omitempty"`
}

type Response struct {
	Result cbor.RawMessage `cbor:"0,keyasint,omitempty"`
	Error  *ErrorResponse  `cbor:"1,keyasint,omitempty"`
}

type ErrorResponse struct {
	Code    int             `cbor:"0,keyasint,omitempty"`
	Message string          `cbor:"1,keyasint,omitempty"`
	Content cbor.RawMessage `cbor:"2,keyasint,omitempty"`
}

func (e *ErrorResponse) Error() string  { return e.Message }
func (e *ErrorResponse) ErrorCode() int { return e.Code }

func (e *ErrorResponse) ErrorContent(v any) (ok bool, err error) {
	if e.Content == nil {
		return false, nil
	}
	if err = cbor.Unmarshal(e.Content, v); err != nil {
		return false, err
	}
	return true, nil
}

type Layout struct{}

func (Layout) NewRequest(id uint64, r *rpc.Request) Message {
	par := make([]cbor.RawMessage, len(r.Parameters))
	for i, p := range r.Parameters {
		par[i] = cbor.RawMessage(p)
	}
	return Message{
		ID: id,
		Request: &Request{
			Path:       r.Path,
			Method:     r.Method,
			Parameters: par,
		},
	}
}

func (Layout) NewResponse(id uint64, r *rpc.Response[codec.CBOR]) Message {
	res := Response{
		Result: cbor.RawMessage(r.Result),
	}
	if e := r.Error; e != nil {
		res.Error = &ErrorResponse{
			Code:    e.Code,
			Message: e.Message,
			Content: cbor.RawMessage(e.Content),
		}
	}
	return Message{
		ID:       id,
		Response: &res,
	}
}

func (Layout) Codec() codec.CBOR { return codec.CBOR{} }
