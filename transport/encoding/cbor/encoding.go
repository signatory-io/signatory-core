package cbor

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/protocol"
)

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

func (m Message) GetRequest() *protocol.Request {
	if q := m.Request; q != nil {
		var params [][]byte
		if len(q.Parameters) != 0 {
			params = make([][]byte, len(q.Parameters))
			for i, p := range q.Parameters {
				params[i] = []byte(p)
			}
		}
		return &protocol.Request{
			Path:       q.Path,
			Method:     q.Method,
			Parameters: params,
		}
	}
	return nil
}

func (m Message) GetResponse() *protocol.Response[codec.CBOR] {
	if r := m.Response; r != nil {
		if e := r.Error; e != nil {
			return &protocol.Response[codec.CBOR]{
				Error: &protocol.ErrorResponse[codec.CBOR]{
					Code:    e.Code,
					Message: e.Message,
					Content: []byte(e.Content),
				},
			}
		} else {
			return &protocol.Response[codec.CBOR]{
				Result: []byte(r.Result),
			}
		}
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
	Error  *Error          `cbor:"1,keyasint,omitempty"`
}

type Error struct {
	Code    int             `cbor:"0,keyasint,omitempty"`
	Message string          `cbor:"1,keyasint,omitempty"`
	Content cbor.RawMessage `cbor:"2,keyasint,omitempty"`
}

type Layout struct{}

func (Layout) NewRequest(id uint64, r *protocol.Request) Message {
	var par []cbor.RawMessage
	if len(r.Parameters) != 0 {
		par = make([]cbor.RawMessage, len(r.Parameters))
		for i, p := range r.Parameters {
			par[i] = cbor.RawMessage(p)
		}
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

func (Layout) NewResponse(id uint64, res *protocol.Response[codec.CBOR]) Message {
	var r Response
	if e := res.Error; e != nil {
		r.Error = &Error{
			Code:    e.Code,
			Message: e.Message,
			Content: cbor.RawMessage(e.Content),
		}
	} else {
		r.Result = cbor.RawMessage(res.Result)
	}
	return Message{
		ID:       id,
		Response: &r,
	}
}

func (Layout) Codec() codec.CBOR { return codec.CBOR{} }
