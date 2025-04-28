package json

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

type Message struct {
	Version    string                  `json:"jsonrpc"`
	ID         uint64                  `json:"id"`
	Method     string                  `json:"method,omitempty"`
	Parameters []json.RawMessage       `json:"params,omitempty"`
	Result     Option[json.RawMessage] `json:"result,omitempty"`
	Error      *Error                  `json:"error,omitempty"`
}

func (m *Message) MarshalJSON() ([]byte, error) {
	type errMessage struct {
		Version string `json:"jsonrpc"`
		ID      uint64 `json:"id"`
		Error   *Error `json:"error"`
	}

	type resultMessage Message

	if m.Error != nil {
		// omit the result field
		msg := errMessage{
			Version: m.Version,
			ID:      m.ID,
			Error:   m.Error,
		}
		return json.Marshal(&msg)
	}
	return json.Marshal((*resultMessage)(m))
}

type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message,omitempty"`
	Content json.RawMessage `json:"data,omitempty"`
}

const Version = "2.0"

func (m Message) IsValid() bool {
	return m.Version == Version &&
		(m.Method != "" && m.Result.IsNone() && m.Error == nil ||
			m.Method == "" && m.Result.IsSome() && m.Error == nil ||
			m.Method == "" && m.Result.IsNone() && m.Error != nil)
}

func (m Message) GetID() uint64 { return m.ID }

func (m Message) GetRequest() *rpc.Request {
	if m.Method != "" {
		var params [][]byte
		if len(m.Parameters) != 0 {
			params = make([][]byte, len(m.Parameters))
			for i, p := range m.Parameters {
				params[i] = []byte(p)
			}
		}
		pm := strings.SplitN(m.Method, "_", 2)
		var path, method string
		if len(pm) == 2 {
			path, method = pm[0], pm[1]
		} else {
			method = pm[0]
		}
		return &rpc.Request{
			Path:       []string{path},
			Method:     method,
			Parameters: params,
		}
	}
	return nil
}

func (m Message) GetResponse() *rpc.Response[codec.JSON] {
	if e := m.Error; e != nil {
		return &rpc.Response[codec.JSON]{
			Error: &rpc.ErrorResponse[codec.JSON]{
				Code:    e.Code,
				Message: e.Message,
				Content: []byte(e.Content),
			},
		}
	} else if m.Result.IsSome() {
		var res []byte
		if !m.Result.IsNull() {
			res = []byte(m.Result.Value())
		}
		return &rpc.Response[codec.JSON]{
			Result: res,
		}
	}
	return nil
}

type Layout struct{}

func (Layout) NewRequest(id uint64, r *rpc.Request) Message {
	var par []json.RawMessage
	if len(r.Parameters) != 0 {
		par = make([]json.RawMessage, len(r.Parameters))
		for i, p := range r.Parameters {
			par[i] = json.RawMessage(p)
		}
	}
	return Message{
		Version:    Version,
		ID:         id,
		Method:     strings.Join(r.Path, "") + "_" + r.Method,
		Parameters: par,
	}
}

func (Layout) NewResponse(id uint64, r *rpc.Response[codec.JSON]) Message {
	msg := Message{
		Version: Version,
		ID:      id,
	}
	if e := r.Error; e != nil {
		msg.Error = &Error{
			Code:    e.Code,
			Message: e.Message,
			Content: json.RawMessage(e.Content),
		}
	} else {
		if r.Result != nil {
			msg.Result = Some(json.RawMessage(r.Result))
		} else {
			msg.Result = None[json.RawMessage]()
		}
	}
	return msg
}

func (Layout) Codec() codec.JSON { return codec.JSON{} }

type Option[T any] struct {
	isSome bool
	isNull bool
	value  T
}

func Some[T any](v T) Option[T] { return Option[T]{isSome: true, isNull: false, value: v} }
func None[T any]() Option[T]    { return Option[T]{isSome: false, isNull: false} }
func Null[T any]() Option[T]    { return Option[T]{isSome: true, isNull: true} }

func (o *Option[T]) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		*o = Option[T]{
			isSome: true,
			isNull: true,
		}
		return nil
	}
	*o = Option[T]{
		isSome: true,
		isNull: false,
	}
	return json.Unmarshal(b, &o.value)
}

func (o *Option[T]) MarshalJSON() ([]byte, error) {
	if o.isSome && !o.isNull {
		return json.Marshal(&o.value)
	}
	return []byte("null"), nil
}

func (o *Option[T]) IsNull() bool { return o.isNull }
func (o *Option[T]) IsSome() bool { return o.isSome }
func (o *Option[T]) IsNone() bool { return !o.isSome }
func (o *Option[T]) Value() T {
	if !o.isSome {
		panic("None value")
	}
	if o.isNull {
		panic("Null value")
	}
	return o.value
}
