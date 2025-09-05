package json

import (
	"encoding/json"
	"strings"

	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
)

var null = json.RawMessage("null")

type Request struct {
	Path       []string
	Method     string
	Parameters []json.RawMessage
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
	Result []byte
	Error  *Error
}

func (r Response) GetResult() []byte { return r.Result }
func (r Response) GetError() *transport.ErrorResponse[codec.JSON] {
	if r.Error == nil {
		return nil
	}
	return &transport.ErrorResponse[codec.JSON]{
		Code:    r.GetError().Code,
		Message: r.Error.Message,
		Content: r.Error.Content,
	}
}

type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message,omitempty"`
	Content json.RawMessage `json:"data,omitempty"`
}

const Version = "2.0"

type Message struct {
	Version    string            `json:"jsonrpc"`
	ID         uint64            `json:"id"`
	Method     string            `json:"method,omitempty"`
	Parameters []json.RawMessage `json:"params,omitempty"`
	Result     json.RawMessage   `json:"result,omitempty"`
	Error      *Error            `json:"error,omitempty"`
}

func (m Message) IsValid() bool {
	return m.Version == Version &&
		(m.Method != "" && m.Result == nil && m.Error == nil ||
			m.Method == "" && m.Result != nil && m.Error == nil ||
			m.Method == "" && m.Result == nil && m.Error != nil)
}

func (m Message) GetID() uint64 { return m.ID }

func (m Message) GetRequest() *Request {
	if m.Method != "" {
		var params []json.RawMessage
		if len(m.Parameters) != 0 {
			params = make([]json.RawMessage, len(m.Parameters))
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
		return &Request{
			Path:       []string{path},
			Method:     method,
			Parameters: params,
		}
	}
	return nil
}

func (m Message) GetResponse() *Response {
	if e := m.Error; e != nil {
		return &Response{
			Error: &Error{
				Code:    e.Code,
				Message: e.Message,
				Content: []byte(e.Content),
			},
		}
	} else if m.Result != nil {
		return &Response{
			Result: []byte(m.Result),
		}
	}
	return nil
}

type Layout struct{}

func (Layout) NewRequest(path string, method string, args ...any) (*Request, error) {
	params := make([]json.RawMessage, len(args))
	var codec codec.JSON
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
		Result: json.RawMessage(result),
	}, nil
}

func (Layout) NewErrorResponse(err error, code int) (*Response, error) {
	var content json.RawMessage
	var cod codec.JSON
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
	var par []json.RawMessage
	if r, ok := (*r).(Request); ok {
		if len(r.GetParameters()) != 0 {
			par = make([]json.RawMessage, len(r.GetParameters()))
			for i, p := range r.GetParameters() {
				par[i] = json.RawMessage(p)
			}
		}
	}
	return Message{
		Version:    Version,
		ID:         id,
		Method:     strings.Join((*r).GetPath(), "") + "_" + (*r).GetMethod(),
		Parameters: par,
	}
}

func (Layout) NewMessageFromResponse(id uint64, res *transport.Response[codec.JSON]) Message {
	msg := Message{
		Version: Version,
		ID:      id,
	}
	if e := (*res).GetError(); e != nil {
		msg.Error = &Error{
			Code:    e.Code,
			Message: e.Message,
			Content: json.RawMessage(e.Content),
		}
	} else {
		if (*res).GetResult() != nil {
			msg.Result = json.RawMessage((*res).GetResult())
		} else {
			msg.Result = null
		}
	}
	return msg
}

func (Layout) Codec() codec.JSON { return codec.JSON{} }
