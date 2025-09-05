package rest

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
)

type Request struct {
	Path    []string        `json:"path,omitempty"`
	Method  string          `json:"method,omitempty"`
	Headers http.Header     `json:"headers,omitempty"`
	Query   url.Values      `json:"query,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

func (r Request) GetPath() []string       { return r.Path }
func (r Request) GetMethod() string       { return r.Method }
func (r Request) GetHeaders() http.Header { return r.Headers }
func (r Request) GetQuery() url.Values    { return r.Query }
func (r Request) GetBody() []byte         { return []byte(r.Body) }

type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

func (r Response) GetResult() []byte { return []byte(r.Result) }
func (r Response) GetError() *transport.ErrorResponse[codec.JSON] {
	if r.Error == nil {
		return nil
	}
	return &transport.ErrorResponse[codec.JSON]{
		Code:    r.Error.Code,
		Message: r.Error.Message,
		Content: r.Error.Content,
	}
}

type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message,omitempty"`
	Content json.RawMessage `json:"data,omitempty"`
}

// func (e *Error) Error() string  { return e.Message }
// func (e *Error) ErrorCode() int { return e.Code }
// func (e *Error) ErrorContent(v any) (ok bool, err error) {
// 	if e.Content == nil {
// 		return false, nil
// 	}
// 	var codec codec.JSON
// 	if err = codec.Unmarshal(e.Content, v); err != nil {
// 		return false, err
// 	}
// 	return true, nil
// }

type Message struct {
	ID      uint64          `json:"id,omitempty"`
	Path    string          `json:"path,omitempty"`
	Method  string          `json:"method,omitempty"`
	Headers http.Header     `json:"headers,omitempty"`
	Query   url.Values      `json:"query,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

func (m Message) IsValid() bool {
	return m.Method != "" && m.Path != "" && m.Error == nil
}

func (m Message) GetID() uint64 { return m.ID }

func (m Message) GetRequest() *Request {
	if m.Method != "" {
		return &Request{
			Path:    []string{m.Path},
			Method:  m.Method,
			Headers: m.Headers,
			Query:   m.Query,
			Body:    json.RawMessage(m.Body),
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
				Content: json.RawMessage(e.Content),
			},
		}
	} else if m.Result != nil {
		return &Response{
			Result: json.RawMessage(m.Result),
		}
	}
	return nil
}

type Layout struct{}

func (Layout) NewRequest(path, method string, args ...any) (*Request, error) {
	// args are expected to be headers, query and body where body is optional
	headers := make(http.Header)
	query := make(url.Values)
	body := []byte{}
	if len(args) >= 2 {
		headers = args[0].(http.Header)
		query = args[1].(url.Values)
		if len(args) == 3 {
			body = args[2].([]byte)
		}
	}
	return &Request{
		Path:    strings.Split(path, "/"),
		Method:  method,
		Headers: headers,
		Query:   query,
		Body:    json.RawMessage(body),
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
	if req, ok := (*r).(Request); ok {
		return Message{
			ID:     id,
			Path:   strings.Join(req.GetPath(), ""),
			Method: req.GetMethod(),
			Body:   json.RawMessage(req.GetBody()),
		}
	}
	return Message{}
}

var null = json.RawMessage("null")

func (Layout) NewMessageFromResponse(id uint64, res *transport.Response[codec.JSON]) Message {
	msg := Message{
		ID: id,
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
