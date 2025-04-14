package rpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/rpc/secureconnection"
	"github.com/signatory-io/signatory-core/rpc/types"
)

type Error interface {
	error
	ErrorCode() int
}

type errorEx interface {
	Error
	ErrorContent() any
}

type ErrorEx interface {
	Error
	ErrorContent(v any) (ok bool, err error)
}

const (
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	CodeParseError     = -32700
	CodeObjectNotFound = -32800
)

type message struct {
	ID       uint64    `cbor:"0,keyasint"`
	Request  *request  `cbor:"1,keyasint,omitempty"`
	Response *response `cbor:"2,keyasint,omitempty"`
}

type request struct {
	Path       []string          `cbor:"0,keyasint,omitempty"`
	Method     string            `cbor:"1,keyasint"`
	Parameters []cbor.RawMessage `cbor:"2,keyasint,omitempty"`
}

type response struct {
	Result cbor.RawMessage `cbor:"0,keyasint,omitempty"`
	Error  *errorResponse  `cbor:"1,keyasint,omitempty"`
}

type errorResponse struct {
	Code    int             `cbor:"0,keyasint,omitempty"`
	Message string          `cbor:"1,keyasint,omitempty"`
	Content cbor.RawMessage `cbor:"2,keyasint,omitempty"`
}

func (e *errorResponse) Error() string  { return e.Message }
func (e *errorResponse) ErrorCode() int { return e.Code }

func (e *errorResponse) ErrorContent(v any) (ok bool, err error) {
	if e.Content == nil {
		return false, nil
	}
	if err = cbor.Unmarshal(e.Content, v); err != nil {
		return false, err
	}
	return true, nil
}

var _ ErrorEx = (*errorResponse)(nil)

type Method struct {
	fn reflect.Value
}

func mkErrorResponse(err error, code int) *response {
	ret := &errorResponse{
		Message: err.Error(),
	}
	if err, ok := err.(Error); ok {
		ret.Code = err.ErrorCode()
		if err, ok := err.(errorEx); ok {
			if content, err := cbor.Marshal(err.ErrorContent()); err == nil {
				ret.Content = content
			}
		}
	} else {
		ret.Code = code
	}
	return &response{Error: ret}
}

type Context interface {
	Peer() Caller
	SessionID() []byte
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	RemotePublicKey() *ed25519.PublicKey
}

type Caller interface {
	Call(ctx context.Context, result any, objPath, method string, args ...any) (err error)
}

type rpcCtxKey struct{}

func GetContext(ctx context.Context) Context {
	return ctx.Value(rpcCtxKey{}).(Context)
}

// error is returned only in case of the context cancellation
func (m *Method) call(ctx context.Context, args []cbor.RawMessage) (*response, error) {
	t := m.fn.Type()
	idx := 0
	ins := make([]reflect.Value, t.NumIn())
	if t.In(idx) == ctxType {
		ins[idx] = reflect.ValueOf(ctx)
		idx += 1
	}
	if t.NumIn()-idx != len(args) {
		return mkErrorResponse(errors.New("invalid number of arguments"), CodeInvalidParams), nil
	}
	for i, arg := range args {
		ptr := reflect.New(t.In(i + idx))
		if err := cbor.Unmarshal(arg, ptr.Interface()); err != nil {
			return mkErrorResponse(err, CodeParseError), nil
		}
		ins[i+idx] = ptr.Elem()
	}
	outs := m.fn.Call(ins)

	if ev := outs[len(outs)-1]; !ev.IsNil() {
		err := ev.Interface().(error)
		// in case the cause was returned directly by the handler
		if cause := context.Cause(ctx); errors.Is(err, ErrCanceled) || errors.Is(err, context.Canceled) && cause == ErrCanceled {
			return nil, cause
		}
		return mkErrorResponse(err, 0), nil
	}
	var result cbor.RawMessage
	if len(outs) > 1 {
		var r any
		if len(outs) > 2 {
			res := make([]any, len(outs)-1)
			for i := range len(outs) - 1 {
				res[i] = outs[i].Interface()
			}
			r = res
		} else {
			r = outs[0].Interface()
		}
		var err error
		if result, err = cbor.Marshal(r); err != nil {
			// shouldn't happen during normal operation
			panic(err)
		}
	}
	return &response{Result: result}, nil
}

var (
	ctxType = reflect.TypeOf((*context.Context)(nil)).Elem()
	errType = reflect.TypeOf((*error)(nil)).Elem()
)

func NewMethod(f any) *Method {
	// basic sanity check
	fn := reflect.ValueOf(f)
	t := fn.Type()
	if t.Kind() != reflect.Func {
		panic("not a function")
	}
	if t.NumOut() < 1 {
		panic("insufficient number of results")
	}
	if t.Out(t.NumOut()-1) != errType {
		panic("last result must be error")
	}
	return &Method{
		fn: fn,
	}
}

type MethodTable map[string]*Method

type Handler struct {
	Objects map[string]MethodTable
}

func (h *Handler) RegisterObject(path string, methods MethodTable) {
	if _, ok := h.Objects[path]; ok {
		panic(fmt.Sprintf("rpc: path %s is already in use", path))
	}
	h.Objects[path] = methods
}

func (h *Handler) Register(obj RPCObject) { obj.RegisterSelf(h) }

type RPCObject interface {
	RegisterSelf(h *Handler)
}

func (h *Handler) handleCall(ctx context.Context, req *request) (*response, error) {
	p := strings.Join(req.Path, "/")
	table, ok := h.Objects[p]
	if !ok {
		return mkErrorResponse(fmt.Errorf("object path `%s' is not found", p), CodeObjectNotFound), nil
	}
	m, ok := table[req.Method]
	if !ok {
		return mkErrorResponse(fmt.Errorf("method `%s' is not found", req.Method), CodeMethodNotFound), nil
	}
	return m.call(ctx, req.Parameters)
}

type rpcCall struct {
	req *request
	res chan<- *response
	err chan<- error
}

type RPC struct {
	calls  chan<- rpcCall
	cancel chan<- struct{}
	done   <-chan struct{}
	err    error
}

var aLongTimeAgo = time.Unix(1, 0)
var ErrCanceled = errors.New("canceled")

type rpcCtx struct {
	types.EncodedConn
	secureconnection.AuthenticatedConn
	rpc *RPC
}

func (c *rpcCtx) Peer() Caller { return c.rpc }

var _ Context = (*rpcCtx)(nil)

type dummyAuth struct{}

func (dummyAuth) SessionID() []byte                   { return nil }
func (dummyAuth) RemotePublicKey() *ed25519.PublicKey { return nil }

func mkCallCtx(ctx context.Context, conn types.EncodedConn, rpc *RPC) context.Context {
	c := rpcCtx{
		EncodedConn: conn,
		rpc:         rpc,
	}
	if auth, ok := conn.(secureconnection.AuthenticatedConn); ok {
		c.AuthenticatedConn = auth
	} else {
		c.AuthenticatedConn = dummyAuth{}
	}
	return context.WithValue(ctx, rpcCtxKey{}, &c)
}

func New(conn types.EncodedConn, h *Handler) *RPC {
	in := make(chan message)
	readErrCh := make(chan error)

	out := make(chan message)
	writeErrCh := make(chan error)

	// reader loop
	go func() {
		for {
			var m message
			if err := conn.ReadMessage(&m); err == nil {
				in <- m
			} else {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					readErrCh <- nil
				} else {
					readErrCh <- err
				}
				return
			}
		}
	}()

	// writer loop
	go func() {
		var err error
		for m := range out {
			if err = conn.WriteMessage(&m); err != nil {
				// a bit cleaner than writing to closed connection
				if errors.Is(err, os.ErrDeadlineExceeded) {
					err = nil
				}
				break
			}
		}
		writeErrCh <- err
	}()

	calls := make(chan rpcCall)
	dispatcherCancel := make(chan struct{})
	done := make(chan struct{})

	rpc := &RPC{
		calls:  calls,
		cancel: dispatcherCancel,
		done:   done,
	}

	awaiting := make(map[uint64]*rpcCall)
	msgID := uint64(0)

	// main dispatcher loop
	go func() {
		var handlersWG sync.WaitGroup
		handlersCtx, handlersCancel := context.WithCancelCause(context.Background())

		var (
			readErr, writeErr   error
			readDone, writeDone bool
		)
	Loop:
		for {
			select {
			case m := <-in:
				if m.Request != nil {
					// request to handler
					if h != nil {
						handlersWG.Add(1)
						go func() {
							id := m.ID
							ctx := mkCallCtx(handlersCtx, conn, rpc)
							res, err := h.handleCall(ctx, m.Request)
							if err == nil {
								// all errors except ErrCanceled are returned back
								responseMsg := message{
									ID:       id,
									Response: res,
								}
								out <- responseMsg
							}
							handlersWG.Done()
						}()
					}
				} else if m.Response != nil {
					// response to our call
					if c, ok := awaiting[m.ID]; ok {
						c.res <- m.Response
						delete(awaiting, m.ID)
					}
				}
			case c := <-calls:
				awaiting[msgID] = &c
				callMsg := message{
					ID:      msgID,
					Request: c.req,
				}
				msgID++
				out <- callMsg

			case readErr = <-readErrCh:
				readDone = true
				break Loop

			case writeErr = <-writeErrCh:
				writeDone = true
				break Loop

			case <-dispatcherCancel:
				break Loop
			}
		}

		close(out)
		conn.SetDeadline(aLongTimeAgo)

		if !readDone {
			readErr = <-readErrCh
		}
		if !writeDone {
			writeErr = <-writeErrCh
		}
		err := readErr
		if err == nil {
			err = writeErr
		}

		broadcastErr := err
		if broadcastErr == nil {
			broadcastErr = ErrCanceled
		}
		for _, c := range awaiting {
			c.err <- broadcastErr
		}

		handlersCancel(ErrCanceled)
		handlersWG.Wait()

		cErr := conn.Close()
		if err == nil {
			err = cErr
		}
		rpc.err = err
		close(done)
	}()

	return rpc
}

func (r *RPC) Done() <-chan struct{} { return r.done }
func (r *RPC) Err() error            { return r.err }

func (r *RPC) Call(ctx context.Context, result any, objPath, method string, args ...any) (err error) {
	params := make([]cbor.RawMessage, len(args))
	for i, arg := range args {
		if params[i], err = cbor.Marshal(arg); err != nil {
			return err
		}
	}
	req := request{
		Path:       strings.Split(objPath, "/"),
		Method:     method,
		Parameters: params,
	}

	resCh := make(chan *response, 1)
	errCh := make(chan error)
	call := rpcCall{
		req: &req,
		res: resCh,
		err: errCh,
	}
	select {
	case r.calls <- call:
	case <-ctx.Done():
		return ctx.Err()
	}
	var res *response
	select {
	case res = <-resCh:
	case err = <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
	if res.Error != nil {
		return res.Error
	}
	return cbor.Unmarshal(res.Result, result)
}

func (r *RPC) Close() error {
	close(r.cancel)
	<-r.done
	return r.err
}
