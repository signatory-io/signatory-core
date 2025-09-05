package rest

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
	"unicode"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
)

var aLongTimeAgo = time.Unix(1, 0)
var ErrCanceled = errors.New("canceled")

type authenticatedConn = conn.AuthenticatedConn

type RESTRequest interface {
	transport.Request
	GetHeaders() map[string]string
	GetQuery() map[string]string
	GetBody() []byte
}

type Method struct {
	fn reflect.Value
}

type Context interface {
	Peer() Caller
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type AuthenticatedContext interface {
	Context
	SessionID() []byte
	RemotePublicKey() *ed25519.PublicKey
}

type Caller interface {
	Call(ctx context.Context, result any, objPath, method string, args ...any) (err error)
}

// error is returned only in case of the context cancellation
func callMethod[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q transport.Request, S transport.Response[C], C codec.Codec](m *Method, ctx context.Context, args [][]byte) (*S, error) {
	var enc E
	t := m.fn.Type()
	idx := 0
	ins := make([]reflect.Value, t.NumIn())
	if t.NumIn() != 0 && t.In(idx) == ctxType {
		ins[idx] = reflect.ValueOf(ctx)
		idx += 1
	}
	if t.NumIn()-idx != len(args) {
		return enc.NewErrorResponse(errors.New("invalid number of arguments"), transport.CodeInvalidParams)
	}
	var codec C
	for i, arg := range args {
		ptr := reflect.New(t.In(i + idx))
		if err := codec.Unmarshal(arg, ptr.Interface()); err != nil {
			return enc.NewErrorResponse(err, transport.CodeParseError)
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
		return enc.NewErrorResponse(err, 0)
	}
	var result []byte
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
		if result, err = codec.Marshal(r); err != nil {
			// shouldn't happen during normal operation
			panic(err)
		}
	}
	return enc.NewResponse(result)
}

var (
	ctxType = reflect.TypeOf((*context.Context)(nil)).Elem()
	errType = reflect.TypeOf((*error)(nil)).Elem()
)

func newMethod(fn reflect.Value) *Method {
	// basic sanity check
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

func NewMethod(f any) *Method {
	return newMethod(reflect.ValueOf(f))
}

type MethodTable map[string]*Method

type Handler struct {
	Modules map[string]MethodTable
}

func NewHandler() *Handler { return &Handler{Modules: map[string]MethodTable{}} }

func (h *Handler) RegisterModuleMethodTable(path string, methods MethodTable) {
	if _, ok := h.Modules[path]; ok {
		panic(fmt.Sprintf("rpc: path %s is already in use", path))
	}
	h.Modules[path] = methods
}

func (h *Handler) RegisterModule(path string, object any) {
	if _, ok := h.Modules[path]; ok {
		panic(fmt.Sprintf("rpc: path %s is already in use", path))
	}

	v := reflect.ValueOf(object)
	t := v.Type()
	numMethod := v.NumMethod()
	table := make(MethodTable, numMethod)

	for i := range v.NumMethod() {
		methodDesc := t.Method(i)
		var cc strings.Builder
		for i, r := range methodDesc.Name {
			if i == 0 {
				r = unicode.ToLower(r)
			}
			cc.WriteRune(r)
		}
		table[cc.String()] = newMethod(v.Method(i))
	}
}

func (h *Handler) Register(obj Module) { obj.RegisterSelf(h) }

type Module interface {
	RegisterSelf(h *Handler)
}

type apiCall[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q transport.Request, S transport.Response[C], C codec.Codec] struct {
	req *Q
	res chan<- *S
	err chan<- error
}

type apiCtx[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q transport.Request, S transport.Response[C], C codec.Codec] struct {
	conn.EncodedConn[M, Q, S, C]
	api *API[E, M, Q, S, C]
}

func (c *apiCtx[E, M, Q, S, C]) Peer() Caller { return c.api }

type apiAuthCtx[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q transport.Request, S transport.Response[C], C codec.Codec] struct {
	*apiCtx[E, M, Q, S, C]
	auth authenticatedConn
}

func (c *apiAuthCtx[E, M, Q, S, C]) SessionID() []byte { return c.auth.SessionID() }
func (c *apiAuthCtx[E, M, Q, S, C]) RemotePublicKey() *ed25519.PublicKey {
	return c.auth.RemotePublicKey()
}

type API[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q transport.Request, S transport.Response[C], C codec.Codec] struct {
	calls  chan<- apiCall[E, M, Q, S, C]
	cancel chan<- struct{}
	done   <-chan struct{}
	err    error
	enc    E
}

func (r *API[E, M, Q, S, C]) Done() <-chan struct{} { return r.done }
func (r *API[E, M, Q, S, C]) Err() error            { return r.err }

func (r *API[E, M, Q, S, C]) Call(ctx context.Context, result any, objPath, method string, args ...any) (err error) {
	req, err := r.enc.NewRequest(objPath, method, args...)
	if err != nil {
		return err
	}

	resCh := make(chan *S, 1)
	errCh := make(chan error)
	call := apiCall[E, M, Q, S, C]{
		req: req,
		res: resCh,
		err: errCh,
	}
	select {
	case r.calls <- call:
	case <-ctx.Done():
		return ctx.Err()
	}
	var res *S
	select {
	case res = <-resCh:
	case err = <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
	if (*res).GetError() != nil {
		return (*res).GetError()
	}
	if (*res).GetResult() != nil && result != nil {
		return r.enc.Codec().Unmarshal((*res).GetResult(), result)
	}
	return nil
}

func (r *API[E, M, Q, S, C]) Close() error {
	close(r.cancel)
	<-r.done
	return r.err
}

type apiCtxKey struct{}

func GetContext(ctx context.Context) Context {
	return ctx.Value(apiCtxKey{}).(Context)
}

func mkCallCtx[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q transport.Request, S transport.Response[C], C codec.Codec](ctx context.Context, conn conn.EncodedConn[M, Q, S, C], api *API[E, M, Q, S, C]) context.Context {
	c := &apiCtx[E, M, Q, S, C]{
		EncodedConn: conn,
		api:         api,
	}
	var val any
	if auth, ok := conn.Inner().(authenticatedConn); ok {
		val = &apiAuthCtx[E, M, Q, S, C]{
			apiCtx: c,
			auth:   auth,
		}
	} else {
		val = c
	}
	return context.WithValue(ctx, apiCtxKey{}, val)
}

func HandleCall[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q RESTRequest, S transport.Response[C], C codec.Codec](h *Handler, ctx context.Context, req *Q) (*S, error) {
	var enc E
	p := strings.Join((*req).GetPath(), "/")
	table, ok := h.Modules[p]
	if !ok {
		return enc.NewErrorResponse(fmt.Errorf("object path `%s' is not found", p), transport.CodeModuleNotFound)
	}
	m, ok := table[(*req).GetMethod()]
	if !ok {
		return enc.NewErrorResponse(fmt.Errorf("method `%s' is not found", (*req).GetMethod()), transport.CodeMethodNotFound)
	}
	return callMethod[E](m, ctx, [][]byte{(*req).GetBody()})
}

func New[E transport.Layout[M, Q, S, C], T conn.EncodedConn[M, Q, S, C], M transport.Message[Q, S, C], Q RESTRequest, S transport.Response[C], C codec.Codec](conn T, h *Handler) *API[E, M, Q, S, C] {
	var enc E

	in := make(chan M)
	readErrCh := make(chan error)

	out := make(chan M)
	writeErrCh := make(chan error)

	// reader loop
	go func() {
		for {
			var m M
			fmt.Println("Message type: ", reflect.TypeOf(m))
			if err := conn.ReadEncodedMessage(&m); err == nil {
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
			if err = conn.WriteEncodedMessage(&m); err != nil {
				// a bit cleaner than writing to closed connection
				if errors.Is(err, os.ErrDeadlineExceeded) {
					err = nil
				}
				break
			}
		}
		writeErrCh <- err
	}()

	calls := make(chan apiCall[E, M, Q, S, C])
	dispatcherCancel := make(chan struct{})
	done := make(chan struct{})

	api := &API[E, M, Q, S, C]{
		calls:  calls,
		cancel: dispatcherCancel,
		done:   done,
		enc:    enc,
	}

	awaiting := make(map[uint64]*apiCall[E, M, Q, S, C])
	msgID := uint64(1) // use 1 in case the ID is not set properly
	// TODO: timeout for calls

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
				if !m.IsValid() {
					continue Loop
				}
				if req := m.GetRequest(); req != nil {
					// request to handler
					if h != nil {
						handlersWG.Add(1)
						go func() {
							id := m.GetID()
							ctx := mkCallCtx(handlersCtx, conn, api)
							res, err := HandleCall[E](h, ctx, req)
							if err == nil {
								// all errors except ErrCanceled are returned back
								var iface transport.Response[C] = *res
								responseMsg := enc.NewMessageFromResponse(id, &iface)
								out <- responseMsg
							}
							handlersWG.Done()
						}()
					}
				} else if res := m.GetResponse(); res != nil {
					// response to our call
					if c, ok := awaiting[m.GetID()]; ok {
						c.res <- res
						delete(awaiting, m.GetID())
					}
				}

			case c := <-calls:
				awaiting[msgID] = &c
				var iface transport.Request = *c.req
				callMsg := enc.NewMessageFromRequest(msgID, &iface)
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
		api.err = err
		close(done)
	}()

	return api
}
