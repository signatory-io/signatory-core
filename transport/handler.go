package transport

// import (
// 	"context"
// 	"errors"
// 	"fmt"
// 	"reflect"
// 	"strings"
// 	"unicode"

// 	"github.com/signatory-io/signatory-core/transport/codec"
// )

// var (
// 	ctxType = reflect.TypeOf((*context.Context)(nil)).Elem()
// 	errType = reflect.TypeOf((*error)(nil)).Elem()
// )

// type Module interface {
// 	RegisterSelf(h *Handler)
// }

// func NewHandler() *Handler { return &Handler{Modules: map[string]MethodTable{}} }

// func (h *Handler) RegisterModuleMethodTable(path string, methods MethodTable) {
// 	if _, ok := h.Modules[path]; ok {
// 		panic(fmt.Sprintf("rpc: path %s is already in use", path))
// 	}
// 	h.Modules[path] = methods
// }

// type Method struct {
// 	fn reflect.Value
// }

// func newMethod(fn reflect.Value) *Method {
// 	// basic sanity check
// 	t := fn.Type()
// 	if t.Kind() != reflect.Func {
// 		panic("not a function")
// 	}
// 	if t.NumOut() < 1 {
// 		panic("insufficient number of results")
// 	}
// 	if t.Out(t.NumOut()-1) != errType {
// 		panic("last result must be error")
// 	}
// 	return &Method{
// 		fn: fn,
// 	}
// }

// func NewMethod(f any) *Method {
// 	return newMethod(reflect.ValueOf(f))
// }

// type MethodTable map[string]*Method

// // error is returned only in case of the context cancellation
// func CallMethod[E Layout[M, Q, S, C], M Message[Q, S, C], Q Request, S Response[C], C codec.Codec](m *Method, ctx context.Context, args [][]byte) (*S, error) {
// 	var enc E
// 	t := m.fn.Type()
// 	idx := 0
// 	ins := make([]reflect.Value, t.NumIn())
// 	if t.NumIn() != 0 && t.In(idx) == ctxType {
// 		ins[idx] = reflect.ValueOf(ctx)
// 		idx += 1
// 	}
// 	if t.NumIn()-idx != len(args) {
// 		return enc.NewErrorResponse(errors.New("invalid number of arguments"), transport.CodeInvalidParams)
// 	}
// 	var codec C
// 	for i, arg := range args {
// 		ptr := reflect.New(t.In(i + idx))
// 		if err := codec.Unmarshal(arg, ptr.Interface()); err != nil {
// 			return enc.NewErrorResponse(err, transport.CodeParseError)
// 		}
// 		ins[i+idx] = ptr.Elem()
// 	}
// 	outs := m.fn.Call(ins)

// 	if ev := outs[len(outs)-1]; !ev.IsNil() {
// 		err := ev.Interface().(error)
// 		// in case the cause was returned directly by the handler
// 		if cause := context.Cause(ctx); errors.Is(err, ErrCanceled) || errors.Is(err, context.Canceled) && cause == ErrCanceled {
// 			return nil, cause
// 		}
// 		return enc.NewErrorResponse(err, 0)
// 	}
// 	var result []byte
// 	if len(outs) > 1 {
// 		var r any
// 		if len(outs) > 2 {
// 			res := make([]any, len(outs)-1)
// 			for i := range len(outs) - 1 {
// 				res[i] = outs[i].Interface()
// 			}
// 			r = res
// 		} else {
// 			r = outs[0].Interface()
// 		}
// 		var err error
// 		if result, err = codec.Marshal(r); err != nil {
// 			// shouldn't happen during normal operation
// 			panic(err)
// 		}
// 	}
// 	return enc.NewResponse(result)
// }

// type Handler struct {
// 	Modules map[string]MethodTable
// }

// func (h *Handler) RegisterModule(path string, object any) {
// 	if _, ok := h.Modules[path]; ok {
// 		panic(fmt.Sprintf("rpc: path %s is already in use", path))
// 	}

// 	v := reflect.ValueOf(object)
// 	t := v.Type()
// 	numMethod := v.NumMethod()
// 	table := make(MethodTable, numMethod)

// 	for i := range v.NumMethod() {
// 		methodDesc := t.Method(i)
// 		var cc strings.Builder
// 		for i, r := range methodDesc.Name {
// 			if i == 0 {
// 				r = unicode.ToLower(r)
// 			}
// 			cc.WriteRune(r)
// 		}
// 		table[cc.String()] = newMethod(v.Method(i))
// 	}
// }

// func (h *Handler) Register(obj Module) { obj.RegisterSelf(h) }
