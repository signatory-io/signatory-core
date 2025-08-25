package rpc

const (
	CodeServerError    = -32000
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	CodeParseError     = -32700
	CodeModuleNotFound = -32800

	CodeDefault = CodeServerError
)

func ErrorCodeIs(err error, code int) bool {
	for {
		if e, ok := err.(Error); ok {
			return e.ErrorCode() == code
		}
		if un, ok := err.(interface{ Unwrap() error }); ok {
			err = un.Unwrap()
			if err == nil {
				return false
			}
		} else {
			return false
		}
	}
}

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

type wrappedErr struct {
	error
	code int
}

func (w wrappedErr) ErrorCode() int { return w.code }
func (w wrappedErr) Unwrap() error  { return w.error }

func WrapError(err error, code int) error { return wrappedErr{error: err, code: code} }

type wrappedErrEx struct {
	wrappedErr
	content any
}

func (w *wrappedErrEx) ErrorContent() any { return w.content }

func WrapErrorEx(err error, code int, content any) error {
	return &wrappedErrEx{
		wrappedErr: wrappedErr{
			error: err,
			code:  code,
		},
		content: content,
	}
}
