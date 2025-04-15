package rpc

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
