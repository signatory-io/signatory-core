package logger

type nop struct{}

func Nop() Logger { return nop{} }

func (nop) With(string, any) Logger          { return nop{} }
func (nop) WithFields(map[string]any) Logger { return nop{} }
func (nop) Logf(Level, string, ...any)       {}
func (nop) Log(Level, ...any)                {}
func (nop) Errorf(string, ...any)            {}
func (nop) Error(...any)                     {}
func (nop) Warnf(string, ...any)             {}
func (nop) Warn(...any)                      {}
func (nop) Infof(string, ...any)             {}
func (nop) Info(...any)                      {}
func (nop) Debugf(string, ...any)            {}
func (nop) Debug(...any)                     {}
func (nop) Tracef(string, ...any)            {}
func (nop) Trace(...any)                     {}
