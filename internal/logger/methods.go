package logger

func (NopLogger) Debug(msg any, args ...any)        {}
func (NopLogger) Info(msg any, args ...any)         {}
func (NopLogger) Error(msg any, args ...any)        {}
func (NopLogger) Debugf(format string, args ...any) {}
func (NopLogger) Errorf(format string, args ...any) {}
