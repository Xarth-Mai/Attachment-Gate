package app

import "fmt"

const (
	ExitOK         = 0
	ExitUsage      = 2
	ExitInput      = 3
	ExitDependency = 4
	ExitFilesystem = 5
	ExitCanceled   = 6
	ExitInternal   = 70
)

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

func exitError(code int, format string, args ...any) error {
	return &ExitError{Code: code, Err: fmt.Errorf(format, args...)}
}
