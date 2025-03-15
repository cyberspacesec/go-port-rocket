package scanner

import "errors"

// Scanner errors
var (
	// ErrInvalidOptions indicates invalid scan options were provided
	ErrInvalidOptions = errors.New("invalid scan options")

	// ErrInvalidPortRange indicates an invalid port range was provided
	ErrInvalidPortRange = errors.New("invalid port range")

	// ErrInvalidTarget indicates an invalid target was provided
	ErrInvalidTarget = errors.New("invalid target")

	// ErrInvalidPorts indicates invalid ports were provided
	ErrInvalidPorts = errors.New("invalid ports")

	// ErrRootRequired indicates root privileges are required for the operation
	ErrRootRequired = errors.New("root privileges required")

	// ErrScanTimeout indicates a scan operation timed out
	ErrScanTimeout = errors.New("scan timeout")

	// ErrScanCancelled indicates a scan was cancelled
	ErrScanCancelled = errors.New("scan cancelled")

	// ErrScanInterrupted indicates a scan was interrupted
	ErrScanInterrupted = errors.New("scan interrupted")

	// ErrInvalidConfig indicates invalid scanner configuration
	ErrInvalidConfig = errors.New("invalid scanner configuration")

	// ErrRateLimitExceeded indicates rate limit was exceeded
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// ErrConnectionFailed indicates a connection attempt failed
	ErrConnectionFailed = errors.New("connection failed")

	// ErrInvalidProtocol indicates an invalid protocol was specified
	ErrInvalidProtocol = errors.New("invalid protocol")

	// ErrInvalidTimeout indicates an invalid timeout value was provided
	ErrInvalidTimeout = errors.New("invalid timeout value")

	// ErrInvalidConcurrency indicates an invalid concurrency value was provided
	ErrInvalidConcurrency = errors.New("invalid concurrency value")
)

// IsScannerError checks if an error is a scanner-specific error
func IsScannerError(err error) bool {
	switch err {
	case ErrInvalidOptions,
		ErrInvalidPortRange,
		ErrInvalidTarget,
		ErrInvalidPorts,
		ErrRootRequired,
		ErrScanTimeout,
		ErrScanCancelled,
		ErrScanInterrupted,
		ErrInvalidConfig,
		ErrRateLimitExceeded,
		ErrConnectionFailed,
		ErrInvalidProtocol,
		ErrInvalidTimeout,
		ErrInvalidConcurrency:
		return true
	default:
		return false
	}
}
