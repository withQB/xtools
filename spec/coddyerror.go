package spec

import (
	"fmt"
)

type CoddyErrorCode string

const (
	ErrorUnknown                     CoddyErrorCode = "M_UNKNOWN"
	ErrorUnrecognized                CoddyErrorCode = "M_UNRECOGNIZED"
	ErrorForbidden                   CoddyErrorCode = "M_FORBIDDEN"
	ErrorBadJSON                     CoddyErrorCode = "M_BAD_JSON"
	ErrorBadAlias                    CoddyErrorCode = "M_BAD_ALIAS"
	ErrorNotJSON                     CoddyErrorCode = "M_NOT_JSON"
	ErrorNotFound                    CoddyErrorCode = "M_NOT_FOUND"
	ErrorMissingToken                CoddyErrorCode = "M_MISSING_TOKEN"
	ErrorUnknownToken                CoddyErrorCode = "M_UNKNOWN_TOKEN"
	ErrorWeakPassword                CoddyErrorCode = "M_WEAK_PASSWORD"
	ErrorInvalidUsername             CoddyErrorCode = "M_INVALID_USERNAME"
	ErrorUserInUse                   CoddyErrorCode = "M_USER_IN_USE"
	ErrorFrameInUse                   CoddyErrorCode = "M_ROOM_IN_USE"
	ErrorExclusive                   CoddyErrorCode = "M_EXCLUSIVE"
	ErrorGuestAccessForbidden        CoddyErrorCode = "M_GUEST_ACCESS_FORBIDDEN"
	ErrorInvalidSignature            CoddyErrorCode = "M_INVALID_SIGNATURE"
	ErrorInvalidParam                CoddyErrorCode = "M_INVALID_PARAM"
	ErrorMissingParam                CoddyErrorCode = "M_MISSING_PARAM"
	ErrorUnableToAuthoriseJoin       CoddyErrorCode = "M_UNABLE_TO_AUTHORISE_JOIN"
	ErrorCannotLeaveServerNoticeFrame CoddyErrorCode = "M_CANNOT_LEAVE_SERVER_NOTICE_ROOM"
	ErrorWrongFrameKeysVersion        CoddyErrorCode = "M_WRONG_ROOM_KEYS_VERSION"
	ErrorIncompatibleFrameVersion     CoddyErrorCode = "M_INCOMPATIBLE_ROOM_VERSION"
	ErrorUnsupportedFrameVersion      CoddyErrorCode = "M_UNSUPPORTED_ROOM_VERSION"
	ErrorLimitExceeded               CoddyErrorCode = "M_LIMIT_EXCEEDED"
	ErrorServerNotTrusted            CoddyErrorCode = "M_SERVER_NOT_TRUSTED"
	ErrorSessionNotValidated         CoddyErrorCode = "M_SESSION_NOT_VALIDATED"
	ErrorThreePIDInUse               CoddyErrorCode = "M_THREEPID_IN_USE"
	ErrorThreePIDAuthFailed          CoddyErrorCode = "M_THREEPID_AUTH_FAILED"
)

// CoddyError represents the "standard error response"
type CoddyError struct {
	ErrCode CoddyErrorCode `json:"errcode"`
	Err     string          `json:"error"`
}

func (e CoddyError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Err)
}

func (e CoddyError) Unwrap() error {
	return fmt.Errorf(e.Err)
}

// InternalServerError
type InternalServerError struct {
	Err string
}

func (e InternalServerError) Error() string {
	return fmt.Sprintf("Internal server error: %s", e.Err)
}

// Unknown is an unexpected error
func Unknown(msg string) CoddyError {
	return CoddyError{ErrorUnknown, msg}
}

// Unrecognized is an error when the server received a request at
// an unexpected endpoint.
func Unrecognized(msg string) CoddyError {
	return CoddyError{ErrorUnrecognized, msg}
}

// Forbidden is an error when the client tries to access a resource
// they are not allowed to access.
func Forbidden(msg string) CoddyError {
	return CoddyError{ErrorForbidden, msg}
}

// BadJSON is an error when the client supplies malformed JSON.
func BadJSON(msg string) CoddyError {
	return CoddyError{ErrorBadJSON, msg}
}

// BadAlias is an error when the client supplies a bad alias.
func BadAlias(msg string) CoddyError {
	return CoddyError{ErrorBadAlias, msg}
}

// NotJSON is an error when the client supplies something that is not JSON
// to a JSON endpoint.
func NotJSON(msg string) CoddyError {
	return CoddyError{ErrorNotJSON, msg}
}

// NotFound is an error when the client tries to access an unknown resource.
func NotFound(msg string) CoddyError {
	return CoddyError{ErrorNotFound, msg}
}

// MissingToken is an error when the client tries to access a resource which
// requires authentication without supplying credentials.
func MissingToken(msg string) CoddyError {
	return CoddyError{ErrorMissingToken, msg}
}

// UnknownToken is an error when the client tries to access a resource which
// requires authentication and supplies an unrecognised token
func UnknownToken(msg string) CoddyError {
	return CoddyError{ErrorUnknownToken, msg}
}

// WeakPassword is an error which is returned when the client tries to register
// using a weak password. http://matrix.org/docs/spec/client_server/r0.2.0.html#password-based
func WeakPassword(msg string) CoddyError {
	return CoddyError{ErrorWeakPassword, msg}
}

// InvalidUsername is an error returned when the client tries to register an
// invalid username
func InvalidUsername(msg string) CoddyError {
	return CoddyError{ErrorInvalidUsername, msg}
}

// UserInUse is an error returned when the client tries to register an
// username that already exists
func UserInUse(msg string) CoddyError {
	return CoddyError{ErrorUserInUse, msg}
}

// FrameInUse is an error returned when the client tries to make a frame
// that already exists
func FrameInUse(msg string) CoddyError {
	return CoddyError{ErrorFrameInUse, msg}
}

// ASExclusive is an error returned when an application service tries to
// register an username that is outside of its registered namespace, or if a
// user attempts to register a username or frame alias within an exclusive
// namespace.
func ASExclusive(msg string) CoddyError {
	return CoddyError{ErrorExclusive, msg}
}

// GuestAccessForbidden is an error which is returned when the client is
// forbidden from accessing a resource as a guest.
func GuestAccessForbidden(msg string) CoddyError {
	return CoddyError{ErrorGuestAccessForbidden, msg}
}

// InvalidSignature is an error which is returned when the client tries
// to upload invalid signatures.
func InvalidSignature(msg string) CoddyError {
	return CoddyError{ErrorInvalidSignature, msg}
}

// InvalidParam is an error that is returned when a parameter has the wrong
// value or type.
func InvalidParam(msg string) CoddyError {
	return CoddyError{ErrorInvalidParam, msg}
}

// MissingParam is an error that is returned when a parameter is missing from
// a request.
func MissingParam(msg string) CoddyError {
	return CoddyError{ErrorMissingParam, msg}
}

// UnableToAuthoriseJoin is an error that is returned when a server can't
// determine whether to allow a restricted join or not.
func UnableToAuthoriseJoin(msg string) CoddyError {
	return CoddyError{ErrorUnableToAuthoriseJoin, msg}
}

// LeaveServerNoticeError is an error returned when trying to reject an invite
// for a server notice frame.
func LeaveServerNoticeError() CoddyError {
	return CoddyError{
		ErrCode: ErrorCannotLeaveServerNoticeFrame,
		Err:     "You cannot reject this invite",
	}
}

// ErrFrameKeysVersion is an error returned by `PUT /frame_keys/keys`
type ErrFrameKeysVersion struct {
	CoddyError
	CurrentVersion string `json:"current_version"`
}

func (e ErrFrameKeysVersion) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Err)
}

func (e ErrFrameKeysVersion) Unwrap() error {
	return e.CoddyError
}

// WrongBackupVersionError is an error returned by `PUT /frame_keys/keys`
func WrongBackupVersionError(currentVersion string) ErrFrameKeysVersion {
	return ErrFrameKeysVersion{
		CoddyError: CoddyError{
			ErrCode: ErrorWrongFrameKeysVersion,
			Err:     "Wrong backup version.",
		},
		CurrentVersion: currentVersion,
	}
}

type IncompatibleFrameVersionError struct {
	CoddyError
	FrameVersion string `json:"frame_version"`
}

func (e IncompatibleFrameVersionError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Err)
}

func (e IncompatibleFrameVersionError) Unwrap() error {
	return fmt.Errorf(e.Err)
}

// IncompatibleFrameVersion is an error which is returned when the client
// requests a frame with a version that is unsupported.
func IncompatibleFrameVersion(frameVersion string) IncompatibleFrameVersionError {
	return IncompatibleFrameVersionError{
		FrameVersion: frameVersion,
		CoddyError: CoddyError{
			ErrCode: ErrorIncompatibleFrameVersion,
			Err:     "Your homeserver does not support the features required to join this frame",
		},
	}
}

// UnsupportedFrameVersion is an error which is returned when the client
// requests a frame with a version that is unsupported.
func UnsupportedFrameVersion(msg string) CoddyError {
	return CoddyError{ErrorUnsupportedFrameVersion, msg}
}

// LimitExceededError is a rate-limiting error.
type LimitExceededError struct {
	CoddyError
	RetryAfterMS int64 `json:"retry_after_ms,omitempty"`
}

func (e LimitExceededError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Err)
}

func (e LimitExceededError) Unwrap() error {
	return e.CoddyError
}

// LimitExceeded is an error when the client tries to send events too quickly.
func LimitExceeded(msg string, retryAfterMS int64) LimitExceededError {
	return LimitExceededError{
		CoddyError:  CoddyError{ErrorLimitExceeded, msg},
		RetryAfterMS: retryAfterMS,
	}
}

// NotTrusted is an error which is returned when the client asks the server to
// proxy a request (e.g. 3PID association) to a server that isn't trusted
func NotTrusted(serverName string) CoddyError {
	return CoddyError{
		ErrCode: ErrorServerNotTrusted,
		Err:     fmt.Sprintf("Untrusted server '%s'", serverName),
	}
}
