package adapter

import "net/http"

// Error is an answer the panel shows as it is: an HTTP status, a snake_case code and a
// human-readable message. Neither may contain settings or other secrets.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Codes the panel knows.
const (
	CodeBadSettings         = "bad_settings"
	CodeBadCredentials      = "bad_credentials"
	CodeProviderUnavailable = "provider_unavailable"
	CodeNotFound            = "not_found"
	CodeBadRequest          = "bad_request"
	CodeUnauthorized        = "unauthorized"
)

// BadSettings: the settings fail validation (422).
func BadSettings(msg string) *Error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: CodeBadSettings, Message: msg}
}

// BadCredentials: the provider refused the credentials (422).
func BadCredentials(msg string) *Error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: CodeBadCredentials, Message: msg}
}

// ProviderUnavailable: the provider could not be reached or answered nonsense (502).
func ProviderUnavailable(msg string) *Error {
	return &Error{Status: http.StatusBadGateway, Code: CodeProviderUnavailable, Message: msg}
}

// NotFound: no such invoice at the provider (404).
func NotFound(msg string) *Error {
	return &Error{Status: http.StatusNotFound, Code: CodeNotFound, Message: msg}
}

// BadRequest: the request is malformed, or a webhook is forged (400).
func BadRequest(msg string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: CodeBadRequest, Message: msg}
}

// Refused: the provider refused the request for its own reason, e.g.
// "yookassa_invalid_request" (422).
func Refused(code, msg string) *Error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: code, Message: msg}
}
