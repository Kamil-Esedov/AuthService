package domain

import (
	"net/http"
)

type AppError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
	Cause   error  `json:"-"`
}

func (e *AppError) Error() string {
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Cause
}

func NewErrInternal(cause error) *AppError {
	return &AppError{
		Code:    "ErrInternalServer",
		Message: "internal server error",
		Status:  http.StatusInternalServerError,
		Cause:   cause,
	}
}
