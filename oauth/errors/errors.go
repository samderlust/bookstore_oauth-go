package errors

import (
	"errors"
	"net/http"
)

//RestErr define  http response error
type RestErr struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
	Error   string `json:"error"`
}

//NewBadRequestError return a pointer to RestErr with bad request type
func NewBadRequestError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Status:  http.StatusBadRequest,
		Error:   "badRequest",
	}
}

//NewNotFoundError return a pointer to RestErr with bad request type
func NewNotFoundError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Status:  http.StatusNotFound,
		Error:   "notFount",
	}
}

//NewInternalServerError return a pointer to RestErr with internal server error
func NewInternalServerError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Status:  http.StatusInternalServerError,
		Error:   "internalServerError",
	}
}

func NewError(msg string) error {
	return errors.New(msg)
}
