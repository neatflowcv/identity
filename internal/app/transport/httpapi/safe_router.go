package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

type safeRouter struct {
	mux *http.ServeMux
}

func newSafeRouter(mux *http.ServeMux) http.Handler {
	return &safeRouter{mux: mux}
}

func (r *safeRouter) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	buffered := &bufferedResponseWriter{
		ResponseWriter: writer,
		body:           bytes.Buffer{},
		status:         http.StatusOK,
		headerWritten:  false,
	}

	r.mux.ServeHTTP(buffered, request)
	buffered.flush()
}

type bufferedResponseWriter struct {
	http.ResponseWriter

	body          bytes.Buffer
	status        int
	headerWritten bool
}

func (w *bufferedResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *bufferedResponseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}

	w.status = status
	w.headerWritten = true
}

func (w *bufferedResponseWriter) Write(data []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}

	return w.body.Write(data) //nolint:wrapcheck // bytes.Buffer cannot return an error
}

func (w *bufferedResponseWriter) flush() {
	if w.status < http.StatusBadRequest {
		w.ResponseWriter.WriteHeader(w.status)
		_, _ = io.Copy(w.ResponseWriter, &w.body)

		return
	}

	message := publicErrorMessage(w.status, w.body.Bytes())

	problem, err := json.Marshal(struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}{
		Title:  http.StatusText(w.status),
		Status: w.status,
		Detail: message,
	})
	if err != nil {
		problem = []byte(`{"title":"Internal Server Error","status":500,"detail":"internal server error"}`)
		w.status = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(w.status)
	_, _ = w.ResponseWriter.Write(problem)
}

func publicErrorMessage(status int, responseBody []byte) string {
	switch {
	case status == http.StatusUnauthorized:
		var problem struct {
			Detail string `json:"detail"`
		}

		err := json.Unmarshal(responseBody, &problem)
		if err == nil &&
			problem.Detail == refreshTokenErrorMessage {
			return refreshTokenErrorMessage
		}

		return authenticationErrorMessage
	case status == http.StatusConflict:
		return createUserConflictMessage
	case status >= http.StatusInternalServerError:
		return internalServerErrorMessage
	case status == http.StatusBadRequest,
		status == http.StatusRequestEntityTooLarge,
		status == http.StatusUnsupportedMediaType,
		status == http.StatusUnprocessableEntity:
		return "invalid request"
	default:
		return "request failed"
	}
}
