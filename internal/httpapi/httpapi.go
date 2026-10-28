// Package httpapi holds the request and response plumbing shared by the
// module's HTTP endpoints, following the API design standard: the standard
// error format, strict JSON decoding, request IDs, and finding the real
// client behind a trusted proxy.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/google/uuid"
)

// MaxBodySize is the largest request body the module reads.
const MaxBodySize = 64 << 10

// FieldError describes one invalid field in a validation_failed error.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code      string       `json:"code"`
	Message   string       `json:"message"`
	RequestID string       `json:"request_id"`
	Details   []FieldError `json:"details"`
}

// WriteError writes an error in the standard format. message must be safe
// to show to users.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string, details []FieldError) {
	WriteJSON(w, r, status, errorBody{Error: errorDetail{
		Code:      code,
		Message:   message,
		RequestID: RequestIDFrom(r.Context()),
		Details:   details,
	}})
}

// WriteInternalError logs err and writes a generic 500. The client never
// sees err, which may contain internal details.
func WriteInternalError(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	log.ErrorContext(r.Context(), "auth: internal error",
		slog.String("request_id", RequestIDFrom(r.Context())),
		slog.String("error", err.Error()))
	WriteError(w, r, http.StatusInternalServerError, "internal_error", "Something went wrong. Please try again.", nil)
}

// WriteJSON writes v as a JSON response.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		// Only possible for a programming error in the response types.
		slog.ErrorContext(r.Context(), "auth: encoding response", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

// Decoding errors, for mapping to responses.
var (
	ErrBadRequest = errors.New("malformed request body")
	ErrTooLarge   = errors.New("request body too large")
)

// Decode reads a single JSON object from r's body into dst. Unknown fields
// and trailing data are rejected, so typos fail loudly instead of being
// ignored.
func Decode(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodySize))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return ErrTooLarge
		}
		return fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return ErrTooLarge
		}
		return fmt.Errorf("%w: trailing data after JSON object", ErrBadRequest)
	}
	return nil
}

// WriteDecodeError writes the response for an error from Decode.
func WriteDecodeError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrTooLarge) {
		WriteError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "The request is too large.", nil)
		return
	}
	WriteError(w, r, http.StatusBadRequest, "bad_request", "The request couldn't be read.", nil)
}

type requestIDKey struct{}

// RequestIDHeader carries the request ID in requests and responses.
const RequestIDHeader = "X-Request-ID"

// maxRequestID bounds an incoming request ID, which ends up in logs.
const maxRequestID = 128

// WithRequestID wraps h so every request has an ID, available through
// RequestIDFrom and returned in the X-Request-ID response header. It reuses
// an ID already set on the response by the project's own middleware, then a
// well-formed incoming X-Request-ID, and otherwise generates a UUIDv7.
func WithRequestID(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(requestIDKey{}).(string); ok {
			h.ServeHTTP(w, r)
			return
		}
		id := w.Header().Get(RequestIDHeader)
		if !validRequestID(id) {
			id = r.Header.Get(RequestIDHeader)
		}
		if !validRequestID(id) {
			id = uuid.Must(uuid.NewV7()).String()
		}
		w.Header().Set(RequestIDHeader, id)
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// RequestIDFrom returns the request ID set by WithRequestID, or "".
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// validRequestID accepts IDs that are safe to log and echo: short, and only
// letters, digits, and - _ . characters.
func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestID {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// ForwardedUserAgentHeader carries the real client's User-Agent from a
// trusted proxy (Next.js), whose own User-Agent is in User-Agent.
const ForwardedUserAgentHeader = "X-Forwarded-User-Agent"

// Client returns the real client's IP address and user agent.
//
// If the request comes from a trusted proxy, X-Forwarded-For is read from
// the right, skipping trusted addresses, and the first untrusted one is the
// client: entries further left were written by the client itself and can't
// be believed. X-Forwarded-User-Agent is used if present. Requests from
// anywhere else use the connection's own address and User-Agent. ip is nil
// if no address can be determined.
func Client(r *http.Request, trusted []netip.Prefix) (ip *netip.Addr, userAgent string) {
	peer, ok := remoteAddr(r)
	if !ok {
		return nil, r.UserAgent()
	}
	if !isTrusted(peer, trusted) {
		return &peer, r.UserAgent()
	}

	client := peer
	hops := r.Header.Values("X-Forwarded-For")
walk:
	for i := len(hops) - 1; i >= 0; i-- {
		parts := strings.Split(hops[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			addr, err := netip.ParseAddr(strings.TrimSpace(parts[j]))
			if err != nil {
				// A malformed entry means nothing to its left can be
				// trusted; the last good hop is the best we know.
				break walk
			}
			client = addr.Unmap()
			if !isTrusted(client, trusted) {
				break walk
			}
		}
	}

	ua := r.Header.Get(ForwardedUserAgentHeader)
	if ua == "" {
		ua = r.UserAgent()
	}
	return &client, ua
}

func remoteAddr(r *http.Request) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
