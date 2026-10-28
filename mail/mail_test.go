package mail

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestWriter(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.Send(t.Context(), Message{To: "ada@example.com", Subject: "Hello", Text: "Body", HTML: "<p>Body</p>"}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	want := "To: ada@example.com\nSubject: Hello\n\nBody\n\n"
	if diff := cmp.Diff(want, buf.String()); diff != "" {
		t.Errorf("output (-want +got):\n%s", diff)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriterError(t *testing.T) {
	t.Parallel()
	if err := NewWriter(failingWriter{}).Send(t.Context(), Message{}); err == nil {
		t.Error("Send() to a failing writer: error = nil, want an error")
	}
}
