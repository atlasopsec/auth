package mailtest

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/atlasopsec/auth/mail"
)

func TestRecorder(t *testing.T) {
	t.Parallel()
	var r Recorder
	a := mail.Message{To: "a@example.com", Subject: "A"}
	b := mail.Message{To: "b@example.com", Subject: "B"}
	if err := r.Send(t.Context(), a); err != nil {
		t.Fatal(err)
	}

	broken := errors.New("provider down")
	r.Fail(broken)
	if err := r.Send(t.Context(), mail.Message{To: "lost@example.com"}); !errors.Is(err, broken) {
		t.Errorf("Send() after Fail = %v, want %v", err, broken)
	}
	r.Fail(nil)
	if err := r.Send(t.Context(), b); err != nil {
		t.Fatal(err)
	}

	got := r.Messages()
	if diff := cmp.Diff([]mail.Message{a, b}, got); diff != "" {
		t.Errorf("Messages() (-want +got):\n%s", diff)
	}
	// The returned slice is a copy.
	got[0].To = "changed"
	if r.Messages()[0].To != "a@example.com" {
		t.Error("Messages() returned the Recorder's own slice")
	}
}
