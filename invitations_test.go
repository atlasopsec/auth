package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/internal/token"
)

const invitee = "new.hire@example.com"

func inviteBody(email, role string) string {
	b, _ := json.Marshal(map[string]string{"email": email, "role": role})
	return string(b)
}

func (f orgFixture) invite(t *testing.T, tm team, actor, email, role string) response {
	t.Helper()
	return f.do(t, http.MethodPost, tm.path("/invitations"), inviteBody(email, role), withToken(tm.users[actor].Token))
}

// invitationToken returns the token from the latest invitation email to
// addr.
func (f orgFixture) invitationToken(t *testing.T, addr string) string {
	t.Helper()
	emails := f.emailsTo(addr)
	if len(emails) == 0 {
		t.Fatalf("no invitation email to %s", addr)
	}
	page, tok := linkIn(t, emails[len(emails)-1])
	if page != testAppURL+"/accept-invitation" {
		t.Fatalf("invitation link page = %s", page)
	}
	return tok
}

func (f orgFixture) accept(t *testing.T, tok, invitationToken string) response {
	t.Helper()
	return f.do(t, http.MethodPost, "/v1/invitations/accept", `{"token":"`+invitationToken+`"}`, withToken(tok))
}

func TestInvitation(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)

	res := f.invite(t, tm, "admin", " "+invitee+" ", "member")
	if res.status != http.StatusCreated {
		t.Fatalf("inviting: status %d, body %s", res.status, res.body)
	}
	var inv struct {
		ID        uuid.UUID `json:"id"`
		Email     string    `json:"email"`
		Role      string    `json:"role"`
		InvitedBy uuid.UUID `json:"invited_by"`
		ExpiresAt string    `json:"expires_at"`
	}
	if err := json.Unmarshal(res.body, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Email != invitee || inv.Role != "member" || inv.InvitedBy != tm.users["admin"].User.ID || inv.ExpiresAt != "2026-01-08T12:00:00Z" {
		t.Errorf("invitation = %+v", inv)
	}
	m := f.emailsTo(invitee)
	if len(m) != 1 || m[0].Subject != "You're invited to join Acme on Example" || !strings.Contains(m[0].Text, "7 days") {
		t.Fatalf("invitation email = %+v", m)
	}
	tok := f.invitationToken(t, invitee)

	// The invitee signs up with the invited address, verifies it, and
	// accepts.
	u := f.user(t, invitee)
	res = f.accept(t, u.Token, tok)
	if res.status != http.StatusOK || !strings.Contains(string(res.body), `"role":"member"`) || !strings.Contains(string(res.body), `"name":"Acme"`) {
		t.Fatalf("accepting: status %d, body %s", res.status, res.body)
	}
	if got := f.roleOf(t, tm.org, u.User.ID); got != "member" {
		t.Errorf("membership role = %q, want member", got)
	}
	if res := f.do(t, http.MethodGet, tm.path(""), "", withToken(u.Token)); res.status != http.StatusOK {
		t.Errorf("new member reading the organization: status %d", res.status)
	}
	if res := f.accept(t, u.Token, tok); res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "token_invalid_or_expired" {
		t.Errorf("reused link: status %d, body %s", res.status, res.body)
	}
}

func TestInvitationOnlyForTheInvitedAddress(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	f.invite(t, tm, OwnerRole, invitee, "member")
	tok := f.invitationToken(t, invitee)

	// The link was forwarded to someone else.
	other := f.user(t, "colleague@example.com")
	res := f.accept(t, other.Token, tok)
	if res.status != http.StatusForbidden || res.errorCode(t) != "invitation_email_mismatch" {
		t.Errorf("different address: status %d, body %s; want 403 invitation_email_mismatch", res.status, res.body)
	}
	if f.roleOf(t, tm.org, other.User.ID) != "" {
		t.Error("someone with a forwarded link joined")
	}

	// The right address, but not verified yet.
	unverified := f.signUp(t, strings.ToUpper(invitee))
	if res := f.accept(t, unverified.Token, tok); res.status != http.StatusForbidden || res.errorCode(t) != "email_not_verified" {
		t.Errorf("unverified: status %d, body %s; want 403 email_not_verified", res.status, res.body)
	}
	// Once verified (case doesn't matter), the same link works.
	if _, err := f.pool.Exec(context.Background(), `UPDATE auth.users SET email_verified_at = now() WHERE id = $1`, unverified.User.ID); err != nil {
		t.Fatal(err)
	}
	if res := f.accept(t, unverified.Token, tok); res.status != http.StatusOK {
		t.Errorf("after verifying: status %d, body %s", res.status, res.body)
	}
}

func TestInvitationRejects(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	outsider := f.user(t, "outsider@example.com")

	tests := []struct {
		name     string
		actor    string
		email    string
		role     string
		want     int
		wantCode string
	}{
		{"admin inviting an owner", "admin", invitee, OwnerRole, 403, "forbidden"},
		{"manager inviting an admin", "manager", invitee, "admin", 403, "forbidden"},
		{"member without members:manage", "member", invitee, "viewer", 403, "forbidden"},
		{"existing member", OwnerRole, "VIEWER@example.com", "member", 409, "already_member"},
		{"invalid email", OwnerRole, "not an email", "member", 422, "validation_failed"},
		{"undefined role", OwnerRole, invitee, "superuser", 422, "validation_failed"},
	}
	for _, tt := range tests {
		if res := f.invite(t, tm, tt.actor, tt.email, tt.role); res.status != tt.want || res.errorCode(t) != tt.wantCode {
			t.Errorf("%s: status %d, body %s; want %d %s", tt.name, res.status, res.body, tt.want, tt.wantCode)
		}
	}
	if res := f.do(t, http.MethodPost, tm.path("/invitations"), inviteBody(invitee, "viewer"), withToken(outsider.Token)); res.status != http.StatusNotFound {
		t.Errorf("outsider inviting: status %d, want 404", res.status)
	}
	if n := len(f.emailsTo(invitee)); n != 0 {
		t.Errorf("%d invitation emails from rejected requests", n)
	}
}

func TestAcceptRejects(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	u := f.user(t, invitee)

	for name, c := range map[string]struct {
		tok, body string
		want      int
		wantCode  string
	}{
		"not logged in":   {"", `{"token":"x"}`, 401, "unauthenticated"},
		"missing token":   {u.Token, `{"token":""}`, 422, "validation_failed"},
		"malformed token": {u.Token, `{"token":"abc"}`, 422, "token_invalid_or_expired"},
		"unknown token":   {u.Token, `{"token":"` + token.New() + `"}`, 422, "token_invalid_or_expired"},
	} {
		res := f.do(t, http.MethodPost, "/v1/invitations/accept", c.body, withToken(c.tok))
		if res.status != c.want || res.errorCode(t) != c.wantCode {
			t.Errorf("%s: status %d, body %s; want %d %s", name, res.status, res.body, c.want, c.wantCode)
		}
	}

	// Expired.
	f.invite(t, tm, OwnerRole, invitee, "member")
	tok := f.invitationToken(t, invitee)
	f.clock.advance(InvitationLifetime)
	if res := f.accept(t, u.Token, tok); res.status != http.StatusUnprocessableEntity {
		t.Errorf("expired: status %d, want 422", res.status)
	}

	// For a role that's since been removed from code.
	f.invite(t, tm, OwnerRole, invitee, "member")
	tok = f.invitationToken(t, invitee)
	if _, err := f.pool.Exec(context.Background(), `UPDATE auth.invitations SET role = 'retired' WHERE accepted_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if res := f.accept(t, u.Token, tok); res.status != http.StatusUnprocessableEntity {
		t.Errorf("removed role: status %d, want 422", res.status)
	}
	if f.roleOf(t, tm.org, u.User.ID) != "" {
		t.Error("joined through a rejected invitation")
	}
}

func TestAcceptWhenAlreadyMember(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	f.invite(t, tm, OwnerRole, invitee, "member")
	tok := f.invitationToken(t, invitee)
	u := f.user(t, invitee)
	// Added by another route before accepting.
	f.addMember(t, tm.org, u.User.ID, "viewer")

	res := f.accept(t, u.Token, tok)
	if res.status != http.StatusConflict || res.errorCode(t) != "already_member" {
		t.Errorf("status %d, body %s; want 409 already_member", res.status, res.body)
	}
	if got := f.roleOf(t, tm.org, u.User.ID); got != "viewer" {
		t.Errorf("role = %q, want it unchanged (viewer)", got)
	}
}

func TestReinviting(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	first := f.invite(t, tm, OwnerRole, invitee, "viewer")
	firstTok := f.invitationToken(t, invitee)

	// Within the cooldown: the same invitation comes back, and nothing is sent.
	again := f.invite(t, tm, OwnerRole, invitee, "member")
	if again.status != http.StatusCreated || string(again.body) != string(first.body) {
		t.Errorf("within the cooldown: status %d, body %s; want the existing invitation", again.status, again.body)
	}
	if n := len(f.emailsTo(invitee)); n != 1 {
		t.Errorf("%d emails within the cooldown, want 1", n)
	}

	// After it, a new invitation replaces the old one.
	f.clock.advance(emailtoken.Cooldown)
	if res := f.invite(t, tm, OwnerRole, invitee, "member"); res.status != http.StatusCreated || !strings.Contains(string(res.body), `"role":"member"`) {
		t.Fatalf("re-inviting: status %d, body %s", res.status, res.body)
	}
	secondTok := f.invitationToken(t, invitee)
	u := f.user(t, invitee)
	if res := f.accept(t, u.Token, firstTok); res.status != http.StatusUnprocessableEntity {
		t.Errorf("replaced link: status %d, want 422", res.status)
	}
	if res := f.accept(t, u.Token, secondTok); res.status != http.StatusOK {
		t.Errorf("new link: status %d, body %s", res.status, res.body)
	}
}

func TestListAndCancelInvitations(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	f.invite(t, tm, OwnerRole, "expired@example.com", "viewer")
	f.clock.advance(InvitationLifetime + time.Second)
	f.invite(t, tm, OwnerRole, "accepted@example.com", "viewer")
	acceptedTok := f.invitationToken(t, "accepted@example.com")
	f.accept(t, f.user(t, "accepted@example.com").Token, acceptedTok)
	adminInvite := f.invite(t, tm, OwnerRole, "future.admin@example.com", "admin")
	f.invite(t, tm, OwnerRole, invitee, "viewer")

	list := func(actor, query string) (response, []string) {
		res := f.do(t, http.MethodGet, tm.path("/invitations"+query), "", withToken(tm.users[actor].Token))
		var page struct {
			Data []struct {
				Email string `json:"email"`
			} `json:"data"`
		}
		_ = json.Unmarshal(res.body, &page)
		var emails []string
		for _, d := range page.Data {
			emails = append(emails, d.Email)
		}
		return res, emails
	}
	res, emails := list(OwnerRole, "")
	if res.status != http.StatusOK || strings.Join(emails, ",") != "future.admin@example.com,"+invitee {
		t.Errorf("pending invitations = %v (status %d), want only the two pending ones", emails, res.status)
	}
	if res, emails := list(OwnerRole, "?limit=1"); len(emails) != 1 || !strings.Contains(string(res.body), `"next_cursor":"`) {
		t.Errorf("limit=1: %v, body %s", emails, res.body)
	}
	if res, _ := list("viewer", ""); res.status != http.StatusForbidden {
		t.Errorf("viewer listing: status %d, want 403", res.status)
	}

	var adminInv struct {
		ID uuid.UUID `json:"id"`
	}
	_ = json.Unmarshal(adminInvite.body, &adminInv)
	cancel := func(actor string, id string) int {
		return f.do(t, http.MethodDelete, tm.path("/invitations/"+id), "", withToken(tm.users[actor].Token)).status
	}
	if got := cancel("manager", adminInv.ID.String()); got != http.StatusForbidden {
		t.Errorf("manager cancelling an admin invitation: status %d, want 403", got)
	}
	if got := cancel("admin", adminInv.ID.String()); got != http.StatusNoContent {
		t.Errorf("admin cancelling: status %d, want 204", got)
	}
	if got := cancel("admin", adminInv.ID.String()); got != http.StatusNotFound {
		t.Errorf("cancelling twice: status %d, want 404", got)
	}
	if got := cancel("admin", "abc"); got != http.StatusNotFound {
		t.Errorf("malformed ID: status %d, want 404", got)
	}
	tok := f.invitationToken(t, "future.admin@example.com")
	if res := f.accept(t, f.user(t, "future.admin@example.com").Token, tok); res.status != http.StatusUnprocessableEntity {
		t.Errorf("cancelled invitation: status %d, want 422", res.status)
	}
}

func TestInvitationsAreIsolated(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	res := f.invite(t, tm, OwnerRole, invitee, "viewer")
	var inv struct {
		ID uuid.UUID `json:"id"`
	}
	_ = json.Unmarshal(res.body, &inv)

	rival := f.user(t, "rival@example.com")
	rivalOrg := f.createOrg(t, rival.Token, "Rival").ID
	// Cancelling this organization's invitation through another one.
	path := "/v1/organizations/" + rivalOrg.String() + "/invitations/" + inv.ID.String()
	if res := f.do(t, http.MethodDelete, path, "", withToken(rival.Token)); res.status != http.StatusNotFound {
		t.Errorf("status %d, want 404", res.status)
	}
	if res := f.do(t, http.MethodGet, tm.path("/invitations"), "", withToken(rival.Token)); res.status != http.StatusNotFound {
		t.Errorf("listing another organization's invitations: status %d, want 404", res.status)
	}
}

func TestConcurrentAccepts(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	f.invite(t, tm, OwnerRole, invitee, "member")
	tok := f.invitationToken(t, invitee)
	u := f.user(t, invitee)

	const n = 5
	statuses := make(chan int, n)
	for range n {
		go func() { statuses <- f.accept(t, u.Token, tok).status }()
	}
	ok := 0
	for range n {
		switch s := <-statuses; s {
		case http.StatusOK:
			ok++
		case http.StatusUnprocessableEntity, http.StatusConflict:
		default:
			t.Errorf("status %d", s)
		}
	}
	if ok != 1 {
		t.Errorf("%d concurrent accepts succeeded, want 1", ok)
	}
}

func TestInvitationsKeepSecretsOutOfLogs(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	f.invite(t, tm, OwnerRole, invitee, "member")
	tok := f.invitationToken(t, invitee)
	f.accept(t, f.user(t, invitee).Token, tok)

	logs := f.logs.String()
	if !strings.Contains(logs, "auth: member invited") || !strings.Contains(logs, "auth: invitation accepted") {
		t.Fatalf("events weren't logged:\n%s", logs)
	}
	for _, secret := range []string{invitee, tok} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain %q", secret)
		}
	}
}
