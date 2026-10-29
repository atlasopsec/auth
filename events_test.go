package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/internal/oauth/oauthtest"
	"github.com/atlasopsec/auth/internal/totp"
)

// eventsOf returns all of a user's events, oldest first.
func (f fixture) eventsOf(t *testing.T, userID uuid.UUID) []Event {
	t.Helper()
	var all []Event
	cursor := ""
	for {
		page, err := f.auth.Events(context.Background(), userID, cursor)
		if err != nil {
			t.Fatalf("Events() error = %v", err)
		}
		all = append(all, page.Events...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	slices.Reverse(all)
	return all
}

// summary describes e as its type and metadata, like
// "login_succeeded method=password".
func summary(e Event) string {
	parts := []string{e.Type}
	for k, v := range e.Metadata {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts[1:])
	return strings.Join(parts, " ")
}

// eventSummaries returns the summaries of a user's events, oldest first.
func (f fixture) eventSummaries(t *testing.T, userID uuid.UUID) []string {
	t.Helper()
	var out []string
	for _, e := range f.eventsOf(t, userID) {
		out = append(out, summary(e))
	}
	return out
}

// allEventRows returns every stored event row as text, to search for
// things that must never be there.
func (f fixture) allEventRows(t *testing.T) string {
	t.Helper()
	var s *string
	if err := f.pool.QueryRow(context.Background(), `SELECT string_agg(e::text, E'\n') FROM auth.auth_events e`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	if s == nil {
		return ""
	}
	return *s
}

func TestEventsForAccountSecurity(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	m := f.logIn(t, testEmail)
	if res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, "not my password", "web")); res.status != http.StatusUnauthorized {
		t.Fatalf("wrong password: status %d", res.status)
	}
	var sessions sessionListJSON
	if err := json.Unmarshal(f.do(t, http.MethodGet, "/v1/sessions", "", withToken(m.Token)).body, &sessions); err != nil {
		t.Fatal(err)
	}
	var mID uuid.UUID
	for _, s := range sessions.Data {
		if s.IsCurrent {
			mID = s.ID
		}
	}
	if res := f.do(t, http.MethodDelete, "/v1/sessions/"+mID.String(), "", withToken(l.Token)); res.status != http.StatusNoContent {
		t.Fatalf("ending a session: status %d, body %s", res.status, res.body)
	}

	secret, codes := f.enableTwoFactor(t, l.Token)
	res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/recovery-codes", pwCodeBody(testPassword, f.code(secret)), withToken(l.Token))
	var regenerated struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if res.status != http.StatusOK || json.Unmarshal(res.body, &regenerated) != nil {
		t.Fatalf("regenerating codes: status %d, body %s", res.status, res.body)
	}
	codes = append(codes, regenerated.RecoveryCodes...)
	f.clock.advance(totp.Period)

	challenge := f.startChallenge(t, testEmail)
	wantError(t, "wrong code", f.verify(t, challenge, f.wrongCode(secret)), http.StatusUnauthorized, "invalid_two_factor_code")
	loginOf(t, f.verify(t, challenge, f.code(secret)))
	f.clock.advance(totp.Period)
	loginOf(t, f.verify(t, f.startChallenge(t, testEmail), regenerated.RecoveryCodes[0]))

	f.clock.advance(emailtoken.Cooldown)
	resetTok := f.requestReset(t, testEmail)
	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetCodeBody(resetTok, newPassword, regenerated.RecoveryCodes[1])); res.status != http.StatusNoContent {
		t.Fatalf("reset: status %d, body %s", res.status, res.body)
	}
	res = f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, newPassword, "web"))
	n := loginOf(t, f.verify(t, challengeIn(t, res), f.code(secret)))
	f.clock.advance(totp.Period)
	if res := f.do(t, http.MethodDelete, "/v1/users/me/two-factor", pwCodeBody(newPassword, f.code(secret)), withToken(n.Token)); res.status != http.StatusNoContent {
		t.Fatalf("disabling 2FA: status %d, body %s", res.status, res.body)
	}
	if res := f.do(t, http.MethodPost, "/v1/users/me/password", changeBody(newPassword, testPassword), withToken(n.Token)); res.status != http.StatusNoContent {
		t.Fatalf("changing password: status %d, body %s", res.status, res.body)
	}
	o := f.logIn(t, testEmail)
	if res := f.do(t, http.MethodDelete, "/v1/sessions/current", "", withToken(o.Token)); res.status != http.StatusNoContent {
		t.Fatalf("logging out: status %d", res.status)
	}
	if res := f.do(t, http.MethodDelete, "/v1/sessions", "", withToken(n.Token)); res.status != http.StatusNoContent {
		t.Fatalf("logging out everywhere: status %d", res.status)
	}

	want := []string{
		"login_succeeded method=password",
		"login_failed method=password",
		"session_ended",
		"two_factor_enabled",
		"recovery_codes_regenerated",
		"login_failed method=two_factor",
		"login_succeeded method=two_factor",
		"recovery_code_used",
		"login_succeeded method=two_factor",
		"password_reset",
		"recovery_code_used",
		"login_succeeded method=two_factor",
		"two_factor_disabled",
		"password_changed",
		"login_succeeded method=password",
		"logout",
		"logout_everywhere",
	}
	if diff := cmp.Diff(want, f.eventSummaries(t, l.User.ID)); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}

	rows := f.allEventRows(t)
	secrets := append([]string{testEmail, testPassword, newPassword, l.Token, m.Token, n.Token, o.Token, resetTok, challenge, string(secret)}, codes...)
	for _, s := range secrets {
		if strings.Contains(rows, s) {
			t.Errorf("events contain %q:\n%s", s, rows)
		}
	}
}

func TestEventDetails(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	long := strings.Repeat("é", 600)
	f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"),
		withHeader("User-Agent", long), fromIP("192.0.2.7"))
	f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"),
		fromIP("10.0.0.5"), withHeader("X-Forwarded-For", "192.0.2.8"), withHeader("X-Forwarded-User-Agent", "Example/1.0"))
	// Under 512 characters but over 512 bytes, so kept whole.
	f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"),
		withHeader("User-Agent", strings.Repeat("é", 300)), fromIP("192.0.2.7"))

	events := f.eventsOf(t, l.User.ID)
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	for i, want := range []struct {
		ip, ua string
	}{
		{"192.0.2.7", strings.Repeat("é", 512)},
		{"192.0.2.8", "Example/1.0"},
		{"192.0.2.7", strings.Repeat("é", 300)},
	} {
		e := events[i]
		if e.IP == nil || *e.IP != netip.MustParseAddr(want.ip) || e.UserAgent != want.ua {
			t.Errorf("event %d: IP %v, user agent %q; want %s, %q", i, e.IP, e.UserAgent, want.ip, want.ua)
		}
		if e.ID == uuid.Nil || !e.CreatedAt.Equal(f.clock.now()) || e.CreatedAt.Location() != time.UTC {
			t.Errorf("event %d: ID %s, created %v; want an ID and %v", i, e.ID, e.CreatedAt, f.clock.now())
		}
		if *e.UserID != l.User.ID || e.ActorID != nil {
			t.Errorf("event %d: user %v, actor %v", i, e.UserID, e.ActorID)
		}
	}
}

func TestFailedLoginEventsWithoutAccount(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	loginOf(t, f.googleSignIn(t, ada("g-1")))
	for _, email := range []string{"nobody@example.com", testEmail} {
		if res := f.do(t, http.MethodPost, "/v1/sessions", credentials(email, testPassword, "web"), fromIP("192.0.2.9")); res.status != http.StatusUnauthorized {
			t.Fatalf("%s: status %d", email, res.status)
		}
	}
	var n int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM auth.auth_events
		WHERE event = 'login_failed' AND user_id IS NULL AND ip = '192.0.2.9' AND metadata = '{"method": "password"}'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("%d failed-login events with no user, want 2", n)
	}
	if rows := f.allEventRows(t); strings.Contains(rows, "nobody@example.com") || strings.Contains(rows, testEmail) {
		t.Errorf("events contain an email:\n%s", rows)
	}
}

func TestOAuthEvents(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	g := loginOf(t, f.googleSignIn(t, ada("g-1")))
	loginOf(t, f.googleSignIn(t, ada("g-1")))
	if diff := cmp.Diff([]string{
		"oauth_linked provider=google",
		"login_succeeded method=google",
		"login_succeeded method=google",
	}, f.eventSummaries(t, g.User.ID)); diff != "" {
		t.Errorf("Google sign-ins (-want +got):\n%s", diff)
	}

	grace := f.signUp(t, "grace@example.com")
	if res := f.linkGitHub(t, grace.Token, testPassword, 7); res.status != http.StatusCreated {
		t.Fatalf("linking: status %d, body %s", res.status, res.body)
	}
	if res := f.unlink(t, grace.Token, f.oauthAccounts(t, grace.Token).Data[0].ID, testPassword); res.status != http.StatusNoContent {
		t.Fatalf("unlinking: status %d, body %s", res.status, res.body)
	}
	if diff := cmp.Diff([]string{"oauth_linked provider=github", "oauth_unlinked provider=github"}, f.eventSummaries(t, grace.User.ID)); diff != "" {
		t.Errorf("linking GitHub (-want +got):\n%s", diff)
	}

	a := loginOf(t, f.appleSignIn(t, oauthtest.AppleUser{Subject: "a-1", Email: "hopper@example.com", EmailVerified: true}))
	if diff := cmp.Diff([]string{"oauth_linked provider=apple", "login_succeeded method=apple"}, f.eventSummaries(t, a.User.ID)); diff != "" {
		t.Errorf("Apple sign-in (-want +got):\n%s", diff)
	}
}

func TestVerificationAndEmailChangeEvents(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)
	if res := f.requestEmailChange(t, l.Token, newEmail); res.status != http.StatusAccepted {
		t.Fatalf("requesting change: status %d", res.status)
	}
	_, tok := linkIn(t, f.emailsTo(newEmail)[0])
	if res := f.confirmEmailChange(t, tok); res.status != http.StatusNoContent {
		t.Fatalf("confirming change: status %d, body %s", res.status, res.body)
	}
	if diff := cmp.Diff([]string{"login_succeeded method=verification_link", "email_changed"}, f.eventSummaries(t, l.User.ID)); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}
	if rows := f.allEventRows(t); strings.Contains(rows, testEmail) || strings.Contains(rows, newEmail) {
		t.Errorf("events contain an email:\n%s", rows)
	}
}

// A verification link for a user with 2FA logs in only once the code is
// entered.
func TestVerificationWithTwoFactorEvents(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	_, tok := linkIn(t, f.emailsTo(testEmail)[0])
	res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(tok, testPassword))
	loginOf(t, f.verify(t, challengeIn(t, res), f.code(secret)))
	if diff := cmp.Diff([]string{"two_factor_enabled", "login_succeeded method=two_factor"}, f.eventSummaries(t, l.User.ID)); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}
}

func TestOrganizationEvents(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	owner, admin := tm.users[OwnerRole].User.ID, tm.users["admin"].User.ID
	org := tm.org.String()
	if diff := cmp.Diff([]string{"member_added organization_id=" + org + " role=owner"}, f.eventSummaries(t, owner)); diff != "" {
		t.Errorf("creating an organization (-want +got):\n%s", diff)
	}

	if res := f.invite(t, tm, "admin", invitee, "member"); res.status != http.StatusCreated {
		t.Fatalf("inviting: status %d", res.status)
	}
	invitation := f.invitationToken(t, invitee)
	hire := f.user(t, invitee)
	if res := f.accept(t, hire.Token, invitation); res.status != http.StatusOK {
		t.Fatalf("accepting: status %d, body %s", res.status, res.body)
	}
	if res := f.setRole(t, tm, OwnerRole, hire.User.ID, "viewer"); res.status != http.StatusOK {
		t.Fatalf("changing role: status %d, body %s", res.status, res.body)
	}
	if res := f.do(t, http.MethodDelete, tm.path("/members/"+hire.User.ID.String()), "", withToken(tm.users["admin"].Token)); res.status != http.StatusNoContent {
		t.Fatalf("removing: status %d, body %s", res.status, res.body)
	}

	events := f.eventsOf(t, hire.User.ID)
	var got []string
	for _, e := range events {
		actor := "none"
		if e.ActorID != nil {
			actor = map[uuid.UUID]string{owner: "owner", admin: "admin"}[*e.ActorID]
		}
		got = append(got, summary(e)+" by "+actor)
	}
	want := []string{
		"member_added organization_id=" + org + " role=member by admin",
		"org_role_changed organization_id=" + org + " role=viewer by owner",
		"member_removed organization_id=" + org + " by admin",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("membership events (-want +got):\n%s", diff)
	}

	o, err := f.auth.CreateOrganization(context.Background(), "Initech", admin, Actor{})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.eventSummaries(t, admin); !slices.Contains(got, "member_added organization_id="+o.ID.String()+" role=owner") {
		t.Errorf("CreateOrganization: events %v", got)
	}
}

func TestAdminEvents(t *testing.T) {
	t.Parallel()
	f := setupAccess(t)
	ctx := context.Background()
	l := f.signUp(t, testEmail)
	if err := f.auth.SetAppRole(ctx, l.User.ID, "support", Actor{}); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.SetAppRole(ctx, l.User.ID, "", Actor{}); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.SetTwoFactorRequired(ctx, l.User.ID, true, Actor{}); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.SetTwoFactorRequired(ctx, l.User.ID, false, Actor{}); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.ResetTwoFactor(ctx, l.User.ID, Actor{}); err != nil {
		t.Fatal(err)
	}
	f.enableTwoFactor(t, l.Token)
	if err := f.auth.ResetTwoFactor(ctx, l.User.ID, Actor{}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"app_role_changed role=support",
		"app_role_changed role=",
		"two_factor_required_changed required=true",
		"two_factor_required_changed required=false",
		"two_factor_enabled",
		"two_factor_reset",
	}
	if diff := cmp.Diff(want, f.eventSummaries(t, l.User.ID)); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}
	if err := f.auth.SetTwoFactorRequired(ctx, uuid.Must(uuid.NewV7()), true, Actor{}); err == nil {
		t.Error("SetTwoFactorRequired for no user: no error")
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.auth_events WHERE user_id IS NULL`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d events with no user (%v), want none for a failed change", n, err)
	}
}

func TestOnEvent(t *testing.T) {
	t.Parallel()
	var got []Event
	f := setup(t, Hooks{OnEvent: func(ctx context.Context, e Event) {
		if ctx == nil {
			t.Error("OnEvent got no context")
		}
		got = append(got, e)
	}})
	l := f.signUp(t, testEmail)
	f.logIn(t, testEmail)
	stored := f.eventsOf(t, l.User.ID)
	if diff := cmp.Diff(stored, got, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("OnEvent got (-stored +got):\n%s", diff)
	}

	// An event that fails to record is logged, and not passed on.
	f.auth.recordEvent(context.Background(), Event{Type: "Not A Type", UserID: &l.User.ID})
	if len(got) != 1 {
		t.Errorf("OnEvent called %d times, want once", len(got))
	}
	if !strings.Contains(f.logs.String(), "auth: recording security event") || !strings.Contains(f.logs.String(), `event="Not A Type"`) {
		t.Errorf("failure not logged:\n%s", f.logs.String())
	}
}

func TestEventsPaging(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	ctx := context.Background()
	ada, grace, hopper := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, id := range []uuid.UUID{ada, grace, hopper} {
		if _, err := f.pool.Exec(ctx, `INSERT INTO auth.users (id, email) VALUES ($1, $2)`, id, id.String()+"@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 120 {
		f.auth.recordEvent(ctx, Event{Type: EventLogout, UserID: &ada, Metadata: map[string]string{"n": string(rune('a' + i%26))}})
		f.auth.recordEvent(ctx, Event{Type: EventLogout, UserID: &grace})
		if i < eventPageSize {
			f.auth.recordEvent(ctx, Event{Type: EventLogout, UserID: &hopper})
		}
	}

	var sizes []int
	var all []Event
	cursor := ""
	for {
		page, err := f.auth.Events(ctx, ada, cursor)
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(page.Events))
		all = append(all, page.Events...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if diff := cmp.Diff([]int{50, 50, 20}, sizes); diff != "" {
		t.Errorf("page sizes (-want +got):\n%s", diff)
	}
	for i, e := range all {
		if *e.UserID != ada {
			t.Fatalf("event %d is another user's", i)
		}
		if i > 0 && e.ID.String() >= all[i-1].ID.String() {
			t.Fatalf("event %d isn't older than the one before", i)
		}
	}
	if want := string(rune('a' + 119%26)); all[0].Metadata["n"] != want {
		t.Errorf("newest event n=%s, want %s", all[0].Metadata["n"], want)
	}

	// Exactly a page has no next page.
	if page, err := f.auth.Events(ctx, hopper, ""); err != nil || len(page.Events) != 50 || page.NextCursor != "" {
		t.Errorf("50 events: %d on the page, cursor %q, error %v; want all 50 and no cursor", len(page.Events), page.NextCursor, err)
	}
	// Events without metadata store an empty object, not JSON null.
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.auth_events WHERE user_id = $1 AND metadata = '{}'`, grace).Scan(&n); err != nil || n != 120 {
		t.Errorf("%d of grace's events have empty metadata (%v), want 120", n, err)
	}

	if _, err := f.auth.Events(ctx, ada, "not-a-cursor"); !errors.Is(err, ErrBadCursor) {
		t.Errorf("bad cursor: error %v, want ErrBadCursor", err)
	}
	page, err := f.auth.Events(ctx, uuid.Must(uuid.NewV7()), "")
	if err != nil || len(page.Events) != 0 || page.NextCursor != "" || page.Events == nil {
		t.Errorf("user with no events: %+v, %v; want an empty page", page, err)
	}
}

func TestCleanupDeletesYearOldEvents(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	ctx := context.Background()
	l := f.signUp(t, testEmail)
	f.auth.recordEvent(ctx, Event{Type: EventLogout, UserID: &l.User.ID, Metadata: map[string]string{"n": "old"}})
	f.clock.advance(2 * day)
	f.auth.recordEvent(ctx, Event{Type: EventLogout, UserID: &l.User.ID, Metadata: map[string]string{"n": "new"}})
	f.clock.advance(364 * day)
	if err := f.auth.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"logout n=new"}, f.eventSummaries(t, l.User.ID)); diff != "" {
		t.Errorf("events after cleanup (-want +got):\n%s", diff)
	}
}

func TestDeletingUserKeepsEvents(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	ctx := context.Background()
	l := f.signUp(t, testEmail)
	m := f.signUp(t, "grace@example.com")
	f.auth.recordEvent(ctx, Event{Type: EventAppRoleChanged, UserID: &l.User.ID, ActorID: &m.User.ID})
	if _, err := f.pool.Exec(ctx, `DELETE FROM auth.users`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.auth_events WHERE user_id IS NULL AND actor_id IS NULL`).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d events kept without their users (%v), want 1", n, err)
	}
}

func TestAdminEventsRecordTheActor(t *testing.T) {
	t.Parallel()
	f := setupAccess(t)
	ctx := context.Background()
	admin := f.signUp(t, "admin@example.com")
	target := f.signUp(t, testEmail)

	// A project's own admin endpoint, as admin tooling would write it.
	var by Actor
	h := f.auth.Authenticated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		by = f.auth.ActorOf(r)
	}))
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/admin", nil)
	r.RemoteAddr = proxyAddr
	r.Header.Set("Authorization", "Bearer "+admin.Token)
	r.Header.Set("X-Forwarded-For", "192.0.2.44")
	r.Header.Set("X-Forwarded-User-Agent", "AdminTool/1.0")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if by.UserID == nil || *by.UserID != admin.User.ID || by.IP == nil || *by.IP != netip.MustParseAddr("192.0.2.44") || by.UserAgent != "AdminTool/1.0" {
		t.Fatalf("ActorOf = %+v, want the admin from 192.0.2.44 with AdminTool/1.0", by)
	}

	if err := f.auth.SetAppRole(ctx, target.User.ID, "support", by); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.SetAppRole(ctx, target.User.ID, "", by); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.SetTwoFactorRequired(ctx, target.User.ID, true, by); err != nil {
		t.Fatal(err)
	}
	f.enableTwoFactor(t, target.Token)
	if err := f.auth.ResetTwoFactor(ctx, target.User.ID, by); err != nil {
		t.Fatal(err)
	}
	o, err := f.auth.CreateOrganization(ctx, "Acme", target.User.ID, by)
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, e := range f.eventsOf(t, target.User.ID) {
		if e.Type == EventTwoFactorEnabled {
			continue
		}
		if e.ActorID == nil || *e.ActorID != admin.User.ID || e.IP == nil || e.IP.String() != "192.0.2.44" || e.UserAgent != "AdminTool/1.0" {
			t.Errorf("%s: actor %v, IP %v, user agent %q; want the admin's", e.Type, e.ActorID, e.IP, e.UserAgent)
		}
		got = append(got, summary(e))
	}
	want := []string{
		"app_role_changed role=support",
		"app_role_changed role=",
		"two_factor_required_changed required=true",
		"two_factor_reset",
		"member_added organization_id=" + o.ID.String() + " role=owner",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}

	// Without a logged-in user, ActorOf names no one.
	if by := f.auth.ActorOf(httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)); by.UserID != nil {
		t.Errorf("ActorOf without a session: UserID = %v, want nil", by.UserID)
	}
}
