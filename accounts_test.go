package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/atlasopsec/auth/internal/password"
)

// testHash is an argon2id hash of testPassword, as another system that
// uses the module's format would hand it over.
func testHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := password.Hash(pw, password.DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// bcryptHash is a bcrypt hash of pw, as many other systems store them.
func bcryptHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// adminActor is an admin making changes from tooling.
func adminActor(t *testing.T, f orgFixture) (Actor, uuid.UUID) {
	t.Helper()
	admin := f.user(t, "admin-tool@example.com")
	id := admin.User.ID
	return Actor{UserID: &id}, id
}

func TestCreateUser(t *testing.T) {
	t.Parallel()
	var hooked []User
	// Verify first mode, the default.
	f := setupWith(t, Config{Hooks: Hooks{OnUserCreated: func(_ context.Context, _ pgx.Tx, u User) error {
		hooked = append(hooked, u)
		return nil
	}}})
	admin, err := f.auth.CreateUser(context.Background(), NewUser{Email: "admin-tool@example.com"}, Actor{})
	if err != nil {
		t.Fatal(err)
	}
	adminID := admin.ID
	by := Actor{UserID: &adminID}
	hooked = nil

	u, err := f.auth.CreateUser(context.Background(), NewUser{Email: "  Ada@Example.com ", PasswordHash: testHash(t, testPassword)}, by)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if u.Email != "Ada@Example.com" || !u.EmailVerified || u.ID == uuid.Nil {
		t.Errorf("CreateUser() = %+v, want a new verified user with the trimmed email", u)
	}
	if len(hooked) != 1 || hooked[0].ID != u.ID {
		t.Errorf("OnUserCreated ran for %v, want once for the new user", hooked)
	}
	// Verified, so it logs in even in verify first mode, with the password
	// behind the hash, found regardless of case.
	if l := f.logIn(t, "ada@example.com"); l.User.ID != u.ID {
		t.Errorf("logged in as %v, want %v", l.User.ID, u.ID)
	}
	if got := f.sent(); len(got) != 0 {
		t.Errorf("sent %d emails, want none", len(got))
	}
	events := f.eventsOf(t, u.ID)
	if len(events) == 0 || events[0].Type != EventUserCreated || events[0].ActorID == nil || *events[0].ActorID != adminID {
		t.Errorf("first event %+v, want user_created by the admin", events)
	}
}

func TestCreateUserWithoutPassword(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	u, err := f.auth.CreateUser(context.Background(), NewUser{Email: testEmail}, Actor{})
	if err != nil {
		t.Fatal(err)
	}
	// No password: a login fails like a wrong password, and a password
	// reset can add one.
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"))
	if res.status != http.StatusUnauthorized || res.errorCode(t) != "invalid_credentials" {
		t.Errorf("login: status %d, body %s", res.status, res.body)
	}
	var hash *string
	if err := f.pool.QueryRow(context.Background(), `SELECT password_hash FROM auth.users WHERE id = $1`, u.ID).Scan(&hash); err != nil || hash != nil {
		t.Errorf("password_hash = %v (%v), want NULL", hash, err)
	}
}

func TestCreateUserRejects(t *testing.T) {
	t.Parallel()
	refuse := false
	f := setupOrgs(t, Config{Hooks: Hooks{OnUserCreated: func(context.Context, pgx.Tx, User) error {
		if refuse {
			return ErrSignUpNotAllowed
		}
		return nil
	}}})
	ctx := context.Background()
	f.user(t, testEmail)
	before := f.userCount(t)
	hash := testHash(t, testPassword)

	tests := []struct {
		name string
		u    NewUser
		want error
	}{
		{"blank email", NewUser{Email: " ", PasswordHash: hash}, ErrInvalidEmail},
		{"display name", NewUser{Email: "Ada <ada@example.org>", PasswordHash: hash}, ErrInvalidEmail},
		{"too long", NewUser{Email: strings.Repeat("a", 250) + "@example.com", PasswordHash: hash}, ErrInvalidEmail},
		{"taken, other case", NewUser{Email: strings.ToUpper(testEmail), PasswordHash: hash}, ErrEmailTaken},
		{"plain password", NewUser{Email: "grace@example.com", PasswordHash: testPassword}, ErrInvalidPasswordHash},
		{"truncated hash", NewUser{Email: "grace@example.com", PasswordHash: hash[:len(hash)-10]}, ErrInvalidPasswordHash},
		{"bcrypt hash", NewUser{Email: "grace@example.com", PasswordHash: bcryptHash(t, testPassword)}, ErrInvalidPasswordHash},
	}
	for _, tt := range tests {
		_, err := f.auth.CreateUser(ctx, tt.u, Actor{})
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: error = %v, want %v", tt.name, err, tt.want)
		}
		if err != nil && tt.u.PasswordHash != "" && strings.Contains(err.Error(), tt.u.PasswordHash) {
			t.Errorf("%s: error %q contains the hash", tt.name, err)
		}
	}

	refuse = true
	if _, err := f.auth.CreateUser(ctx, NewUser{Email: "grace@example.com", PasswordHash: hash}, Actor{}); !errors.Is(err, ErrSignUpNotAllowed) {
		t.Errorf("hook refused: error = %v, want ErrSignUpNotAllowed", err)
	}
	if got := f.userCount(t); got != before {
		t.Errorf("%d users, want %d: nothing created", got, before)
	}
}

func TestUpdateUser(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	by, adminID := adminActor(t, f)
	l := f.user(t, testEmail)
	id := l.User.ID

	// Nothing to change: sessions stay and nothing is recorded.
	same := testEmail
	if _, err := f.auth.UpdateUser(ctx, id, UserChanges{Email: &same}, by); err != nil {
		t.Fatal(err)
	}
	if n := f.sessionCount(t, id); n != 1 {
		t.Errorf("%d sessions after a no-op update, want 1", n)
	}

	newEmail := "ada.lovelace@example.com"
	u, err := f.auth.UpdateUser(ctx, id, UserChanges{Email: &newEmail}, by)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != newEmail || !u.EmailVerified {
		t.Errorf("UpdateUser() = %+v, want the new, verified email", u)
	}
	if n := f.sessionCount(t, id); n != 0 {
		t.Errorf("%d sessions after an email change, want 0", n)
	}
	if res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web")); res.status != http.StatusUnauthorized {
		t.Errorf("login with the old email: status %d", res.status)
	}
	f.logIn(t, newEmail)

	newPassword := "a different long password"
	hash := testHash(t, newPassword)
	if _, err := f.auth.UpdateUser(ctx, id, UserChanges{PasswordHash: &hash}, by); err != nil {
		t.Fatal(err)
	}
	if n := f.sessionCount(t, id); n != 0 {
		t.Errorf("%d sessions after a password change, want 0", n)
	}
	if res := f.do(t, http.MethodPost, "/v1/sessions", credentials(newEmail, testPassword, "web")); res.status != http.StatusUnauthorized {
		t.Errorf("login with the old password: status %d", res.status)
	}
	if res := f.do(t, http.MethodPost, "/v1/sessions", credentials(newEmail, newPassword, "web")); res.status != http.StatusCreated {
		t.Errorf("login with the new password: status %d, body %s", res.status, res.body)
	}
	// The same hash again changes nothing.
	if _, err := f.auth.UpdateUser(ctx, id, UserChanges{PasswordHash: &hash}, by); err != nil {
		t.Fatal(err)
	}
	if n := f.sessionCount(t, id); n != 1 {
		t.Errorf("%d sessions after setting the same hash, want 1", n)
	}

	none := ""
	if _, err := f.auth.UpdateUser(ctx, id, UserChanges{PasswordHash: &none}, by); err != nil {
		t.Fatal(err)
	}
	if res := f.do(t, http.MethodPost, "/v1/sessions", credentials(newEmail, newPassword, "web")); res.status != http.StatusUnauthorized {
		t.Errorf("login after removing the password: status %d", res.status)
	}

	var got []string
	for _, e := range f.eventsOf(t, id) {
		if e.ActorID != nil && *e.ActorID == adminID {
			got = append(got, summary(e))
		}
	}
	want := []string{"email_changed", "password_changed", "password_changed"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("events by the admin (-want +got):\n%s", diff)
	}
	if rows := f.allEventRows(t); strings.Contains(rows, hash) || strings.Contains(rows, newEmail) {
		t.Error("event log contains a hash or an email address")
	}
}

func TestUpdateUserRejects(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	l := f.user(t, testEmail)
	f.user(t, "grace@example.com")

	taken, bad, badHash := "GRACE@example.com", "not an email", "$argon2id$v=19$nonsense"
	tests := []struct {
		name string
		id   uuid.UUID
		c    UserChanges
		want error
	}{
		{"taken email", l.User.ID, UserChanges{Email: &taken}, ErrEmailTaken},
		{"invalid email", l.User.ID, UserChanges{Email: &bad}, ErrInvalidEmail},
		{"invalid hash", l.User.ID, UserChanges{PasswordHash: &badHash}, ErrInvalidPasswordHash},
		{"no such user, invalid email", uuid.Must(uuid.NewV7()), UserChanges{Email: &bad}, ErrInvalidEmail},
		{"no such user", uuid.Must(uuid.NewV7()), UserChanges{}, ErrUserNotFound},
	}
	for _, tt := range tests {
		if _, err := f.auth.UpdateUser(ctx, tt.id, tt.c, Actor{}); !errors.Is(err, tt.want) {
			t.Errorf("%s: error = %v, want %v", tt.name, err, tt.want)
		}
	}
	// A failed change changes nothing.
	if n := f.sessionCount(t, l.User.ID); n != 1 {
		t.Errorf("%d sessions, want 1", n)
	}
	f.logIn(t, testEmail)
}

func TestDeleteUser(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	by, adminID := adminActor(t, f)
	owner := f.user(t, "owner@example.com")
	l := f.user(t, testEmail)
	org := f.createOrg(t, owner.Token, "Acme").ID
	f.addMember(t, org, l.User.ID, "member")

	if err := f.auth.DeleteUser(ctx, l.User.ID, by); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	if res := f.do(t, http.MethodGet, "/v1/users/me", "", withToken(l.Token)); res.status != http.StatusUnauthorized {
		t.Errorf("deleted user's session: status %d, want 401", res.status)
	}
	if role := f.roleOf(t, org, l.User.ID); role != "" {
		t.Errorf("deleted user still has role %q", role)
	}
	var meta map[string]string
	var actor *uuid.UUID
	err := f.pool.QueryRow(ctx, `SELECT metadata, actor_id FROM auth.auth_events WHERE event = 'user_deleted'`).Scan(&meta, &actor)
	if err != nil || meta["user_id"] != l.User.ID.String() || actor == nil || *actor != adminID {
		t.Errorf("user_deleted event: metadata %v, actor %v (%v)", meta, actor, err)
	}

	if err := f.auth.DeleteUser(ctx, l.User.ID, by); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("deleting again: error = %v, want ErrUserNotFound", err)
	}
}

func TestDeleteUserKeepsAnOwner(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	owner := f.user(t, "owner@example.com")
	org := f.createOrg(t, owner.Token, "Acme").ID
	f.createOrg(t, owner.Token, "Second")

	if err := f.auth.DeleteUser(ctx, owner.User.ID, Actor{}); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("deleting the only owner: error = %v, want ErrLastOwner", err)
	}
	if role := f.roleOf(t, org, owner.User.ID); role != OwnerRole {
		t.Errorf("owner's role is %q after a refused delete", role)
	}
	// Owning one organization with another owner isn't enough: the other
	// one still has only this owner.
	other := f.user(t, "other@example.com")
	f.addMember(t, org, other.User.ID, OwnerRole)
	if err := f.auth.DeleteUser(ctx, owner.User.ID, Actor{}); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("deleting one of the owners: error = %v, want ErrLastOwner", err)
	}
}

func TestDeleteUserWithAnotherOwner(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	owner := f.user(t, "owner@example.com")
	other := f.user(t, "other@example.com")
	org := f.createOrg(t, owner.Token, "Acme").ID
	f.addMember(t, org, other.User.ID, OwnerRole)
	if err := f.auth.DeleteUser(context.Background(), owner.User.ID, Actor{}); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	if role := f.roleOf(t, org, other.User.ID); role != OwnerRole {
		t.Errorf("other owner's role is %q", role)
	}
}

func TestDeleteUserAndDemotionConcurrently(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	for range 5 {
		a := f.user(t, uuid.NewString()+"@example.com")
		b := f.user(t, uuid.NewString()+"@example.com")
		org := f.createOrg(t, a.Token, "Acme").ID
		f.addMember(t, org, b.User.ID, OwnerRole)

		var wg sync.WaitGroup
		wg.Go(func() { _ = f.auth.DeleteUser(ctx, a.User.ID, Actor{}) })
		wg.Go(func() { _ = f.auth.SetMemberRole(ctx, org, b.User.ID, "viewer", Actor{}) })
		wg.Wait()
		var owners int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.memberships WHERE organization_id = $1 AND role = 'owner'`, org).Scan(&owners); err != nil {
			t.Fatal(err)
		}
		if owners != 1 {
			t.Fatalf("%d owners left, want 1", owners)
		}
	}
}

func TestEndSessions(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	by, adminID := adminActor(t, f)
	l := f.user(t, testEmail)
	f.logIn(t, testEmail)
	other := f.user(t, "grace@example.com")

	if err := f.auth.EndSessions(ctx, l.User.ID, by); err != nil {
		t.Fatalf("EndSessions() error = %v", err)
	}
	if n := f.sessionCount(t, l.User.ID); n != 0 {
		t.Errorf("%d sessions left, want 0", n)
	}
	if n := f.sessionCount(t, other.User.ID); n != 1 {
		t.Errorf("another user has %d sessions, want 1", n)
	}
	events := f.eventsOf(t, l.User.ID)
	last := events[len(events)-1]
	if last.Type != EventLogoutEverywhere || last.ActorID == nil || *last.ActorID != adminID {
		t.Errorf("last event %+v, want logout_everywhere by the admin", last)
	}
	if err := f.auth.EndSessions(ctx, uuid.Must(uuid.NewV7()), by); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("no such user: error = %v, want ErrUserNotFound", err)
	}
}

func TestEndSessionsEndsTwoFactorLogins(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	l := f.user(t, testEmail)
	f.enableTwoFactor(t, l.Token)
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"))
	if res.status != http.StatusOK || !strings.Contains(string(res.body), "challenge_token") {
		t.Fatalf("login: status %d, want a 2FA challenge", res.status)
	}
	if err := f.auth.EndSessions(ctx, l.User.ID, Actor{}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.two_factor_challenges WHERE user_id = $1`, l.User.ID).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d 2FA challenges left (%v), want 0", n, err)
	}
}

func TestSetMemberRole(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	by, adminID := adminActor(t, f)
	owner := f.user(t, "owner@example.com")
	org := f.createOrg(t, owner.Token, "Acme").ID
	l := f.user(t, testEmail)

	if err := f.auth.SetMemberRole(ctx, org, l.User.ID, "member", by); err != nil {
		t.Fatalf("adding: %v", err)
	}
	if role := f.roleOf(t, org, l.User.ID); role != "member" {
		t.Errorf("role %q after adding, want member", role)
	}
	if err := f.auth.SetMemberRole(ctx, org, l.User.ID, "member", by); err != nil {
		t.Fatalf("same role: %v", err)
	}
	if err := f.auth.SetMemberRole(ctx, org, l.User.ID, OwnerRole, by); err != nil {
		t.Fatalf("promoting: %v", err)
	}
	if err := f.auth.SetMemberRole(ctx, org, owner.User.ID, "viewer", by); err != nil {
		t.Fatalf("demoting an owner who isn't the last: %v", err)
	}
	if err := f.auth.RemoveMember(ctx, org, owner.User.ID, by); err != nil {
		t.Fatalf("removing: %v", err)
	}
	if err := f.auth.RemoveMember(ctx, org, owner.User.ID, by); err != nil {
		t.Fatalf("removing someone who isn't a member: %v", err)
	}
	if role := f.roleOf(t, org, owner.User.ID); role != "" {
		t.Errorf("removed member has role %q", role)
	}

	var got []string
	for _, id := range []uuid.UUID{l.User.ID, owner.User.ID} {
		for _, e := range f.eventsOf(t, id) {
			if e.ActorID != nil && *e.ActorID == adminID {
				got = append(got, strings.ReplaceAll(summary(e), org.String(), "ORG"))
			}
		}
	}
	want := []string{
		"member_added organization_id=ORG role=member",
		"org_role_changed organization_id=ORG role=owner",
		"org_role_changed organization_id=ORG role=viewer",
		"member_removed organization_id=ORG",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("events by the admin (-want +got):\n%s", diff)
	}
}

func TestSetMemberRoleRejects(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	owner := f.user(t, "owner@example.com")
	org := f.createOrg(t, owner.Token, "Acme").ID
	l := f.user(t, testEmail)
	noOrg, noUser := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())

	tests := []struct {
		name      string
		org, user uuid.UUID
		role      string
		want      error
	}{
		{"unknown role", org, l.User.ID, "superuser", ErrUnknownRole},
		{"empty role", org, l.User.ID, "", ErrUnknownRole},
		{"no such organization", noOrg, l.User.ID, "member", ErrOrganizationNotFound},
		{"no such user", org, noUser, "member", ErrUserNotFound},
		{"last owner", org, owner.User.ID, "admin", ErrLastOwner},
	}
	for _, tt := range tests {
		if err := f.auth.SetMemberRole(ctx, tt.org, tt.user, tt.role, Actor{}); !errors.Is(err, tt.want) {
			t.Errorf("%s: error = %v, want %v", tt.name, err, tt.want)
		}
	}
	if err := f.auth.RemoveMember(ctx, org, owner.User.ID, Actor{}); !errors.Is(err, ErrLastOwner) {
		t.Errorf("removing the last owner: error = %v, want ErrLastOwner", err)
	}
	if err := f.auth.RemoveMember(ctx, noOrg, owner.User.ID, Actor{}); !errors.Is(err, ErrOrganizationNotFound) {
		t.Errorf("removing from no organization: error = %v, want ErrOrganizationNotFound", err)
	}
	if role := f.roleOf(t, org, owner.User.ID); role != OwnerRole {
		t.Errorf("owner's role is %q, want owner", role)
	}
	if role := f.roleOf(t, org, l.User.ID); role != "" {
		t.Errorf("user got role %q from refused changes", role)
	}

	// Without organizations there's nothing to manage.
	plain := setupWith(t, Config{})
	if err := plain.auth.SetMemberRole(ctx, org, l.User.ID, "member", Actor{}); err == nil {
		t.Error("SetMemberRole without OrgRoles: no error")
	}
	if err := plain.auth.RemoveMember(ctx, org, l.User.ID, Actor{}); err == nil {
		t.Error("RemoveMember without OrgRoles: no error")
	}
}

func TestOwnersDemotedFromCodeConcurrently(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	a := f.user(t, "a@example.com")
	b := f.user(t, "b@example.com")
	org := f.createOrg(t, a.Token, "Acme").ID
	f.addMember(t, org, b.User.ID, OwnerRole)

	errs := make(chan error, 2)
	go func() { errs <- f.auth.SetMemberRole(ctx, org, a.User.ID, "viewer", Actor{}) }()
	go func() { errs <- f.auth.RemoveMember(ctx, org, b.User.ID, Actor{}) }()
	e1, e2 := <-errs, <-errs
	if (e1 == nil) == (e2 == nil) || !errors.Is(errors.Join(e1, e2), ErrLastOwner) {
		t.Errorf("errors %v and %v, want exactly one ErrLastOwner", e1, e2)
	}
}
