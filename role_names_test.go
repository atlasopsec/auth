package auth

import (
	"encoding/json"
	"net/http"
	"testing"
)

// roleNames reads every role_name in a response: from a single object, or
// from each item of a list.
func roleNames(t *testing.T, res response) map[string]string {
	t.Helper()
	if res.status != http.StatusOK {
		t.Fatalf("status %d, body %s", res.status, res.body)
	}
	type item struct {
		ID       string `json:"id"`
		UserID   string `json:"user_id"`
		Role     string `json:"role"`
		RoleName string `json:"role_name"`
	}
	var list struct {
		Data []item `json:"data"`
	}
	var one item
	out := map[string]string{}
	if json.Unmarshal(res.body, &list) == nil && list.Data != nil {
		for _, it := range list.Data {
			out[it.ID+it.UserID] = it.Role + " " + it.RoleName
		}
		return out
	}
	if err := json.Unmarshal(res.body, &one); err != nil {
		t.Fatal(err)
	}
	out[one.ID+one.UserID] = one.Role + " " + one.RoleName
	return out
}

func TestRoleNames(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	owner, viewer := tm.users[OwnerRole], tm.users["viewer"]
	clerk := f.createRole(t, tm, OwnerRole, roleBody("Billing clerk", "invoices:read"))
	if res := f.setRole(t, tm, OwnerRole, viewer.User.ID, clerk.Key); res.status != http.StatusOK {
		t.Fatal(res.status)
	}
	org, vid, oid := tm.org.String(), viewer.User.ID.String(), owner.User.ID.String()
	want := func(what string, got map[string]string, id, role, name string) {
		t.Helper()
		if got[id] != role+" "+name {
			t.Errorf("%s: role and name %q, want %q", what, got[id], role+" "+name)
		}
	}

	// A role defined in code is shown as itself; a custom one by its name.
	members := roleNames(t, f.do(t, http.MethodGet, tm.path("/members"), "", withToken(owner.Token)))
	want("members list, owner", members, oid, OwnerRole, OwnerRole)
	want("members list, custom", members, vid, clerk.Key, "Billing clerk")
	want("changing a role", roleNames(t, f.setRole(t, tm, OwnerRole, viewer.User.ID, clerk.Key)), vid, clerk.Key, "Billing clerk")
	want("my organizations", roleNames(t, f.do(t, http.MethodGet, "/v1/organizations", "", withToken(viewer.Token))), org, clerk.Key, "Billing clerk")
	want("one organization", roleNames(t, f.do(t, http.MethodGet, tm.path(""), "", withToken(viewer.Token))), org, clerk.Key, "Billing clerk")
	want("renaming the organization", roleNames(t, f.do(t, http.MethodPatch, tm.path(""), `{"name":"Acme Ltd"}`, withToken(owner.Token))), org, OwnerRole, OwnerRole)

	// Renaming the role renames it everywhere, on the next request.
	if res := f.do(t, http.MethodPatch, tm.path("/roles/"+clerk.ID.String()), `{"name":"Accounts"}`, withToken(owner.Token)); res.status != http.StatusOK {
		t.Fatal(res.status)
	}
	want("after renaming the role", roleNames(t, f.do(t, http.MethodGet, tm.path("/members"), "", withToken(owner.Token))), vid, clerk.Key, "Accounts")
}
