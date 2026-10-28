package rbac

import "testing"

var roles = Roles{
	"owner":  {All},
	"admin":  {"invoices:read", "invoices:create", "members:manage"},
	"viewer": {"invoices:read"},
	"empty":  {},
}

func TestValidate(t *testing.T) {
	t.Parallel()
	if err := roles.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	bad := map[string]Roles{
		"uppercase role":         {"Admin": {"invoices:read"}},
		"role with space":        {"super admin": {"invoices:read"}},
		"role starting with _":   {"_admin": {"invoices:read"}},
		"empty role name":        {"": {"invoices:read"}},
		"no colon":               {"admin": {"invoices"}},
		"two colons":             {"admin": {"invoices:read:all"}},
		"uppercase permission":   {"admin": {"Invoices:read"}},
		"empty action":           {"admin": {"invoices:"}},
		"empty resource":         {"admin": {":read"}},
		"hyphen":                 {"admin": {"line-items:read"}},
		"wildcard action":        {"admin": {"invoices:*"}},
		"whitespace":             {"admin": {"invoices:read "}},
		"bad permission in many": {"admin": {"invoices:read", "Bad"}},
	}
	for name, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want an error", name)
		}
	}
	if err := (Roles{"admin": {"line_items:read", "v2_reports:export2"}}).Validate(); err != nil {
		t.Errorf("underscores and digits: Validate() = %v", err)
	}
}

func TestHas(t *testing.T) {
	t.Parallel()
	tests := []struct {
		role string
		perm Permission
		want bool
	}{
		{"owner", "invoices:read", true},
		{"owner", "anything:else", true},
		{"admin", "invoices:create", true},
		{"admin", "invoices:delete", false},
		{"viewer", "invoices:read", true},
		{"viewer", "invoices:create", false},
		{"empty", "invoices:read", false},
		{"unknown", "invoices:read", false},
		{"", "invoices:read", false},
	}
	for _, tt := range tests {
		if got := roles.Has(tt.role, tt.perm); got != tt.want {
			t.Errorf("Has(%q, %q) = %v, want %v", tt.role, tt.perm, got, tt.want)
		}
	}
}

func TestDefinesAndMentions(t *testing.T) {
	t.Parallel()
	if !roles.Defines("empty") || roles.Defines("unknown") {
		t.Error("Defines() wrong")
	}
	if !roles.Mentions("members:manage") || roles.Mentions("invoices:delete") {
		t.Error("Mentions() wrong")
	}
	// All doesn't make every misspelling count as mentioned.
	if (Roles{"owner": {All}}).Mentions("invocies:read") {
		t.Error("Mentions() counted All")
	}
	var none Roles
	if none.Has("owner", "x:y") || none.Defines("owner") || none.Mentions("x:y") {
		t.Error("nil Roles grants something")
	}
}
