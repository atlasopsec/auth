// Package rbac defines roles and permissions for the auth module.
//
// A permission is a specific action named "resource:action", such as
// "invoices:create". A role is a named set of permissions. Roles live in Go
// code, not the database, so every change to who can do what goes through
// code review. Code checks permissions, never role names, so roles can
// change without hunting through handlers.
package rbac

import (
	"fmt"
	"regexp"
	"slices"
)

// Permission is an action, named "resource:action": lowercase letters,
// digits, and underscores on each side of the colon.
type Permission string

// All grants every permission. Give it only to roles such as an
// organization's owner.
const All Permission = "*"

// Roles maps role names to the permissions they grant. Role names are
// lowercase letters, digits, and underscores, starting with a letter.
type Roles map[string][]Permission

var (
	permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$`)
	rolePattern       = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// Validate checks every role name and permission is well formed, so a typo
// fails at startup instead of silently denying access.
func (r Roles) Validate() error {
	for role, perms := range r {
		if !rolePattern.MatchString(role) {
			return fmt.Errorf("rbac: invalid role name %q (use lowercase letters, digits, and _)", role)
		}
		for _, p := range perms {
			if p != All && !permissionPattern.MatchString(string(p)) {
				return fmt.Errorf("rbac: role %q: invalid permission %q (use resource:action, e.g. invoices:create)", role, p)
			}
		}
	}
	return nil
}

// Has reports whether role grants p. An unknown role grants nothing.
func (r Roles) Has(role string, p Permission) bool {
	perms, ok := r[role]
	return ok && (slices.Contains(perms, All) || slices.Contains(perms, p))
}

// Defines reports whether role exists.
func (r Roles) Defines(role string) bool {
	_, ok := r[role]
	return ok
}

// Mentions reports whether any role lists p by name. All doesn't count:
// it's used to catch permissions that are misspelled where they're
// required, which a role with All would otherwise hide.
func (r Roles) Mentions(p Permission) bool {
	for _, perms := range r {
		if slices.Contains(perms, p) {
			return true
		}
	}
	return false
}
