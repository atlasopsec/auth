package auth

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
)

// newDeviceMemory is how long a login's browser or app and network are
// remembered, so logging in from them again sends no email.
const newDeviceMemory = 90 * 24 * time.Hour

// noticeNewDevice emails the user if no login to their account in the last
// 90 days came from this user agent and network (IPv4 /24 or IPv6 /48).
// It runs before the login itself is recorded, and never for a user's
// first login. It reads the event log, so like it, it's best effort.
func (a *Auth) noticeNewDevice(ctx context.Context, userID uuid.UUID, ip *netip.Addr, ua string) {
	if ip == nil {
		// Only when the server can't parse the connection's address, which
		// net/http always sets.
		return
	}
	bits := int32(48)
	if ip.Is4() {
		bits = 24
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	h, err := a.q.GetLoginHistory(ctx, db.GetLoginHistoryParams{
		UserID: &userID, Since: now.Add(-newDeviceMemory), UserAgent: storedUserAgent(ua), Ip: *ip, Bits: bits,
	})
	if err != nil {
		a.log.ErrorContext(ctx, "auth: checking for a new device",
			slog.String("request_id", httpapi.RequestIDFrom(ctx)),
			slog.String("user_id", userID.String()),
			slog.String("error", err.Error()))
		return
	}
	if !h.AnyLogin || h.Seen {
		return
	}
	user, err := a.q.GetUserByID(ctx, userID)
	if err != nil {
		a.log.ErrorContext(ctx, "auth: reading user for a new-device email",
			slog.String("request_id", httpapi.RequestIDFrom(ctx)),
			slog.String("user_id", userID.String()),
			slog.String("error", err.Error()))
		return
	}
	var device string
	if s := storedUserAgent(ua); s != nil {
		device = *s
	}
	a.send(user.Email, a.emails.NewDeviceLogin, EmailData{AppName: a.appName, AppURL: a.appURL, Device: device, LoggedInAt: now}, uuid.Must(uuid.NewV7()))
}
