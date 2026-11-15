package enrollment

import (
	"context"
	"database/sql"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const controlPanelPath = "/v1/device/control-panel"

// ControlPanelHint conveys only eligibility to show a navigation link. The
// control panel still authenticates under its separate audience and ACL.
type ControlPanelHint struct {
	SchemaVersion int   `json:"schemaVersion"`
	UntilMs       int64 `json:"untilMs"`
}

func (s *Store) ControlPanelRole(ctx context.Context) error {
	var scoped bool
	err := s.DB.QueryRowContext(ctx, `SELECT has_function_privilege(current_user,'public.catalog_control_panel_expiry(text,bigint)','EXECUTE')
 AND NOT has_any_column_privilege(current_user,'public.catalog_acl','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.catalog_acl','INSERT')
 AND NOT has_any_column_privilege(current_user,'public.catalog_acl','UPDATE')
 AND NOT has_table_privilege(current_user,'public.catalog_acl','DELETE')`).Scan(&scoped)
	if err != nil || !scoped {
		return ErrDenied
	}
	return nil
}

func (s *Store) ControlPanel(ctx context.Context, binding Binding, token string, proof identity.Proof, now time.Time) (any, error) {
	return s.WithDeviceSession(ctx, binding, token, proof, now, func(ctx context.Context, tx *sql.Tx, authority DeviceAuthority) (DeviceResult, error) {
		var expiry int64
		if err := tx.QueryRowContext(ctx, `SELECT public.catalog_control_panel_expiry($1,$2)`, authority.Binding.Owner, now.Unix()).Scan(&expiry); err != nil {
			return DeviceResult{}, ErrUnavailable
		}
		deadline := min(authority.AccountUntilMs, authority.Binding.AccessUntil*1000, now.Add(2*time.Minute).UnixMilli())
		hint := ControlPanelHint{SchemaVersion: 1}
		if expiry > now.Unix() {
			deadline = min(deadline, min(expiry, now.Add(2*time.Minute).Unix())*1000)
			hint.UntilMs = deadline
		}
		return DeviceResult{Value: hint, UntilMs: deadline}, nil
	})
}
