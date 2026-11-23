package deviceprovisioning

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
)

type DeviceSummary struct {
	Device             string                  `json:"device"`
	PolicyRevision     int64                   `json:"policyRevision"`
	DesiredRevision    int64                   `json:"desiredRevision"`
	ReportValidUntilMs int64                   `json:"reportValidUntilMs,omitempty"`
	Report             ConfigurationActivation `json:"report"`
}

type DeviceInventory struct {
	Devices      []DeviceSummary `json:"devices"`
	Next         string          `json:"next"`
	ReportExpiry bool            `json:"reportExpiry,omitempty"`
	ObservedAtMs int64           `json:"observedAtMs"`
}

func (DeviceSummary) String() string     { return "DeviceSummary([redacted])" }
func (DeviceSummary) GoString() string   { return "DeviceSummary([redacted])" }
func (DeviceInventory) String() string   { return "DeviceInventory([redacted])" }
func (DeviceInventory) GoString() string { return "DeviceInventory([redacted])" }

// Discovery uses precisely the authority required to open an individual card.
// It exposes no account identifiers, configuration bodies or key material, and
// does not infer current connectivity from a historical activation receipt.
func (c *ConfigurationControl) deviceInventory(ctx context.Context, actor, after, prefix, request string, includeExpiry bool, until int64, now time.Time) (DeviceInventory, error) {
	result := DeviceInventory{Devices: []DeviceSummary{}, ObservedAtMs: now.UnixMilli(), ReportExpiry: includeExpiry}
	if ctx == nil || c == nil || c.Store == nil || c.Store.DB == nil {
		return result, enrollment.ErrUnavailable
	}
	if !configurationObjectID.MatchString(actor) || after != "" && !configurationObjectID.MatchString(after) || prefix != "" && !configurationObjectID.MatchString(prefix) || !configurationRequestID.MatchString(request) || now.Unix() >= until {
		return result, enrollment.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	tx, e := c.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	// Lock the selected live grant, device and account until response commit.
	// A revoked/expired ACL cannot reveal even the existence of another device.
	args := []any{actor, after, current().Unix()}
	var prefixClause string
	if prefix != "" {
		// Device IDs use a bounded ASCII alphabet. Its DEL upper bound includes
		// exact matches and treats hyphens and underscores as literal bytes.
		folded := strings.ToLower(prefix)
		prefixClause = ` AND lower(d.id COLLATE "C") >= $4 AND lower(d.id COLLATE "C") < $5`
		args = append(args, folded, folded+"\x7f")
	}
	rows, e := tx.QueryContext(ctx, `SELECT d.id,d.revision,COALESCE(h.revision,0),
	  COALESCE(p.policy_revision,0),COALESCE(p.outcome,''),COALESCE(p.active_policy_revision,0),COALESCE(p.received_at_ms,0),
	  d.offline_until,d.publication_grant_hash=a.grant_hash,a.valid_until,g.expires
	  FROM identity_devices d JOIN identity_accounts a ON a.owner=d.owner
	  JOIN LATERAL (SELECT expires FROM catalog_acl WHERE actor=$1
	    AND action IN ('configuration.drafts.read','*') AND target_kind IN ('device','*')
	    AND target_id IN (d.id,'*') AND expires>$3 ORDER BY expires DESC LIMIT 1 FOR SHARE) g ON true
	  LEFT JOIN managed_configuration_heads h ON h.device=d.id
	  LEFT JOIN identity_policy_activation p ON p.device=d.id
	  WHERE d.active AND d.approved AND a.enabled AND a.valid_until>$3
	    AND d.id COLLATE "C">$2 COLLATE "C"`+prefixClause+`
	  ORDER BY d.id COLLATE "C" LIMIT 33 FOR SHARE OF d,a`, args...)
	if e != nil {
		return result, enrollment.ErrUnavailable
	}
	defer rows.Close()
	earliest := int64(math.MaxInt64)
	var reportDeadlines []int64
	for rows.Next() {
		var row DeviceSummary
		var offline, accountUntil, grantUntil int64
		var matchingGrant bool
		if e = rows.Scan(&row.Device, &row.PolicyRevision, &row.DesiredRevision,
			&row.Report.PolicyRevision, &row.Report.Outcome, &row.Report.ActivePolicyRevision, &row.Report.ReceivedAtMs,
			&offline, &matchingGrant, &accountUntil, &grantUntil); e != nil {
			return result, enrollment.ErrUnavailable
		}
		if !configurationObjectID.MatchString(row.Device) || row.PolicyRevision < 0 || row.PolicyRevision > 9007199254740991 || row.DesiredRevision < 0 || row.DesiredRevision > 9007199254740991 || row.Report.PolicyRevision < 0 || row.Report.PolicyRevision > 9007199254740991 || row.Report.ActivePolicyRevision < 0 || row.Report.ActivePolicyRevision > 9007199254740991 || row.Report.ReceivedAtMs < 0 || row.Report.ReceivedAtMs > 9007199254740991 {
			return result, enrollment.ErrUnavailable
		}
		earliest = min(earliest, accountUntil, grantUntil)
		row.Report.State = "awaiting_report"
		if row.Report.ReceivedAtMs > 0 {
			row.Report.State = "historical"
			if row.Report.PolicyRevision == row.PolicyRevision && matchingGrant && offline > current().Unix() {
				row.Report.State = "reported"
			}
		} else if row.PolicyRevision == 0 {
			row.Report.State = "not_issued"
		}
		result.Devices = append(result.Devices, row)
		reportDeadlines = append(reportDeadlines, offline)
	}
	if e = rows.Err(); e != nil {
		return result, enrollment.ErrUnavailable
	}
	rows.Close()
	if current().Unix() >= min(until, earliest) {
		return result, enrollment.ErrDenied
	}
	if len(result.Devices) > 32 {
		result.Devices = result.Devices[:32]
		result.Next = result.Devices[31].Device
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO catalog_audit(actor,action,target,request_id,observed_at,before_hash,after_hash,outcome)
	  VALUES($1,'configuration.devices.list','devices',$2,$3,'','','read')`, actor, request, current().Unix()); e != nil {
		return result, enrollment.ErrUnavailable
	}
	if current().Unix() >= min(until, earliest) {
		return result, enrollment.ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return result, enrollment.ErrUnavailable
	}
	observed := current().Unix()
	if observed >= min(until, earliest) {
		return DeviceInventory{}, enrollment.ErrDenied
	}
	for i := range result.Devices {
		row := &result.Devices[i]
		if row.Report.State != "reported" {
			continue
		}
		deadline := reportDeadlines[i]
		if deadline <= observed {
			row.Report.State = "historical"
		} else if includeExpiry {
			if deadline > 9007199254740991/1000 {
				return DeviceInventory{}, enrollment.ErrUnavailable
			}
			row.ReportValidUntilMs = deadline * 1000
		}
	}
	return result, nil
}
