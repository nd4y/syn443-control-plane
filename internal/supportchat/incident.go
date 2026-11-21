package supportchat

import (
	"context"
	"database/sql"
	"regexp"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

var incidentReference = regexp.MustCompile(`^SYN-[0-9a-f]{12}$`)

type incidentMatch struct {
	Text      string `json:"text"`
	CreatedAt int64  `json:"createdAt"`
}

type incidentResult struct {
	Reference string         `json:"reference"`
	State     string         `json:"state"`
	Report    *incidentMatch `json:"report,omitempty"`
}

// Dispatch has already locked the current chat grant in this transaction.
// A reference collision is never resolved by selecting an arbitrary owner.
func lookupIncident(ctx context.Context, tx *sql.Tx, admin bool, raw []byte) (any, error) {
	if !admin {
		return nil, ErrDenied
	}
	var query struct {
		Reference string `json:"reference"`
	}
	if identity.Decode(raw, &query, true) != nil || !incidentReference.MatchString(query.Reference) {
		return nil, ErrInvalid
	}
	rows, err := tx.QueryContext(ctx, `SELECT m.text,m.created_at FROM chat_messages m
        JOIN chat_conversations c ON c.id=m.conversation AND c.owner=m.sender
        WHERE left(m.client_id,12)=$1 AND split_part(m.text,chr(10),1)='Обращение SYN-' || left(m.client_id,12)
        LIMIT 2`, query.Reference[4:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := incidentResult{Reference: query.Reference, State: "missing"}
	for rows.Next() {
		var match incidentMatch
		if err = rows.Scan(&match.Text, &match.CreatedAt); err != nil {
			return nil, err
		}
		if result.Report != nil {
			result.State = "ambiguous"
			result.Report = nil
			break
		}
		result.State = "found"
		result.Report = &match
	}
	return result, rows.Err()
}
