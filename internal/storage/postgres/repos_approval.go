package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// --- resource-owner approvals ---

type approvalRepo struct{ db execer }

func (r *approvalRepo) Get(ctx context.Context, userID, clientID string) (oauth.Approval, error) {
	var (
		scopes  string
		granted int64
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT scopes, granted_at FROM approvals WHERE user_id = ? AND client_id = ?`, userID, clientID).
		Scan(&scopes, &granted)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.Approval{}, oauth.ErrNotFound
	}
	if err != nil {
		return oauth.Approval{}, err
	}
	list, err := decodeList(scopes)
	if err != nil {
		return oauth.Approval{}, err
	}
	return oauth.Approval{UserID: userID, ClientID: clientID, Scopes: list, GrantedAt: fromNanos(granted)}, nil
}

func (r *approvalRepo) Put(ctx context.Context, a oauth.Approval) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO approvals (user_id, client_id, scopes, granted_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = excluded.scopes, granted_at = excluded.granted_at`,
		a.UserID, a.ClientID, encodeList(a.Scopes), nanos(a.GrantedAt))
	return err
}
