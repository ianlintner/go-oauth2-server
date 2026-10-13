package sqlite_test

import (
	"path/filepath"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/storage/sqlite"
	"github.com/ianlintner/go-oauth2-server/internal/storage/storagetest"
)

func TestSQLiteStoreContract(t *testing.T) {
	storagetest.Run(t, storagetest.Factory{
		New: func(t *testing.T) oauth.Store {
			t.Helper()
			s, err := sqlite.Open(sqlite.MemoryDSN)
			if err != nil {
				t.Fatalf("open memory store: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		},
		NewPersistent: func(t *testing.T) func(t *testing.T) oauth.Store {
			t.Helper()
			path := filepath.Join(t.TempDir(), "oauth.db")
			return func(t *testing.T) oauth.Store {
				t.Helper()
				s, err := sqlite.Open(path)
				if err != nil {
					t.Fatalf("open file store: %v", err)
				}
				t.Cleanup(func() { _ = s.Close() })
				return s
			}
		},
	})
}
