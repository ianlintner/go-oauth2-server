package sqlite_test

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/dpop"
	"github.com/ianlintner/go-oauth2-server/internal/storage/sqlite"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestReplayStoreRejectsReplayAndReusesExpired(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	st, err := sqlite.Open(sqlite.MemoryDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rs := st.ReplayStore(clk, 10)

	exp := clk.Now().Add(90 * time.Second)
	if fresh, err := rs.Add("k", exp); err != nil || !fresh {
		t.Fatalf("first Add = %v, %v; want fresh", fresh, err)
	}
	if fresh, err := rs.Add("k", exp); err != nil || fresh {
		t.Fatalf("second Add = %v, %v; want replay", fresh, err)
	}
	clk.advance(91 * time.Second)
	if fresh, err := rs.Add("k", clk.Now().Add(90*time.Second)); err != nil || !fresh {
		t.Fatalf("Add after expiry = %v, %v; want fresh", fresh, err)
	}
}

func TestReplayStoreSurvivesRestartAndIsSharedByProcesses(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	path := filepath.Join(t.TempDir(), "oauth.db")
	exp := clk.Now().Add(90 * time.Second)

	a, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := a.ReplayStore(clk, 10).Add("k", exp); err != nil || !fresh {
		t.Fatalf("Add on first instance = %v, %v", fresh, err)
	}
	// A second live instance on the same database sees it (shared).
	b, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := b.ReplayStore(clk, 10).Add("k", exp); err != nil || fresh {
		t.Fatalf("replay against second instance = %v, %v; want rejected", fresh, err)
	}
	_ = a.Close()
	_ = b.Close()

	// A restart (fresh open) still rejects it.
	c, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if fresh, err := c.ReplayStore(clk, 10).Add("k", exp); err != nil || fresh {
		t.Fatalf("replay after restart = %v, %v; want rejected", fresh, err)
	}
}

func TestReplayStoreFailsClosedWhenFullAndRecoversAfterExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	st, err := sqlite.Open(sqlite.MemoryDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rs := st.ReplayStore(clk, 2)
	exp := clk.Now().Add(90 * time.Second)
	for _, k := range []string{"a", "b"} {
		if fresh, err := rs.Add(k, exp); err != nil || !fresh {
			t.Fatalf("Add %s = %v, %v", k, fresh, err)
		}
	}
	if _, err := rs.Add("c", exp); !errors.Is(err, dpop.ErrReplayStoreFull) {
		t.Fatalf("Add when full err = %v; want ErrReplayStoreFull", err)
	}
	// A live entry must not have been evicted by the failed Add.
	if fresh, _ := rs.Add("a", exp); fresh {
		t.Fatal("replay of a after flood was accepted")
	}
	clk.advance(2 * time.Minute)
	if fresh, err := rs.Add("c", clk.Now().Add(90*time.Second)); err != nil || !fresh {
		t.Fatalf("Add after expiry = %v, %v; want fresh", fresh, err)
	}
}
