package conformance_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/conformance"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
	"github.com/ianlintner/go-oauth2-server/internal/storage/sqlite"
)

// contractExample mirrors examples/seed.yaml of the pinned contract.
const contractExample = `
issuer: http://localhost:8080
clients:
  - client_id: client-a
    client_secret: test-only-secret
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: [https://client.example/callback]
    grant_types: [authorization_code, refresh_token]
  - client_id: spa
    public: true
    token_endpoint_auth_method: none
    redirect_uris: [http://127.0.0.1/cb]
users:
  - username: alice
    password: test-only-password
    auto_approve_clients: [client-a]
signingKeys:
  - kid: k1
    alg: RS256
`

func writeSeed(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "seed.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadParsesContractExample(t *testing.T) {
	seed, err := conformance.LoadSeed(writeSeed(t, contractExample))
	if err != nil {
		t.Fatalf("LoadSeed: %v", err)
	}
	if seed.Issuer != "http://localhost:8080" || len(seed.Clients) != 2 || len(seed.Users) != 1 || len(seed.SigningKeys) != 1 {
		t.Fatalf("seed = %+v", seed)
	}
	if seed.Users[0].AutoApproveClients[0] != "client-a" {
		t.Fatalf("auto approve = %v", seed.Users[0].AutoApproveClients)
	}
}

func TestLoadSeedAcceptsJSON(t *testing.T) {
	body := `{"issuer":"http://localhost:8080","clients":[{"client_id":"c","redirect_uris":["https://c/cb"],"client_secret":"s","token_endpoint_auth_method":"client_secret_post"}],"users":[{"username":"u","password":"p"}]}`
	if _, err := conformance.LoadSeed(writeSeed(t, body)); err != nil {
		t.Fatalf("LoadSeed(json): %v", err)
	}
}

// Every case is a seed the contract's schema rejects; loading must abort, never
// apply a partial seed or fall back to defaults.
func TestLoadSeedRejectsSchemaViolations(t *testing.T) {
	const okUsers = "users:\n  - {username: u, password: p}\n"
	const okIssuer = "issuer: http://localhost:8080\n"
	tests := map[string]string{
		"missing issuer":        "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\n" + okUsers,
		"non-http issuer":       "issuer: ftp://x\nclients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\n" + okUsers,
		"missing clients":       okIssuer + okUsers,
		"empty clients":         okIssuer + "clients: []\n" + okUsers,
		"missing users":         okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\n",
		"empty users":           okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\nusers: []\n",
		"unknown top key":       okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\n" + okUsers + "extra: 1\n",
		"unknown client key":    okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb], bogus: 1}\n" + okUsers,
		"empty client id":       okIssuer + "clients:\n  - {client_id: '', redirect_uris: [https://c/cb]}\n" + okUsers,
		"no redirect uris":      okIssuer + "clients:\n  - {client_id: c, redirect_uris: []}\n" + okUsers,
		"empty redirect uri":    okIssuer + "clients:\n  - {client_id: c, redirect_uris: ['']}\n" + okUsers,
		"public with secret":    okIssuer + "clients:\n  - {client_id: c, public: true, client_secret: s, token_endpoint_auth_method: none, redirect_uris: [https://c/cb]}\n" + okUsers,
		"public wrong method":   okIssuer + "clients:\n  - {client_id: c, public: true, token_endpoint_auth_method: client_secret_basic, redirect_uris: [https://c/cb]}\n" + okUsers,
		"basic without secret":  okIssuer + "clients:\n  - {client_id: c, token_endpoint_auth_method: client_secret_basic, redirect_uris: [https://c/cb]}\n" + okUsers,
		"post without secret":   okIssuer + "clients:\n  - {client_id: c, token_endpoint_auth_method: client_secret_post, redirect_uris: [https://c/cb]}\n" + okUsers,
		"bad auth method":       okIssuer + "clients:\n  - {client_id: c, token_endpoint_auth_method: private_key_jwt, redirect_uris: [https://c/cb]}\n" + okUsers,
		"bad grant type":        okIssuer + "clients:\n  - {client_id: c, grant_types: [implicit], redirect_uris: [https://c/cb]}\n" + okUsers,
		"user missing password": okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\nusers:\n  - {username: u}\n",
		"user empty password":   okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\nusers:\n  - {username: u, password: ''}\n",
		"bad key alg":           okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\n" + okUsers + "signingKeys:\n  - {kid: k, alg: none}\n",
		"key missing kid":       okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\n" + okUsers + "signingKeys:\n  - {alg: RS256}\n",
		"duplicate client id":   okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\n  - {client_id: c, redirect_uris: [https://c/cb]}\n" + okUsers,
		"duplicate username":    okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\nusers:\n  - {username: u, password: p}\n  - {username: u, password: q}\n",
		"unknown auto-approve":  okIssuer + "clients:\n  - {client_id: c, redirect_uris: [https://c/cb]}\nusers:\n  - {username: u, password: p, auto_approve_clients: [ghost]}\n",
		"not yaml":              "{{{",
		"empty file":            "",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := conformance.LoadSeed(writeSeed(t, body)); err == nil {
				t.Fatal("LoadSeed accepted an invalid seed")
			}
		})
	}
}

func TestLoadSeedMissingFileFails(t *testing.T) {
	if _, err := conformance.LoadSeed(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("missing seed file accepted")
	}
}

func TestApplyStoresHashedCredentialsAndVerbatimURIs(t *testing.T) {
	seed, err := conformance.LoadSeed(writeSeed(t, contractExample))
	if err != nil {
		t.Fatal(err)
	}
	st, err := sqlite.Open(sqlite.MemoryDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := conformance.Apply(context.Background(), st, oauth.CryptoRandom{}, seed); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	c, err := st.Clients().Get(context.Background(), "client-a")
	if err != nil {
		t.Fatal(err)
	}
	if c.SecretHash == "test-only-secret" || strings.Contains(c.SecretHash, "test-only-secret") {
		t.Fatal("client secret stored in plaintext")
	}
	if ok, err := secret.Verify(c.SecretHash, "test-only-secret"); err != nil || !ok {
		t.Fatalf("seeded secret does not verify: %v %v", ok, err)
	}
	if c.AuthMethod != "client_secret_basic" || len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://client.example/callback" {
		t.Fatalf("client = %+v", c)
	}

	pub, err := st.Clients().Get(context.Background(), "spa")
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Public || pub.SecretHash != "" || pub.AuthMethod != "none" {
		t.Fatalf("public client = %+v", pub)
	}

	u, err := st.Users().GetByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.PasswordHash, "test-only-password") {
		t.Fatal("user password stored in plaintext")
	}
	if ok, _ := secret.Verify(u.PasswordHash, "test-only-password"); !ok {
		t.Fatal("seeded password does not verify")
	}
}

func TestApplyIsAllOrNothing(t *testing.T) {
	// A conflict midway (client already present) must leave no seeded rows.
	seed, err := conformance.LoadSeed(writeSeed(t, contractExample))
	if err != nil {
		t.Fatal(err)
	}
	st, err := sqlite.Open(sqlite.MemoryDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Clients().Create(ctx, oauth.Client{ID: "spa", AuthMethod: "none", Public: true, RedirectURIs: []string{"https://x/cb"}}); err != nil {
		t.Fatal(err)
	}
	if err := conformance.Apply(ctx, st, oauth.CryptoRandom{}, seed); err == nil {
		t.Fatal("Apply succeeded despite a conflicting client")
	}
	if _, err := st.Clients().Get(ctx, "client-a"); err != oauth.ErrNotFound {
		t.Fatalf("client-a after failed Apply: %v, want ErrNotFound", err)
	}
	if _, err := st.Users().GetByUsername(ctx, "alice"); err != oauth.ErrNotFound {
		t.Fatalf("alice after failed Apply: %v, want ErrNotFound", err)
	}
}
