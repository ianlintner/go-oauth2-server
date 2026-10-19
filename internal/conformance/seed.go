// Package conformance implements the shared contract's test-mode SUT seed
// (contract/sut-interface.md): loading and strictly validating the seed file,
// and applying it to a store before the server reports ready.
//
// It is only reachable when OAUTH2_CONFORMANCE_MODE=1 (see internal/config);
// nothing here is wired into a normal start.
package conformance

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
	"gopkg.in/yaml.v3"
)

// Seed mirrors schemas/seed.schema.json of the pinned contract.
type Seed struct {
	Issuer      string       `yaml:"issuer"`
	SigningKeys []SigningKey `yaml:"signingKeys"`
	Clients     []Client     `yaml:"clients"`
	Users       []User       `yaml:"users"`
}

// SigningKey names a key the SUT must provision. The seed carries no key
// material.
type SigningKey struct {
	KID string `yaml:"kid"`
	Alg string `yaml:"alg"`
	Use string `yaml:"use"`
}

// Client is a seeded client.
type Client struct {
	ClientID                string   `yaml:"client_id"`
	Name                    *string  `yaml:"name"`
	ClientSecret            string   `yaml:"client_secret"`
	TokenEndpointAuthMethod string   `yaml:"token_endpoint_auth_method"`
	Public                  bool     `yaml:"public"`
	RedirectURIs            []string `yaml:"redirect_uris"`
	Scopes                  []string `yaml:"scopes"`
	GrantTypes              []string `yaml:"grant_types"`
}

// User is a seeded resource owner.
type User struct {
	Username           string   `yaml:"username"`
	Password           string   `yaml:"password"`
	Email              *string  `yaml:"email"`
	Scopes             []string `yaml:"scopes"`
	AutoApproveClients []string `yaml:"auto_approve_clients"`
}

var algPattern = regexp.MustCompile(`^(RS|ES|PS|HS)[0-9]{3}$`)

// defaultClientScope is applied to a client that seeds no scopes so the
// token-lifecycle scenarios requesting `openid`/`read` resolve. It mirrors the
// Rust reference's DEFAULT_CLIENT_SCOPE; a client that seeds its own scopes
// keeps them verbatim.
var defaultClientScope = []string{"openid", "read"}

var validGrantTypes = map[string]bool{
	"authorization_code": true,
	"refresh_token":      true,
	"client_credentials": true,
	"urn:ietf:params:oauth:grant-type:device_code": true,
}

// LoadSeed reads and validates the seed file at path (YAML or JSON). It
// rejects unknown fields and every violation of the contract schema, and also
// refuses inputs the schema permits but that cannot be applied unambiguously
// (duplicate identities, dangling auto-approve references, a confidential
// client with no credential). It never returns a partial seed.
func LoadSeed(path string) (*Seed, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("conformance seed: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var seed Seed
	if err := dec.Decode(&seed); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("conformance seed: file is empty")
		}
		return nil, fmt.Errorf("conformance seed: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("conformance seed: must contain exactly one document")
	}

	if err := seed.validate(); err != nil {
		return nil, fmt.Errorf("conformance seed: %w", err)
	}
	return &seed, nil
}

func (s *Seed) validate() error {
	u, err := url.Parse(s.Issuer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("issuer %q must be an absolute http(s) URL", s.Issuer)
	}
	if len(s.Clients) == 0 {
		return errors.New("clients must contain at least one client")
	}
	if len(s.Users) == 0 {
		return errors.New("users must contain at least one user")
	}

	for i, k := range s.SigningKeys {
		if k.KID == "" {
			return fmt.Errorf("signingKeys[%d].kid is required", i)
		}
		if !algPattern.MatchString(k.Alg) {
			return fmt.Errorf("signingKeys[%d].alg %q is not a JWS algorithm of the form RS256", i, k.Alg)
		}
		if k.Use != "" && k.Use != "sig" {
			return fmt.Errorf("signingKeys[%d].use must be sig", i)
		}
	}

	clientIDs := make(map[string]bool, len(s.Clients))
	for i, c := range s.Clients {
		if err := c.validate(); err != nil {
			return fmt.Errorf("clients[%d]: %w", i, err)
		}
		if clientIDs[c.ClientID] {
			return fmt.Errorf("clients[%d]: duplicate client_id %q", i, c.ClientID)
		}
		clientIDs[c.ClientID] = true
	}

	usernames := make(map[string]bool, len(s.Users))
	for i, usr := range s.Users {
		if usr.Username == "" {
			return fmt.Errorf("users[%d].username is required", i)
		}
		if usr.Password == "" {
			return fmt.Errorf("users[%d].password is required", i)
		}
		if usr.Email != nil && len(*usr.Email) < 3 {
			return fmt.Errorf("users[%d].email is too short", i)
		}
		if usernames[usr.Username] {
			return fmt.Errorf("users[%d]: duplicate username %q", i, usr.Username)
		}
		usernames[usr.Username] = true
		for _, id := range usr.AutoApproveClients {
			if !clientIDs[id] {
				return fmt.Errorf("users[%d].auto_approve_clients names unknown client %q", i, id)
			}
		}
	}
	return nil
}

func (c Client) validate() error {
	if c.ClientID == "" {
		return errors.New("client_id is required")
	}
	if c.Name != nil && *c.Name == "" {
		return errors.New("name must not be empty")
	}
	if len(c.RedirectURIs) == 0 {
		return errors.New("redirect_uris must contain at least one URI")
	}
	for _, r := range c.RedirectURIs {
		if r == "" {
			return errors.New("redirect_uris must not contain an empty URI")
		}
	}
	for _, sc := range c.Scopes {
		if sc == "" {
			return errors.New("scopes must not contain an empty scope")
		}
	}
	for _, g := range c.GrantTypes {
		if !validGrantTypes[g] {
			return fmt.Errorf("unsupported grant type %q", g)
		}
	}

	switch c.TokenEndpointAuthMethod {
	case "", "none", "client_secret_basic", "client_secret_post":
	default:
		return fmt.Errorf("token_endpoint_auth_method %q is not none, client_secret_basic or client_secret_post", c.TokenEndpointAuthMethod)
	}

	if c.Public {
		if c.ClientSecret != "" {
			return errors.New("a public client must not have a client_secret")
		}
		if c.TokenEndpointAuthMethod != "" && c.TokenEndpointAuthMethod != "none" {
			return errors.New("a public client must use token_endpoint_auth_method none")
		}
		return nil
	}

	// Beyond the schema: a confidential client has exactly one credential and a
	// matching method, so a seed can never create an unauthenticated
	// "confidential" client or a secret nothing will check.
	method := c.TokenEndpointAuthMethod
	switch {
	case method == "client_secret_basic" || method == "client_secret_post":
		if c.ClientSecret == "" {
			return fmt.Errorf("token_endpoint_auth_method %s requires client_secret", method)
		}
	case c.ClientSecret != "":
		return errors.New("client_secret requires token_endpoint_auth_method client_secret_basic or client_secret_post")
	default:
		return errors.New("a client with no client_secret must set public: true")
	}
	return nil
}

// Apply writes the seed to st in one transaction, hashing every secret and
// password, so a failure leaves nothing behind. Registered redirect URIs are
// stored verbatim. Signing keys are not applied here: the seed carries no key
// material and key provisioning belongs to the Signer.
func Apply(ctx context.Context, st oauth.Store, rnd oauth.Random, seed *Seed) error {
	return st.WithTx(ctx, func(ctx context.Context, tx oauth.Repositories) error {
		for _, c := range seed.Clients {
			scopes := c.Scopes
			if len(scopes) == 0 {
				scopes = defaultClientScope
			}
			rec := oauth.Client{
				ID:           c.ClientID,
				Public:       c.Public,
				AuthMethod:   c.TokenEndpointAuthMethod,
				RedirectURIs: c.RedirectURIs,
				Scopes:       scopes,
				GrantTypes:   c.GrantTypes,
			}
			if c.Name != nil {
				rec.Name = *c.Name
			}
			if rec.AuthMethod == "" {
				rec.AuthMethod = "none"
			}
			if c.ClientSecret != "" {
				h, err := secret.Hash(rnd, c.ClientSecret)
				if err != nil {
					return fmt.Errorf("hash secret of client %q: %w", c.ClientID, err)
				}
				rec.SecretHash = h
			}
			if err := tx.Clients().Create(ctx, rec); err != nil {
				return fmt.Errorf("seed client %q: %w", c.ClientID, err)
			}
		}
		for _, u := range seed.Users {
			idBytes, err := rnd.Bytes(16)
			if err != nil {
				return fmt.Errorf("generate id of user %q: %w", u.Username, err)
			}
			h, err := secret.Hash(rnd, u.Password)
			if err != nil {
				return fmt.Errorf("hash password of user %q: %w", u.Username, err)
			}
			rec := oauth.User{
				ID:           "user-" + hex.EncodeToString(idBytes),
				Username:     u.Username,
				PasswordHash: h,
				Scopes:       u.Scopes,
			}
			if u.Email != nil {
				rec.Email = *u.Email
			}
			if err := tx.Users().Create(ctx, rec); err != nil {
				return fmt.Errorf("seed user %q: %w", u.Username, err)
			}
		}
		return nil
	})
}
