// Package identity verifies who a caller is, from a signed bearer token.
//
// It deliberately supports only what the ownership check needs: HS256 and
// RS256 compact JWTs, checked for signature, algorithm, expiry, and optionally
// issuer and audience. It has no notion of sessions or refresh; the backend
// issues tokens, and the gateway only has to refuse the ones it did not sign.
package identity

import (
	"cmp"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

// Failures are split by what they say about the caller. A missing or expired
// token is what an ordinary logged-out user sends; a token whose signature or
// algorithm is wrong was made by someone other than the issuer.
var (
	ErrMissing = errors.New("no bearer token")
	ErrExpired = errors.New("token expired or not yet valid")
	ErrForged  = errors.New("token signature, algorithm or claims are invalid")
)

// clockSkew tolerates small differences between the issuer's clock and ours.
const clockSkew = 30 * time.Second

// Caller is what a verified token says.
type Caller struct {
	ID       string
	Bypasses bool
}

type Verifier struct {
	algorithm    string
	secret       []byte
	publicKey    *rsa.PublicKey
	issuer       string
	audience     string
	userClaim    string
	bypassClaim  string
	bypassValues map[string]bool
	now          func() time.Time
}

// NewVerifier loads the key material. A secret variable that is unset falls
// back to the config's literal secret, and fails when there is none: a gateway
// that could not check signatures must not start and pass everything.
func NewVerifier(cfg config.JWTConfig, getenv func(string) string) (*Verifier, error) {
	v := &Verifier{
		algorithm:    cfg.Algorithm,
		issuer:       cfg.Issuer,
		audience:     cfg.Audience,
		userClaim:    cfg.UserClaim,
		bypassClaim:  cfg.BypassClaim,
		bypassValues: make(map[string]bool, len(cfg.BypassValues)),
		now:          time.Now,
	}
	v.userClaim = cmp.Or(v.userClaim, "sub")
	for _, value := range cfg.BypassValues {
		v.bypassValues[value] = true
	}

	switch cfg.Algorithm {
	case "HS256":
		secret := ""
		if cfg.SecretEnv != "" {
			secret = getenv(cfg.SecretEnv)
		}
		secret = cmp.Or(secret, cfg.Secret)
		if secret == "" {
			return nil, fmt.Errorf("identity.jwt: %s is not set and the config has no fallback secret", cfg.SecretEnv)
		}
		if len(secret) < 16 {
			return nil, fmt.Errorf("identity.jwt: the HS256 secret must be at least 16 characters")
		}
		v.secret = []byte(secret)
	case "RS256":
		key, err := loadRSAPublicKey(cfg.PublicKeyFile)
		if err != nil {
			return nil, err
		}
		v.publicKey = key
	default:
		return nil, fmt.Errorf("identity.jwt: unsupported algorithm %q", cfg.Algorithm)
	}
	return v, nil
}

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity.jwt: read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("identity.jwt: %s is not PEM", path)
	}
	if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if key, ok := parsed.(*rsa.PublicKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("identity.jwt: %s is not an RSA public key", path)
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity.jwt: parse public key: %w", err)
	}
	return key, nil
}

// FromRequest verifies the request's "Authorization: Bearer" token.
func (v *Verifier) FromRequest(r *http.Request) (Caller, error) {
	header := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return Caller{}, ErrMissing
	}
	return v.Verify(strings.TrimSpace(token))
}

// Verify checks a compact JWT and returns the caller it names.
func (v *Verifier) Verify(token string) (Caller, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Caller{}, ErrForged
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return Caller{}, ErrForged
	}
	// The algorithm comes from our config, never from the token: accepting the
	// token's own claim is how "alg: none" and HS256-with-the-public-key
	// forgeries get through.
	if header.Alg != v.algorithm {
		return Caller{}, ErrForged
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Caller{}, ErrForged
	}
	if !v.signatureValid(parts[0]+"."+parts[1], signature) {
		return Caller{}, ErrForged
	}

	claims := map[string]any{}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return Caller{}, ErrForged
	}

	now := v.now()
	exp, hasExp := numericClaim(claims["exp"])
	if !hasExp {
		// A token that never expires cannot be revoked by waiting; refuse it
		// rather than trust it forever.
		return Caller{}, ErrForged
	}
	if now.After(time.Unix(exp, 0).Add(clockSkew)) {
		return Caller{}, ErrExpired
	}
	if nbf, ok := numericClaim(claims["nbf"]); ok && now.Add(clockSkew).Before(time.Unix(nbf, 0)) {
		return Caller{}, ErrExpired
	}
	if v.issuer != "" && claims["iss"] != v.issuer {
		return Caller{}, ErrForged
	}
	if v.audience != "" && !audienceMatches(claims["aud"], v.audience) {
		return Caller{}, ErrForged
	}

	id := ClaimString(claims[v.userClaim])
	if id == "" {
		return Caller{}, ErrForged
	}
	caller := Caller{ID: id}
	if v.bypassClaim != "" {
		caller.Bypasses = claimHasAny(claims[v.bypassClaim], v.bypassValues)
	}
	return caller, nil
}

func (v *Verifier) signatureValid(signed string, signature []byte) bool {
	switch v.algorithm {
	case "HS256":
		mac := hmac.New(sha256.New, v.secret)
		mac.Write([]byte(signed))
		return hmac.Equal(mac.Sum(nil), signature)
	case "RS256":
		digest := sha256.Sum256([]byte(signed))
		return rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, digest[:], signature) == nil
	default:
		return false
	}
}

func decodeSegment(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	return decoder.Decode(into)
}

func numericClaim(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	if n, err := number.Int64(); err == nil {
		return n, true
	}
	f, err := number.Float64()
	if err != nil {
		return 0, false
	}
	return int64(f), true
}

// ClaimString renders an id the way an owner field will be compared: 7 and "7"
// name the same user, because issuers and databases disagree about which one
// an id is.
func ClaimString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return ""
	default:
		return ""
	}
}

func audienceMatches(value any, want string) bool {
	switch v := value.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if item == want {
				return true
			}
		}
	}
	return false
}

func claimHasAny(value any, wanted map[string]bool) bool {
	switch v := value.(type) {
	case string:
		return wanted[v]
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && wanted[s] {
				return true
			}
		}
	}
	return false
}
