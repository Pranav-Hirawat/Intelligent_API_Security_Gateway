package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

func writePEM(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A gateway that cannot check signatures must refuse to start rather than
// start and wave everything through, whatever is wrong with the key.
func TestAnUnusableKeyStopsTheGatewayAtBoot(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(notPEM, []byte("just text"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, cfg := range map[string]config.JWTConfig{
		"missing file":      {Algorithm: "RS256", PublicKeyFile: filepath.Join(t.TempDir(), "absent.pem")},
		"not PEM":           {Algorithm: "RS256", PublicKeyFile: notPEM},
		"not an RSA key":    {Algorithm: "RS256", PublicKeyFile: writePEM(t, "PUBLIC KEY", ecDER)},
		"garbage in PEM":    {Algorithm: "RS256", PublicKeyFile: writePEM(t, "PUBLIC KEY", []byte("garbage"))},
		"alg none":          {Algorithm: "none"},
		"unknown algorithm": {Algorithm: "ES256"},
	} {
		if _, err := NewVerifier(cfg, os.Getenv); err == nil {
			t.Errorf("%s: the verifier started", name)
		}
	}
}

func TestAnOlderPKCS1PublicKeyIsAccepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := writePEM(t, "RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&key.PublicKey))
	if _, err := NewVerifier(config.JWTConfig{Algorithm: "RS256", PublicKeyFile: path}, os.Getenv); err != nil {
		t.Errorf("PKCS#1 key refused: %v", err)
	}
}

func TestTimesThatCannotBeReadAreRefused(t *testing.T) {
	v := hsVerifier(t, config.JWTConfig{})
	header := map[string]any{"alg": "HS256"}

	for name, exp := range map[string]any{"text": "tomorrow", "missing": nil, "object": map[string]int{"at": 1}} {
		claims := map[string]any{"sub": "1"}
		if exp != nil {
			claims["exp"] = exp
		}
		if _, err := v.Verify(hs256(t, testSecret, header, claims)); !errors.Is(err, ErrForged) {
			t.Errorf("exp %s: err = %v, want ErrForged", name, err)
		}
	}

	// Some issuers write times as floating point; that is still a time.
	fractional := json.Number("1.9e9")
	if _, err := v.Verify(hs256(t, testSecret, header, map[string]any{"sub": "1", "exp": fractional})); err != nil {
		t.Errorf("fractional exp refused: %v", err)
	}
}

func TestATokenNotYetValidIsTreatedLikeAnExpiredOne(t *testing.T) {
	v := hsVerifier(t, config.JWTConfig{})
	later := time.Now().Add(time.Hour).Unix()
	token := hs256(t, testSecret, map[string]any{"alg": "HS256"}, map[string]any{"sub": "1", "exp": future() + 3600, "nbf": later})
	if _, err := v.Verify(token); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

// 7 and "7" are the same user: issuers and databases disagree about which one
// an id is, and an ownership check comparing them as different would lock
// every user out of their own orders.
func TestANumericUserIDMatchesItsTextForm(t *testing.T) {
	v := hsVerifier(t, config.JWTConfig{})
	header := map[string]any{"alg": "HS256"}
	caller, err := v.Verify(hs256(t, testSecret, header, map[string]any{"sub": 7, "exp": future()}))
	if err != nil || caller.ID != "7" {
		t.Errorf("numeric sub: caller=%+v err=%v, want ID 7", caller, err)
	}
	for name, sub := range map[string]any{"boolean": true, "empty": ""} {
		if _, err := v.Verify(hs256(t, testSecret, header, map[string]any{"sub": sub, "exp": future()})); !errors.Is(err, ErrForged) {
			t.Errorf("%s sub: err = %v, want ErrForged", name, err)
		}
	}
	if got := ClaimString(7.0); got != "7" {
		t.Errorf("ClaimString(7.0) = %q, want 7", got)
	}
	if got := ClaimString(nil); got != "" {
		t.Errorf("ClaimString(nil) = %q, want empty", got)
	}
}

func TestBypassAndAudienceReadFromLists(t *testing.T) {
	v := hsVerifier(t, config.JWTConfig{Audience: "api", BypassClaim: "roles", BypassValues: []string{"admin"}})
	header := map[string]any{"alg": "HS256"}

	admin := hs256(t, testSecret, header, map[string]any{"sub": "1", "exp": future(), "aud": "api", "roles": []any{"user", "admin"}})
	if caller, err := v.Verify(admin); err != nil || !caller.Bypasses {
		t.Errorf("admin in a list: caller=%+v err=%v, want bypass", caller, err)
	}
	odd := hs256(t, testSecret, header, map[string]any{"sub": "1", "exp": future(), "aud": "api", "roles": []any{1, "user"}})
	if caller, err := v.Verify(odd); err != nil || caller.Bypasses {
		t.Errorf("no admin in list: caller=%+v err=%v, want no bypass", caller, err)
	}
	for name, aud := range map[string]any{"other list": []any{"web", "mobile"}, "number": 5} {
		token := hs256(t, testSecret, header, map[string]any{"sub": "1", "exp": future(), "aud": aud})
		if _, err := v.Verify(token); !errors.Is(err, ErrForged) {
			t.Errorf("aud %s: err = %v, want ErrForged", name, err)
		}
	}
}

func TestMalformedTokensAreForgeries(t *testing.T) {
	v := hsVerifier(t, config.JWTConfig{})
	good := hs256(t, testSecret, map[string]any{"alg": "HS256"}, map[string]any{"sub": "1", "exp": future()})
	for name, token := range map[string]string{
		"two parts":         "a.b",
		"header not b64":    "!!!." + good[len(good)/3:],
		"signature not b64": good[:len(good)-4] + "!!!!",
	} {
		if _, err := v.Verify(token); !errors.Is(err, ErrForged) {
			t.Errorf("%s: err = %v, want ErrForged", name, err)
		}
	}
}
