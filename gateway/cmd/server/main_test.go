package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func collect(lines *[]string) func(...any) {
	return func(args ...any) { *lines = append(*lines, fmt.Sprint(args...)) }
}

// The shipped config must start the gateway; this is the file the container runs.
func TestTheShippedConfigLoads(t *testing.T) {
	var lines []string
	cfg, err := load(env(map[string]string{"IASG_CONFIG": "../../configs/config.yaml"}), collect(&lines))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr == "" || cfg.BackendURL == "" {
		t.Errorf("incomplete server config: %+v", cfg)
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "Gateway starting on "+cfg.ListenAddr) {
		t.Errorf("startup line = %q", lines)
	}
}

// Compose points the gateway at its backend and Redis by environment; those
// overrides must win over the file, and say so in the log.
func TestEnvironmentOverridesWinAndAreLogged(t *testing.T) {
	var lines []string
	cfg, err := load(env(map[string]string{
		"IASG_CONFIG":      "../../configs/config.yaml",
		"IASG_BACKEND_URL": "http://backend.internal:5000",
		"IASG_REDIS_HOST":  "cache",
	}), collect(&lines))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BackendURL != "http://backend.internal:5000" {
		t.Errorf("backend = %q", cfg.BackendURL)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"IASG_BACKEND_URL: http://backend.internal:5000", "IASG_REDIS_HOST: cache", "backend: http://backend.internal:5000"} {
		if !strings.Contains(joined, want) {
			t.Errorf("log is missing %q:\n%s", want, joined)
		}
	}
}

// A gateway that cannot read its config must not start on defaults: it would
// run without the detectors and limits the operator configured.
func TestABadConfigStopsTheGatewayNamingTheFile(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(broken, []byte("server: [not, a, map"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{broken, filepath.Join(t.TempDir(), "absent.yaml")} {
		_, err := load(env(map[string]string{"IASG_CONFIG": path}), func(...any) {})
		if err == nil || !strings.Contains(err.Error(), "failed to load config from "+path) {
			t.Errorf("%s: err = %v", path, err)
		}
	}
}

func TestWithoutIASGConfigTheDefaultPathIsUsed(t *testing.T) {
	_, err := load(env(nil), func(...any) {})
	if err == nil || !strings.Contains(err.Error(), "configs/config.yaml") {
		t.Errorf("err = %v, want the default path named", err)
	}
}
