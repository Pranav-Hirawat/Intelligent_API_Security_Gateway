package main

import (
	"cmp"
	"fmt"
	"log"
	"os"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/proxy"
)

func main() {
	serverConfig, err := load(os.Getenv, log.Print)
	if err != nil {
		log.Fatal(err)
	}
	if err := proxy.NewServer(serverConfig).Start(); err != nil {
		log.Fatal(err)
	}
}

// load is everything main does before serving, apart so it can be tested
// without starting a listener.
func load(getenv func(string) string, logf func(...any)) (proxy.Config, error) {
	cfgPath := cmp.Or(getenv("IASG_CONFIG"), "configs/config.yaml")

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return proxy.Config{}, fmt.Errorf("failed to load config from %s: %v", cfgPath, err)
	}
	for _, line := range config.ApplyEnvOverrides(cfg, getenv) {
		logf(line)
	}

	serverConfig := proxy.ConfigFrom(cfg)
	logf(fmt.Sprintf("Gateway starting on %s (backend: %s, config: %s)", serverConfig.ListenAddr, cfg.Proxy.BackendURL, cfgPath))
	return serverConfig, nil
}
