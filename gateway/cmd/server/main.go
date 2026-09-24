package main

import (
	"cmp"
	"log"
	"os"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/proxy"
)

func main() {
	cfgPath := os.Getenv("IASG_CONFIG")
	cfgPath = cmp.Or(cfgPath, "configs/config.yaml")

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("failed to load config from %s: %v", cfgPath, err)
	}
	for _, line := range config.ApplyEnvOverrides(cfg, os.Getenv) {
		log.Print(line)
	}

	serverConfig := proxy.ConfigFrom(cfg)
	log.Printf("Gateway starting on %s (backend: %s, config: %s)", serverConfig.ListenAddr, cfg.Proxy.BackendURL, cfgPath)

	if err := proxy.NewServer(serverConfig).Start(); err != nil {
		log.Fatal(err)
	}
}
