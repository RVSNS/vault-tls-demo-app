package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

type config struct {
	vaultAddr    string
	k8sRole      string
	jwtPath      string
	kvMount      string
	kvPath       string
	kvRefresh    time.Duration
	certFile     string
	keyFile      string
	listenAddr   string
}

func loadConfig() config {
	return config{
		vaultAddr:  getenv("VAULT_ADDR", "http://vault.vault.svc.cluster.local:8200"),
		k8sRole:    getenv("VAULT_K8S_ROLE", "vault-tls-demo"),
		jwtPath:    getenv("VAULT_K8S_JWT_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		kvMount:    getenv("VAULT_KV_MOUNT", "secret"),
		kvPath:     getenv("VAULT_KV_PATH", "vault-tls-demo/config"),
		kvRefresh:  getenvDuration("VAULT_KV_REFRESH_INTERVAL", 10*time.Second),
		certFile:   getenv("TLS_CERT_FILE", "/etc/certs/tls.crt"),
		keyFile:    getenv("TLS_KEY_FILE", "/etc/certs/tls.key"),
		listenAddr: getenv("LISTEN_ADDR", ":8443"),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("config: invalid duration %q for %s, using default %s", v, key, def)
		return def
	}
	return d
}

// secretCache holds the most recently read KV v2 payload so request handlers
// never block on a Vault round-trip.
type secretCache struct {
	data atomic.Pointer[map[string]interface{}]
}

func (c *secretCache) set(m map[string]interface{}) { c.data.Store(&m) }
func (c *secretCache) get() map[string]interface{} {
	if p := c.data.Load(); p != nil {
		return *p
	}
	return nil
}

func main() {
	cfg := loadConfig()

	vs, err := newVaultSession(cfg.vaultAddr, cfg.k8sRole, cfg.jwtPath)
	if err != nil {
		log.Fatalf("vault: initial authentication failed: %v", err)
	}

	cache := &secretCache{}
	refreshSecret := func() {
		data, err := vs.readKV2(cfg.kvMount, cfg.kvPath)
		if err != nil {
			log.Printf("vault: kv2 refresh failed: %v", err)
			return
		}
		cache.set(data)
		log.Printf("kv2: %s/%s = %v", cfg.kvMount, cfg.kvPath, data)
	}
	refreshSecret()
	go func() {
		ticker := time.NewTicker(cfg.kvRefresh)
		defer ticker.Stop()
		for range ticker.C {
			refreshSecret()
		}
	}()

	cw, err := newCertWatcher(cfg.certFile, cfg.keyFile)
	if err != nil {
		log.Fatalf("tls: initial certificate load failed: %v", err)
	}
	if err := cw.watch(); err != nil {
		log.Fatalf("tls: cannot watch certificate directory: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		data := cache.get()
		if data == nil {
			http.Error(w, "secret not loaded yet", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	})
	mux.HandleFunc("/cert-info", func(w http.ResponseWriter, r *http.Request) {
		cert, err := cw.GetCertificate(nil)
		if err != nil || cert == nil || len(cert.Certificate) == 0 {
			http.Error(w, "certificate not loaded", http.StatusServiceUnavailable)
			return
		}
		x509Cert, err := x509ParseFirst(cert.Certificate[0])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"serial_number": x509Cert.SerialNumber.String(),
			"not_before":    x509Cert.NotBefore,
			"not_after":     x509Cert.NotAfter,
			"issuer":        x509Cert.Issuer.String(),
			"subject":       x509Cert.Subject.String(),
		})
	})

	server := &http.Server{
		Addr:    cfg.listenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: cw.GetCertificate,
		},
	}

	go func() {
		log.Printf("listening on %s", cfg.listenAddr)
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("server: shutdown error: %v", err)
	}
}
