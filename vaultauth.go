package main

import (
	"fmt"
	"log"
	"os"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// vaultSession wraps a Vault client that authenticates via the Kubernetes
// auth engine and keeps its token alive for as long as the process runs.
type vaultSession struct {
	client  *vaultapi.Client
	role    string
	jwtPath string
}

func newVaultSession(addr, role, jwtPath string) (*vaultSession, error) {
	client, err := vaultapi.NewClient(&vaultapi.Config{Address: addr})
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}
	vs := &vaultSession{client: client, role: role, jwtPath: jwtPath}
	if err := vs.login(); err != nil {
		return nil, err
	}
	return vs, nil
}

func (vs *vaultSession) login() error {
	jwt, err := os.ReadFile(vs.jwtPath)
	if err != nil {
		return fmt.Errorf("read service account token: %w", err)
	}

	secret, err := vs.client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"jwt":  string(jwt),
		"role": vs.role,
	})
	if err != nil {
		return fmt.Errorf("kubernetes auth login: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("kubernetes auth login: empty response")
	}

	vs.client.SetToken(secret.Auth.ClientToken)
	log.Printf("vault: authenticated via kubernetes auth role=%q ttl=%ds renewable=%v",
		vs.role, secret.Auth.LeaseDuration, secret.Auth.Renewable)

	go vs.keepAlive(secret.Auth)
	return nil
}

// keepAlive renews the login token for as long as Vault allows, and
// transparently re-authenticates once the lease can no longer be renewed.
func (vs *vaultSession) keepAlive(auth *vaultapi.SecretAuth) {
	watcher, err := vs.client.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{
		Secret: &vaultapi.Secret{Auth: auth},
	})
	if err != nil {
		log.Printf("vault: cannot start lifetime watcher: %v", err)
		vs.reauthenticateWithBackoff()
		return
	}

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case err, ok := <-watcher.DoneCh():
			if !ok {
				return
			}
			log.Printf("vault: token lease ended (%v); re-authenticating", err)
			vs.reauthenticateWithBackoff()
			return
		case renewal := <-watcher.RenewCh():
			log.Printf("vault: token renewed, ttl=%ds", renewal.Secret.Auth.LeaseDuration)
		}
	}
}

func (vs *vaultSession) reauthenticateWithBackoff() {
	backoff := 2 * time.Second
	for {
		if err := vs.login(); err == nil {
			return
		} else {
			log.Printf("vault: re-login failed: %v; retrying in %s", err, backoff)
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// readKV2 reads a KV v2 secret, unwrapping the extra "data" envelope KV v2
// adds around the actual secret payload.
func (vs *vaultSession) readKV2(mount, path string) (map[string]interface{}, error) {
	full := fmt.Sprintf("%s/data/%s", mount, path)
	secret, err := vs.client.Logical().Read(full)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", full, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("read %s: no data", full)
	}
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("read %s: unexpected kv2 response shape", full)
	}
	return data, nil
}
