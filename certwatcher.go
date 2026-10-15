package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"path/filepath"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
)

// certWatcher keeps an in-memory TLS certificate up to date with whatever is
// currently on disk, so a running HTTPS server can pick up a cert-manager
// rotation without a restart.
type certWatcher struct {
	certPath string
	keyPath  string
	current  atomic.Pointer[tls.Certificate]
}

func newCertWatcher(certPath, keyPath string) (*certWatcher, error) {
	cw := &certWatcher{certPath: certPath, keyPath: keyPath}
	if err := cw.reload(); err != nil {
		return nil, err
	}
	return cw, nil
}

func (cw *certWatcher) reload() error {
	cert, err := tls.LoadX509KeyPair(cw.certPath, cw.keyPath)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}
	cw.current.Store(&cert)
	log.Printf("tls: certificate (re)loaded from %s", cw.certPath)
	return nil
}

// GetCertificate is wired into tls.Config so every new handshake uses
// whatever certificate is currently cached, without needing a server restart.
func (cw *certWatcher) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cw.current.Load(), nil
}

// watch watches the mount directory rather than the cert file itself.
// Kubernetes updates Secret volumes by atomically swapping a "..data"
// symlink to a new timestamped directory; a watch on the file inode would
// miss that swap, but a directory-level watch sees the rename/create event.
func (cw *certWatcher) watch() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify: %w", err)
	}

	dir := filepath.Dir(cw.certPath)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("watch %s: %w", dir, err)
	}

	go func() {
		defer watcher.Close()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) == 0 {
					continue
				}
				if err := cw.reload(); err != nil {
					log.Printf("tls: reload after %s failed: %v", event, err)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("tls: watcher error: %v", err)
			}
		}
	}()
	return nil
}
