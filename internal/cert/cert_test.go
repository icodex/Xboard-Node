package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/cedar2025/xboard-node/internal/config"
)

// generateSelfSignedPair returns a fresh self-signed certificate and matching
// private key in PEM form, suitable for storing as a libdns/certmagic site
// resource in tests.
func generateSelfSignedPair(t *testing.T, domain string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

// TestLoadPEMFromStorage_RestartScenario simulates the warm-restart bug fix:
// certmagic.ObtainCertSync returns nil without firing cert_obtained when a
// valid cert already exists in storage. The manager must still populate its
// in-memory PEM cache by reading storage explicitly.
func TestLoadPEMFromStorage_RestartScenario(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	const domain = "example.test"
	const issuerKey = "test-issuer"

	certPEM, keyPEM := generateSelfSignedPair(t, domain)

	ctx := context.Background()
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certPEM); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyPEM); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	m := NewManager(config.CertConfig{})
	if m.HasCert() {
		t.Fatal("manager should start with no cert in memory")
	}

	if err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain); err != nil {
		t.Fatalf("loadPEMFromStorage: %v", err)
	}
	if !m.HasCert() {
		t.Fatal("expected HasCert() == true after explicit load")
	}
	got := m.TLSCert()
	if string(got.CertPEM) != string(certPEM) {
		t.Errorf("certPEM mismatch")
	}
	if string(got.KeyPEM) != string(keyPEM) {
		t.Errorf("keyPEM mismatch")
	}
}

// TestLoadPEMFromStorage_RenewalRefresh confirms that calling load a second
// time with newer bytes on disk swaps the in-memory cache atomically — this
// is the renewal hot-reload path triggered from the cert_obtained event.
func TestLoadPEMFromStorage_RenewalRefresh(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	const domain = "example.test"
	const issuerKey = "test-issuer"
	ctx := context.Background()

	certV1, keyV1 := generateSelfSignedPair(t, domain)
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certV1); err != nil {
		t.Fatalf("seed v1 cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyV1); err != nil {
		t.Fatalf("seed v1 key: %v", err)
	}

	m := NewManager(config.CertConfig{})
	if err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	certV2, keyV2 := generateSelfSignedPair(t, domain)
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certV2); err != nil {
		t.Fatalf("seed v2 cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyV2); err != nil {
		t.Fatalf("seed v2 key: %v", err)
	}

	if err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain); err != nil {
		t.Fatalf("refresh load: %v", err)
	}
	got := m.TLSCert()
	if string(got.CertPEM) != string(certV2) {
		t.Error("expected v2 cert after refresh")
	}
	if string(got.KeyPEM) != string(keyV2) {
		t.Error("expected v2 key after refresh")
	}
}

// TestLoadPEMFromStorage_MissingFiles ensures we surface a clear error when
// storage doesn't have the expected keys (defensive — should not happen in
// practice because ObtainCertSync guarantees presence on success).
func TestLoadPEMFromStorage_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	m := NewManager(config.CertConfig{})
	err := m.loadPEMFromStorage(context.Background(), storage, "test-issuer", "example.test")
	if err == nil {
		t.Fatal("expected error when storage is empty")
	}
}

// TestLoadPEMFromStorage_RejectsMismatchedPair guards against silently loading
// a cert and key that do not pair (e.g. partial write or external tampering).
func TestLoadPEMFromStorage_RejectsMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	const domain = "example.test"
	const issuerKey = "test-issuer"
	ctx := context.Background()

	certA, _ := generateSelfSignedPair(t, domain)
	_, keyB := generateSelfSignedPair(t, domain)
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certA); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyB); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	m := NewManager(config.CertConfig{})
	err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain)
	if err == nil {
		t.Fatal("expected error for mismatched cert/key pair")
	}
	if m.HasCert() {
		t.Error("manager should not store invalid pair")
	}
	_ = filepath.Join(dir, "stub")
}

// TestACMEFingerprint covers the config-equality logic that decides whether
// Reconfigure must tear down a running certmagic instance.
func TestACMEFingerprint(t *testing.T) {
	base := config.CertConfig{
		CertMode:    "dns",
		Domain:      "a.example.com",
		Email:       "ops@example.com",
		DNSProvider: "cloudflare",
		DNSEnv:      map[string]string{"CLOUDFLARE_API_TOKEN": "tok"},
	}

	cases := []struct {
		name    string
		mutate  func(*config.CertConfig)
		differs bool
	}{
		{"same", func(*config.CertConfig) {}, false},
		{"domain", func(c *config.CertConfig) { c.Domain = "b.example.com" }, true},
		{"mode", func(c *config.CertConfig) { c.CertMode = "http" }, true},
		{"email", func(c *config.CertConfig) { c.Email = "other@example.com" }, true},
		{"provider", func(c *config.CertConfig) { c.DNSProvider = "alidns" }, true},
		{"env_value", func(c *config.CertConfig) { c.DNSEnv = map[string]string{"CLOUDFLARE_API_TOKEN": "other"} }, true},
		{"env_key_only", func(c *config.CertConfig) { c.DNSEnv = map[string]string{"OTHER": "tok"} }, true},
	}

	baseFp := acmeFingerprint(base)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			if tc.mutate != nil {
				// deep-copy DNSEnv before mutation to avoid sharing
				cfg.DNSEnv = map[string]string{}
				for k, v := range base.DNSEnv {
					cfg.DNSEnv[k] = v
				}
				tc.mutate(&cfg)
			}
			got := acmeFingerprint(cfg)
			if (got != baseFp) != tc.differs {
				t.Errorf("differs=%v but got==base=%v", tc.differs, got == baseFp)
			}
		})
	}
}

// TestACMEFingerprintEnvOrderStable ensures map iteration order does not
// affect the fingerprint (must be sorted internally).
func TestACMEFingerprintEnvOrderStable(t *testing.T) {
	a := config.CertConfig{
		CertMode: "dns", Domain: "x", DNSProvider: "p",
		DNSEnv: map[string]string{"A": "1", "B": "2", "C": "3"},
	}
	b := config.CertConfig{
		CertMode: "dns", Domain: "x", DNSProvider: "p",
		DNSEnv: map[string]string{"C": "3", "A": "1", "B": "2"},
	}
	if acmeFingerprint(a) != acmeFingerprint(b) {
		t.Fatal("fingerprint not order-independent")
	}
}

func TestPersistPEM_WritesFullchainAndPrivkey(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedPair(t, "example.test")

	m := NewManager(config.CertConfig{CertDir: dir})
	m.storePEM(certPEM, keyPEM)

	fullchainPath := filepath.Join(dir, "fullchain.pem")
	privkeyPath := filepath.Join(dir, "privkey.pem")

	readCert, err := os.ReadFile(fullchainPath)
	if err != nil {
		t.Fatalf("expected fullchain.pem to exist: %v", err)
	}
	if string(readCert) != string(certPEM) {
		t.Errorf("cert content mismatch")
	}

	readKey, err := os.ReadFile(privkeyPath)
	if err != nil {
		t.Fatalf("expected privkey.pem to exist: %v", err)
	}
	if string(readKey) != string(keyPEM) {
		t.Errorf("key content mismatch")
	}
}

func TestLoadPersistedPEM_FullchainAndPrivkey(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedPair(t, "example.test")

	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(config.CertConfig{CertDir: dir})
	if !m.loadPersistedPEM() {
		t.Fatal("expected loadPersistedPEM to return true for fullchain.pem and privkey.pem")
	}
	if !m.HasCert() {
		t.Fatal("expected manager to have cert after loadPersistedPEM")
	}
	got := m.TLSCert()
	if string(got.CertPEM) != string(certPEM) || string(got.KeyPEM) != string(keyPEM) {
		t.Errorf("loaded cert mismatch")
	}
}

func TestLoadPersistedPEM_LegacyFallback(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedPair(t, "example.test")

	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(config.CertConfig{CertDir: dir})
	if !m.loadPersistedPEM() {
		t.Fatal("expected loadPersistedPEM to return true for legacy cert.pem and key.pem")
	}
	if !m.HasCert() {
		t.Fatal("expected manager to have cert after loadPersistedPEM")
	}
	got := m.TLSCert()
	if string(got.CertPEM) != string(certPEM) || string(got.KeyPEM) != string(keyPEM) {
		t.Errorf("loaded cert mismatch")
	}
}

func TestPersistPEM_ReadOnlyNoopWhenContentMatches(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedPair(t, "example.test")

	fullchainPath := filepath.Join(dir, "fullchain.pem")
	privkeyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(fullchainPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privkeyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// Make directory read-only so atomicWriteFile (.tmp creation) would fail
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)

	m := NewManager(config.CertConfig{CertDir: dir})
	// Should not log error or panic because content is already equal on disk
	m.persistPEMTo(dir, certPEM, keyPEM)
}

func TestResolveModeFor_CertDirWithDefaultFiles(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedPair(t, "example.test")

	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	mode := resolveModeFor(config.CertConfig{CertDir: dir})
	if mode != "file" {
		t.Errorf("expected mode file, got %q", mode)
	}
}

// tearDownACME must keep the in-memory material: until a new configuration
// produces valid PEM, the old material is the only thing keeping TLS
// validation and warm restarts alive. A failed Reconfigure used to wipe it.
func TestTearDownACME_KeepsMaterial(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedPair(t, "keepme.test")
	m := NewManager(config.CertConfig{CertMode: "dns", Domain: "keepme.test"})
	m.mat.Store(&certMaterial{certPEM: certPEM, keyPEM: keyPEM})
	m.acmeStarted = true
	m.acmeFingerprint = "stale"

	m.tearDownACME()

	if m.acmeStarted || m.cache != nil {
		t.Fatal("tear-down should clear ACME state")
	}
	if !m.HasCert() {
		t.Fatal("tear-down must not drop the in-memory cert material")
	}
	tls := m.TLSCert()
	if string(tls.CertPEM) != string(certPEM) || string(tls.KeyPEM) != string(keyPEM) {
		t.Fatal("TLSCert changed after tear-down")
	}
}

// A service instance that fails setup is rebuilt by runNodeService on the same
// daemon context; a no-op Stop left one certmagic cache + renewal goroutine
// behind per retry.
func TestManagerStopCancelsACME(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedPair(t, "stop.test")
	m := NewManager(config.CertConfig{CertMode: "dns", Domain: "stop.test"})
	m.mat.Store(&certMaterial{certPEM: certPEM, keyPEM: keyPEM})
	canceled := false
	m.acmeStarted = true
	m.acmeCancel = func() { canceled = true }

	m.Stop()

	if !canceled {
		t.Fatal("Stop must cancel ACME maintenance")
	}
	if m.acmeStarted || m.acmeCancel != nil {
		t.Fatal("Stop must clear ACME state")
	}
	if !m.HasCert() {
		t.Fatal("Stop must keep the in-memory cert material")
	}
}

// Start creates a manager-owned lifetime so Stop can cancel ACME maintenance
// even when the service is torn down on the daemon context (runNodeService
// retries reuse it).
func TestManagerStopCancelsLifetime(t *testing.T) {
	m := NewManager(config.CertConfig{CertMode: "none"})
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	life := m.lifetime()
	if life == nil {
		t.Fatal("Start must create a manager lifetime")
	}

	m.Stop()

	select {
	case <-life.Done():
	default:
		t.Fatal("Stop must cancel the manager lifetime")
	}
	if m.lifetime() != nil {
		t.Fatal("Stop must clear the lifetime")
	}
}

// A cert worker may still reach Reconfigure after the service tore the manager
// down; that must fail instead of re-arming ACME maintenance.
func TestReconfigureAfterStopFails(t *testing.T) {
	m := NewManager(config.CertConfig{CertMode: "none"})
	m.Stop()

	if _, err := m.Reconfigure(context.Background(), config.CertConfig{CertMode: "none"}); err == nil {
		t.Fatal("Reconfigure after Stop must fail")
	}
	if m.lifetime() != nil || m.acmeStarted {
		t.Fatal("a stopped manager must not re-arm state")
	}
}

// os.WriteFile-like skip paths must still tighten a pre-existing
// world-readable key, otherwise an old 0644 privkey.pem stays readable.
func TestPersistPEMTightensExistingKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedPair(t, "perm.test")
	if err := os.WriteFile(filepath.Join(dir, defaultCertFile), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, defaultKeyFile), keyPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(config.CertConfig{CertDir: dir})
	m.persistPEMTo(dir, certPEM, keyPEM)

	fi, err := os.Stat(filepath.Join(dir, defaultKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("key mode = %o, want 600", got)
	}
}

// certmagic renewal events must reload the material and set the flag the
// service loop consumes to reload the kernel.
func TestHandleCertEventMarksRenewed(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	const domain = "renew.test"
	const issuerKey = "test-issuer"
	ctx := context.Background()

	certV2, keyV2 := generateSelfSignedPair(t, domain)
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certV2); err != nil {
		t.Fatal(err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyV2); err != nil {
		t.Fatal(err)
	}

	m := NewManager(config.CertConfig{Domain: domain, CertDir: dir})
	if m.CertRenewed() {
		t.Fatal("fresh manager must not report a renewal")
	}

	err := m.handleCertEvent(ctx, "cert_obtained", map[string]any{
		"renewal": true,
		"issuer":  issuerKey,
	}, storage, domain, dir)
	if err != nil {
		t.Fatalf("handleCertEvent: %v", err)
	}
	if !m.CertRenewed() {
		t.Fatal("renewal event must set the renewed flag")
	}
	if m.CertRenewed() {
		t.Fatal("renewed flag must be consumed once")
	}
	if got := m.TLSCert(); string(got.CertPEM) != string(certV2) {
		t.Fatal("renewal must reload the new certificate")
	}

	// Non-renewal events are ignored.
	if err := m.handleCertEvent(ctx, "cert_obtained", map[string]any{"renewal": false}, storage, domain, dir); err != nil {
		t.Fatal(err)
	}
	if m.CertRenewed() {
		t.Fatal("initial issuance must not mark a renewal")
	}
}
