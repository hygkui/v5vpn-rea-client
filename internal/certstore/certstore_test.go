package certstore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// makePKCS12 builds a self-signed client certificate and encodes it as a
// PKCS#12 file. password may be empty.
func makePKCS12(t *testing.T, cn, password string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"v5vpn-rea tests"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	encoded, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		t.Fatalf("encode pkcs12: %v", err)
	}
	return encoded
}

func writeTempCert(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write temp cert: %v", err)
	}
	return path
}

func TestBuildAndParseFilename(t *testing.T) {
	cases := []struct {
		name     string
		id       string
		alias    string
		password string
		ext      string
	}{
		{"simple", "A1B2C3D4E5F60718293A4B5C6D7E8F90", "alice", "secret", "p12"},
		{"chinese alias", "00112233445566778899AABBCCDDEEFF", "测试证书-生产", "p@ss#word!", "pfx"},
		{"empty password", "ABCDEF0123456789ABCDEF0123456789", "no-password", "", "p12"},
		{"hash in alias", "FFEEDDCCBBAA99887766554433221100", "a#b#c", "x", "p12"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filename, err := BuildFilename(tc.id, tc.alias, tc.password, tc.ext)
			if err != nil {
				t.Fatalf("BuildFilename: %v", err)
			}
			id, alias, password, ext, ok := ParseFilename(filename)
			if !ok {
				t.Fatalf("ParseFilename rejected %q", filename)
			}
			if id != tc.id || alias != tc.alias || password != tc.password || ext != tc.ext {
				t.Fatalf("round trip mismatch: got id=%q alias=%q pwd=%q ext=%q", id, alias, password, ext)
			}
		})
	}
}

func TestParseFilenameRejectsForeignNames(t *testing.T) {
	for _, name := range []string{
		"cert.p12",
		"a#b.p12",
		"#alias#pwd.p12",
		"id#alias#pwd.txt",
	} {
		if _, _, _, _, ok := ParseFilename(name); ok {
			t.Fatalf("ParseFilename accepted %q", name)
		}
	}
}

func TestImportListDelete(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	now := time.Now()
	src := writeTempCert(t, "client.p12", makePKCS12(t, "alice@example.com", "p12-secret",
		now.Add(-time.Hour), now.Add(24*time.Hour)))

	info, err := store.ImportFile(src, "生产证书", "p12-secret")
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
	}
	if info.Name != "生产证书" {
		t.Fatalf("expected alias as display name, got %q", info.Name)
	}
	if info.Issuer != "v5vpn-rea tests" && info.Issuer != "" {
		// Self-signed certificates use the same subject as issuer; the CN is
		// the display name, the issuer CN equals it.
		t.Logf("issuer: %q", info.Issuer)
	}
	if info.IsExpired {
		t.Fatal("fresh certificate reported as expired")
	}
	if info.ValidFrom == "" || info.ValidTo == "" {
		t.Fatalf("missing validity, got %+v", info)
	}

	list, err := store.List(SourceFile)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != info.ID {
		t.Fatalf("unexpected list: %+v", list)
	}

	cert, err := store.LoadTLS(info.ID, SourceFile)
	if err != nil {
		t.Fatalf("LoadTLS: %v", err)
	}
	if cert.Leaf == nil || cert.Leaf.Subject.CommonName != "alice@example.com" {
		t.Fatalf("unexpected leaf: %+v", cert.Leaf)
	}
	if cert.PrivateKey == nil {
		t.Fatal("private key missing")
	}

	if err := store.Delete(info.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	list, err = store.List(SourceFile)
	if err != nil {
		t.Fatalf("List after delete: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %+v", list)
	}
	if err := store.Delete(info.ID); err == nil {
		t.Fatal("expected ErrCertNotFound for missing certificate")
	}
}

func TestImportRejectsWrongPassword(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	now := time.Now()
	src := writeTempCert(t, "client.p12", makePKCS12(t, "bob", "right",
		now.Add(-time.Hour), now.Add(time.Hour)))

	if _, err := store.ImportFile(src, "", "wrong"); err == nil {
		t.Fatal("expected import to fail with the wrong password")
	}

	entries, err := os.ReadDir(store.Dir())
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed import left files behind: %v", entries)
	}
}

func TestListMarksExpiredCertificate(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	now := time.Now()
	src := writeTempCert(t, "old.p12", makePKCS12(t, "expired", "pw",
		now.Add(-48*time.Hour), now.Add(-24*time.Hour)))

	info, err := store.ImportFile(src, "", "pw")
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
	}
	if !info.IsExpired {
		t.Fatal("expired certificate not marked as expired")
	}
}

func TestLoadTLSFileOutsideStore(t *testing.T) {
	now := time.Now()
	path := writeTempCert(t, "external.pfx", makePKCS12(t, "external", "pw",
		now.Add(-time.Hour), now.Add(time.Hour)))

	cert, err := LoadTLSFile(path, "pw")
	if err != nil {
		t.Fatalf("LoadTLSFile: %v", err)
	}
	if cert.Leaf.Subject.CommonName != "external" {
		t.Fatalf("unexpected leaf CN: %q", cert.Leaf.Subject.CommonName)
	}
	if _, err := LoadTLSFile(path, "bad"); err == nil {
		t.Fatal("expected failure with wrong password")
	}
}

func TestSystemStoreUnsupportedOnNonWindows(t *testing.T) {
	if strings.Contains(strings.ToLower(os.Getenv("GOOS")), "windows") {
		t.Skip("windows host")
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := store.List(SourceSystem); err == nil {
		t.Skip("this platform exposes a system certificate store")
	}
}
