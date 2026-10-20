package certstore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/crypto"
)

// TestParseFilenameAcceptsOriginalClientLayout verifies that a certificate
// directory written by the original V5VPN client (standard base64 segments,
// DES-encrypted password) stays readable after switching to the URL-safe
// alphabet used by BuildFilename. The original client could not store such a
// name on Windows when a segment contained '/', so the fixture picks segments
// that are representable as a single file name.
func TestParseFilenameAcceptsOriginalClientLayout(t *testing.T) {
	id := "A1B2C3D4E5F60718293A4B5C6D7E8F90"
	alias := "legacy cert"
	password := "legacy-password"

	encPwd, err := crypto.EncryptSettingPassword(password)
	if err != nil {
		t.Fatalf("EncryptSettingPassword: %v", err)
	}
	// The ciphertext may contain '/', which cannot be a filename character on
	// Windows; this fixture only validates the parser, so skip the case where
	// the original layout is not representable.
	aliasSeg := base64.StdEncoding.EncodeToString([]byte(alias))
	if strings.ContainsAny(encPwd, `/\`) || strings.ContainsAny(aliasSeg, `/\`) {
		t.Skip("fixture segments contain a path separator")
	}
	filename := id + "#" + aliasSeg + "#" + encPwd + ".p12"

	gotID, gotAlias, gotPwd, gotExt, ok := ParseFilename(filename)
	if !ok {
		t.Fatalf("ParseFilename rejected original layout %q", filename)
	}
	if gotID != id || gotAlias != alias || gotPwd != password || gotExt != "p12" {
		t.Fatalf("unexpected parse: id=%q alias=%q pwd=%q ext=%q", gotID, gotAlias, gotPwd, gotExt)
	}
}

// TestBuildFilenameAlwaysProducesSafeNames guards the path-separator bug: a
// standard base64 segment can contain '/', which produced nested directories
// and made ImportFile fail.
func TestBuildFilenameAlwaysProducesSafeNames(t *testing.T) {
	// Repeat enough times that any '/' in the password ciphertext is likely.
	for i := 0; i < 200; i++ {
		filename, err := BuildFilename("00112233445566778899AABBCCDDEEFF", "alias", "p@ssw0rd-#", "p12")
		if err != nil {
			t.Fatalf("BuildFilename: %v", err)
		}
		if filepath.Base(filename) != filename {
			t.Fatalf("filename contains a path separator: %q", filename)
		}
		if _, err := os.Stat(filepath.Join(t.TempDir(), filename)); err == nil {
			t.Fatalf("unexpected existing file %q", filename)
		}
	}
}

// TestImportReadsOriginalClientFile places a certificate under the original
// client's file name in the store directory and checks it is listed and
// loadable, which is what "share the cert directory with the original client"
// relies on.
func TestImportReadsOriginalClientFile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	now := time.Now()
	data := makePKCS12(t, "legacy-user", "legacy-password", now.Add(-time.Hour), now.Add(time.Hour))

	encPwd, err := crypto.EncryptSettingPassword("legacy-password")
	if err != nil {
		t.Fatalf("EncryptSettingPassword: %v", err)
	}
	name := "00112233445566778899AABBCCDDEEFF#" +
		base64.StdEncoding.EncodeToString([]byte("旧客户端证书")) + "#" +
		encPwd + ".p12"
	if strings.ContainsAny(name, `/\`) {
		t.Skip("original layout is not representable as a single file name here")
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatalf("write legacy cert: %v", err)
	}

	list, err := store.List(SourceFile)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 certificate, got %+v", list)
	}
	if list[0].Name != "旧客户端证书" {
		t.Fatalf("expected alias from filename, got %q", list[0].Name)
	}

	cert, err := store.LoadTLS(list[0].ID, SourceFile)
	if err != nil {
		t.Fatalf("LoadTLS legacy certificate: %v", err)
	}
	if cert.Leaf.Subject.CommonName != "legacy-user" {
		t.Fatalf("unexpected leaf CN: %q", cert.Leaf.Subject.CommonName)
	}
}

// TestGeneratedCertSanity keeps the self-signed fixture honest: the test
// certificates must be usable for client auth.
func TestGeneratedCertSanity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sanity"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("fixture is not a client-auth certificate: %+v", cert.ExtKeyUsage)
	}
}
