package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCertificateFieldsRoundTrip verifies that authtype/certtype/certautologin
// and the certificate id survive a load/save cycle instead of resetting to
// zero, which used to make the UI forget the certificate login selection.
func TestCertificateFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setting.xml")

	input := `<?xml version="1.0" encoding="UTF-8"?>
<SETTING_INFO>
  <COMMON offRelogin="0" HideToTray="1" LoginDebug="0" language="0" remember="1" autologin="0" trayNotify="0"/>
  <GATEWAY LastUseGateway="prod">
    <Gateway0 Name="prod" Ip="203.0.113.10" Port="443" algo="0">
      <USER LastUserName="YWxpY2U=" authtype="1" certtype="1" certautologin="1" certid="A1B2C3D4E5F60718293A4B5C6D7E8F90">
        <User0 Name="YWxpY2U=" Pwd="" rpwd="0" auto="0"></User0>
      </USER>
    </Gateway0>
  </GATEWAY>
</SETTING_INFO>`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cfg, err := LoadSettingXML(path)
	if err != nil {
		t.Fatalf("LoadSettingXML: %v", err)
	}
	if len(cfg.Gateways) != 1 {
		t.Fatalf("expected 1 gateway, got %d", len(cfg.Gateways))
	}
	gw := cfg.Gateways[0]
	if gw.AuthType != 1 || gw.CertType != 1 || !gw.CertAutoLogin {
		t.Fatalf("certificate fields lost on load: %+v", gw)
	}
	if gw.SelectedCertID != "A1B2C3D4E5F60718293A4B5C6D7E8F90" {
		t.Fatalf("certificate id lost on load: %q", gw.SelectedCertID)
	}

	// Save to a second file and reload: the values must round-trip, and the
	// certificate id must be written as a plain attribute.
	outPath := filepath.Join(dir, "setting.out.xml")
	if err := cfg.SaveSettingXML(outPath); err != nil {
		t.Fatalf("SaveSettingXML: %v", err)
	}
	saved, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	for _, want := range []string{
		`authtype="1"`,
		`certtype="1"`,
		`certautologin="1"`,
		`certid="A1B2C3D4E5F60718293A4B5C6D7E8F90"`,
	} {
		if !strings.Contains(string(saved), want) {
			t.Fatalf("saved XML is missing %s:\n%s", want, saved)
		}
	}

	reloaded, err := LoadSettingXML(outPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := reloaded.Gateways[0]
	if got.AuthType != gw.AuthType || got.CertType != gw.CertType ||
		got.CertAutoLogin != gw.CertAutoLogin || got.SelectedCertID != gw.SelectedCertID {
		t.Fatalf("round trip mismatch: before=%+v after=%+v", gw, got)
	}
}

// TestCertificateIDOmittedWhenUnset keeps the file readable by the original
// client: a certificate-less gateway must not gain an empty certid attribute.
func TestCertificateIDOmittedWhenUnset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setting.xml")
	cfg := &AppConfig{
		LastUseGateway: "gw",
		Gateways: []GatewayProfile{{
			Name: "gw",
			IP:   "203.0.113.10",
			Port: 443,
		}},
	}
	if err := cfg.SaveSettingXML(path); err != nil {
		t.Fatalf("SaveSettingXML: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "certid=") {
		t.Fatalf("unexpected certid attribute for a password-only gateway:\n%s", data)
	}
	if !strings.Contains(string(data), `authtype="0"`) {
		t.Fatalf("authtype default not written:\n%s", data)
	}
}
