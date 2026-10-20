package certstore

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hygkui/v5vpn-rea-client/internal/crypto"
)

// CertFilenameSeparator splits the three parts of a stored certificate file
// name: id, base64 alias and base64(DES(password)).
const CertFilenameSeparator = "#"

// BuildFilename returns the on-disk name used for an imported certificate:
//
//	{GUID32}#{Base64URL(alias)}#{Base64URL(DES-CBC(password))}.{p12|pfx}
//
// The layout mirrors the original V5VPN client's three '#'-separated parts, but
// the alias and password segments use the URL-safe base64 alphabet: standard
// base64 contains '/' and '+', and '/' is a path separator on every platform
// (and an illegal filename character on Windows), so the original layout cannot
// be stored as a single file name on Windows. ParseFilename accepts both
// alphabets so a directory written by the original client is still readable.
func BuildFilename(id, alias, password, ext string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("certificate id is empty")
	}
	ext = normalizeExt(ext)
	if ext == "" {
		return "", fmt.Errorf("unsupported certificate extension %q", ext)
	}

	encPwd, err := crypto.EncryptSettingPassword(password)
	if err != nil {
		return "", fmt.Errorf("encrypt certificate password: %w", err)
	}

	name := fmt.Sprintf("%s%s%s%s%s.%s",
		id,
		CertFilenameSeparator,
		encodeSegment([]byte(alias)),
		CertFilenameSeparator,
		encodeSegment([]byte(encPwd)),
		ext,
	)
	return name, nil
}

// ParseFilename decodes a stored certificate file name. It returns ok=false for
// names that do not follow the three-part V5VPN layout. A malformed password
// segment is not fatal: ok is still true and password is empty, so the caller
// can surface the certificate (metadata) and let the user re-import it.
func ParseFilename(name string) (id, alias, password, ext string, ok bool) {
	ext = normalizeExt(filepath.Ext(name))
	if ext == "" {
		return "", "", "", "", false
	}

	base := strings.TrimSuffix(name, "."+ext)
	parts := strings.Split(base, CertFilenameSeparator)
	if len(parts) != 3 {
		return "", "", "", "", false
	}

	id = strings.TrimSpace(parts[0])
	if id == "" {
		return "", "", "", "", false
	}

	if raw, err := decodeSegment(parts[1]); err == nil {
		alias = string(raw)
	}

	if strings.TrimSpace(parts[2]) != "" {
		if encPwd, err := decodeSegment(parts[2]); err == nil {
			if dec, err := crypto.DecryptSettingPassword(string(encPwd)); err == nil {
				password = dec
			}
		}
	}

	return id, alias, password, ext, true
}

// encodeSegment writes a filename-safe base64 segment.
func encodeSegment(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeSegment reads a segment written by this client (URL-safe, unpadded) or
// by the original client (standard alphabet, padded or not).
func decodeSegment(segment string) ([]byte, error) {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return nil, nil
	}
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		raw, err := enc.DecodeString(segment)
		if err == nil {
			return raw, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// normalizeExt maps a file extension (with or without a leading dot) to the
// lowercase "p12"/"pfx" form, or "" when the extension is not a PKCS#12 file.
func normalizeExt(ext string) string {
	ext = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ext), "."))
	switch ext {
	case "p12", "pfx":
		return ext
	default:
		return ""
	}
}
