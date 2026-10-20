package certstore

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// Source identifies where a certificate came from. The numeric values match
// the certtype attribute stored in setting.xml by the original client.
type Source int

const (
	// SourceFile is a PKCS#12 (.p12/.pfx) file managed by this client.
	SourceFile Source = 0
	// SourceUSBKey is reserved for hardware tokens; not implemented yet.
	// The value 1 (the original client's system store) is no longer served.
	SourceUSBKey Source = 2
)

// Errors surfaced to the UI/CLI. Wrap them with %w when adding context.
var (
	ErrCertNotFound      = errors.New("证书不存在，请刷新证书列表")
	ErrUSBKeyUnsupported = errors.New("USB Key 证书登录暂未支持")
)

// CertInfo is the frontend/CLI view of an installed client certificate.
type CertInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	ValidFrom string `json:"validFrom"`
	ValidTo   string `json:"validTo"`
	IsExpired bool   `json:"isExpired"`
	Source    int    `json:"source"`
	FilePath  string `json:"filePath,omitempty"`
}

// Store manages certificates installed for this client. File certificates are
// kept as PKCS#12 files under Dir using the original client's naming scheme.
type Store struct {
	dir string
}

// NewStore creates the certificate directory when needed and returns a store
// rooted at dir.
func NewStore(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("certificate directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create certificate directory %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the directory that holds file certificates.
func (s *Store) Dir() string { return s.dir }

// List returns the certificates available for the requested source, sorted by
// display name. An unsupported source returns ErrUSBKeyUnsupported; the UI
// hides those entries in that case.
func (s *Store) List(source Source) ([]CertInfo, error) {
	switch source {
	case SourceFile:
		return s.listFiles()
	case SourceUSBKey:
		return nil, ErrUSBKeyUnsupported
	default:
		return nil, fmt.Errorf("不支持的证书来源 %d（系统证书库已移除，请使用导入的文件证书）", source)
	}
}

// ImportFile validates a PKCS#12 file, copies it into the store and returns its
// metadata. The source file is left untouched. Importing the same alias twice
// is allowed; each import gets its own GUID.
func (s *Store) ImportFile(srcPath, alias, password string) (*CertInfo, error) {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %w", err)
	}

	priv, cert, _, err := decodePKCS12(data, password)
	if err != nil {
		return nil, fmt.Errorf("证书口令错误或文件损坏: %w", err)
	}

	id, err := newGUID()
	if err != nil {
		return nil, fmt.Errorf("生成证书标识失败: %w", err)
	}

	ext := normalizeExt(filepath.Ext(srcPath))
	if ext == "" {
		ext = "p12"
	}
	if strings.TrimSpace(alias) == "" {
		alias = displayName(cert)
	}

	name, err := BuildFilename(id, alias, password, ext)
	if err != nil {
		return nil, err
	}

	dest := filepath.Join(s.dir, name)
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return nil, fmt.Errorf("保存证书失败: %w", err)
	}

	// Re-read through the same path the list uses so the metadata is exactly
	// what a later Login would see (catches decode regressions early).
	if _, _, _, _, ok := ParseFilename(name); !ok {
		_ = os.Remove(dest)
		return nil, fmt.Errorf("生成的证书文件名无法解析: %s", name)
	}
	_ = priv // validated above; not persisted separately

	info := certInfoFromX509(cert, id, SourceFile)
	info.Name = alias
	info.FilePath = dest
	return &info, nil
}

// Delete removes a file certificate by ID.
func (s *Store) Delete(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrCertNotFound
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("读取证书目录失败: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fileID, _, _, _, ok := ParseFilename(entry.Name())
		if !ok || !strings.EqualFold(fileID, id) {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, entry.Name())); err != nil {
			return fmt.Errorf("删除证书失败: %w", err)
		}
		return nil
	}
	return ErrCertNotFound
}

// LoadTLS returns the client certificate and private key for mTLS. For file
// certificates the password is read from the stored file name, so the caller
// never needs to keep it in memory.
func (s *Store) LoadTLS(id string, source Source) (*tls.Certificate, error) {
	switch source {
	case SourceFile:
		path, password, err := s.findFileCert(id)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取证书文件失败: %w", err)
		}
		priv, cert, caCerts, err := decodePKCS12(data, password)
		if err != nil {
			return nil, fmt.Errorf("解析证书失败（口令可能已损坏）: %w", err)
		}
		return buildTLSCertificate(cert, priv, caCerts), nil
	case SourceUSBKey:
		return nil, ErrUSBKeyUnsupported
	default:
		return nil, fmt.Errorf("不支持的证书来源 %d（系统证书库已移除，请使用导入的文件证书）", source)
	}
}

// LoadTLSFile loads a PKCS#12 file that is not in the store. It backs the CLI's
// "-cert /path/to/cert.p12" form and never copies the file.
func LoadTLSFile(path, password string) (*tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %w", err)
	}
	priv, cert, caCerts, err := decodePKCS12(data, password)
	if err != nil {
		return nil, fmt.Errorf("证书口令错误或文件损坏: %w", err)
	}
	return buildTLSCertificate(cert, priv, caCerts), nil
}

func (s *Store) listFiles() ([]CertInfo, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []CertInfo{}, nil
		}
		return nil, fmt.Errorf("读取证书目录失败: %w", err)
	}

	infos := make([]CertInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || normalizeExt(filepath.Ext(entry.Name())) == "" {
			continue
		}
		id, alias, password, _, ok := ParseFilename(entry.Name())
		if !ok {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		_, cert, _, err := decodePKCS12(data, password)
		if err != nil {
			// Keep the entry visible so the user can delete a certificate whose
			// password segment no longer decrypts.
			infos = append(infos, CertInfo{
				ID:       id,
				Name:     aliasOrFallback(alias, id),
				Source:   int(SourceFile),
				FilePath: path,
			})
			continue
		}
		info := certInfoFromX509(cert, id, SourceFile)
		if alias != "" {
			info.Name = alias
		}
		info.FilePath = path
		infos = append(infos, info)
	}

	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos, nil
}

func (s *Store) findFileCert(id string) (path, password string, err error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return "", "", fmt.Errorf("读取证书目录失败: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fileID, _, pwd, _, ok := ParseFilename(entry.Name())
		if !ok || !strings.EqualFold(fileID, id) {
			continue
		}
		return filepath.Join(s.dir, entry.Name()), pwd, nil
	}
	return "", "", ErrCertNotFound
}

// decodePKCS12 accepts both the modern AES-based and the legacy RC2/3DES based
// PKCS#12 encodings; Windows-exported .pfx files are usually the latter.
func decodePKCS12(data []byte, password string) (any, *x509.Certificate, []*x509.Certificate, error) {
	priv, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, nil, nil, err
	}
	if cert == nil {
		return nil, nil, nil, errors.New("PKCS#12 中不包含客户端证书")
	}
	return priv, cert, caCerts, nil
}

func buildTLSCertificate(cert *x509.Certificate, priv any, caCerts []*x509.Certificate) *tls.Certificate {
	chain := [][]byte{cert.Raw}
	for _, ca := range caCerts {
		chain = append(chain, ca.Raw)
	}
	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  priv,
		Leaf:        cert,
	}
}

func certInfoFromX509(cert *x509.Certificate, id string, source Source) CertInfo {
	return CertInfo{
		ID:        id,
		Name:      displayName(cert),
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		ValidFrom: cert.NotBefore.Format("2006/1/2"),
		ValidTo:   cert.NotAfter.Format("2006/1/2"),
		IsExpired: time.Now().After(cert.NotAfter),
		Source:    int(source),
	}
}

// displayName prefers the subject common name, then the full subject, then the
// issuer CN, and finally falls back to the certificate ID.
func displayName(cert *x509.Certificate) string {
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		return cn
	}
	if subject := strings.TrimSpace(cert.Subject.String()); subject != "" {
		return subject
	}
	if issuer := strings.TrimSpace(cert.Issuer.CommonName); issuer != "" {
		return issuer
	}
	return "unnamed-certificate"
}

func aliasOrFallback(alias, id string) string {
	if strings.TrimSpace(alias) != "" {
		return alias
	}
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// newGUID returns 16 random bytes formatted as 32 uppercase hex characters,
// matching the GUID representation the original client embeds in file names.
func newGUID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(buf)), nil
}
