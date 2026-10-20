//go:build windows

package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CryptoAPI constants missing from x/sys/windows.
const (
	certHasPrivateKeyPropID     = 65
	certNcryptKeySpec           = 0xFFFFFFFF
	cryptAcquireSilentFlag      = 0x00000040
	cryptAcquireAllowNcryptFlag = 0x00010000
	atSignature                 = 2
	hpHashValue                 = 2
	calgSHA256                  = 0x0000800C
	calgSHA1                    = 0x00008004
)

var (
	crypt32                     = windows.NewLazySystemDLL("crypt32.dll")
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	ncrypt                      = windows.NewLazySystemDLL("ncrypt.dll")
	procCertGetContextProperty  = crypt32.NewProc("CertGetCertificateContextProperty")
	procCryptAcquireCertPrivKey = crypt32.NewProc("CryptAcquireCertificatePrivateKey")
	procCryptCreateHash         = advapi32.NewProc("CryptCreateHash")
	procCryptSetHashParam       = advapi32.NewProc("CryptSetHashParam")
	procCryptSignHash           = advapi32.NewProc("CryptSignHashW")
	procCryptDestroyHash        = advapi32.NewProc("CryptDestroyHash")
	procCryptReleaseContext     = advapi32.NewProc("CryptReleaseContext")
	procNCryptSignHash          = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject        = ncrypt.NewProc("NCryptFreeObject")
)

func listSystemCerts() ([]CertInfo, error) {
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return nil, err
	}
	store, err := windows.CertOpenSystemStore(0, storeName)
	if err != nil {
		return nil, fmt.Errorf("打开系统证书库失败: %w", err)
	}
	defer windows.CertCloseStore(store, 0)

	infos := []CertInfo{}
	var ctx *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(store, ctx)
		if next == nil {
			// Normal end of enumeration: CryptoAPI returns NULL and sets
			// CRYPT_E_NOT_FOUND (0x80092004) or ERROR_NO_MORE_FILES (0x12).
			break
		}
		if err != nil {
			return nil, fmt.Errorf("枚举系统证书失败: %w", err)
		}
		ctx = next
		if ctx.EncodedCert == nil {
			break
		}
		der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		// A certificate without an accessible private key cannot be used for
		// mTLS, so it is not worth showing.
		if !hasPrivateKey(ctx) {
			continue
		}
		id := sha1Hex(cert.Raw)
		info := certInfoFromX509(cert, id, SourceSystem)
		infos = append(infos, info)
	}

	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos, nil
}

func loadSystemCert(id string) (*tls.Certificate, error) {
	want := strings.ToUpper(strings.TrimSpace(id))
	if want == "" {
		return nil, ErrCertNotFound
	}

	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return nil, err
	}
	store, err := windows.CertOpenSystemStore(0, storeName)
	if err != nil {
		return nil, fmt.Errorf("打开系统证书库失败: %w", err)
	}
	defer windows.CertCloseStore(store, 0)

	var ctx *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(store, ctx)
		if next == nil {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("枚举系统证书失败: %w", err)
		}
		ctx = next
		if ctx.EncodedCert == nil {
			break
		}
		der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if !strings.EqualFold(sha1Hex(cert.Raw), want) {
			continue
		}

		// Duplicate the context: the enumerator owns the returned pointer and
		// frees it on the next call.
		owned := windows.CertDuplicateCertificateContext(ctx)
		if owned == nil {
			return nil, fmt.Errorf("复制证书上下文失败")
		}
		signer := &systemSigner{cert: cert, ctx: owned}
		chain := [][]byte{cert.Raw}
		return &tls.Certificate{
			Certificate: chain,
			PrivateKey:  signer,
			Leaf:        cert,
		}, nil
	}
	return nil, ErrCertNotFound
}

func hasPrivateKey(ctx *windows.CertContext) bool {
	var value uint32
	size := uint32(unsafe.Sizeof(value))
	r, _, _ := procCertGetContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		certHasPrivateKeyPropID,
		uintptr(unsafe.Pointer(&value)),
		uintptr(unsafe.Pointer(&size)),
	)
	return r != 0 && value != 0
}

func sha1Hex(der []byte) string {
	sum := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// systemSigner implements crypto.Signer on top of a Windows certificate context.
// It acquires the private key for each signature, which keeps no long-lived
// handles around and works for both CNG keys and legacy CSP keys.
type systemSigner struct {
	cert *x509.Certificate
	ctx  *windows.CertContext
}

func (s *systemSigner) Public() crypto.PublicKey { return s.cert.PublicKey }

// Sign signs digest with the certificate's private key.
//
// The Windows APIs expect the digest in the signature padding scheme the TLS
// stack selected, so the padding info mirrors opts: RSA-PKCS1v15, RSA-PSS or
// ECDSA. crypto.Signer requires ASN.1 DER for ECDSA, while CNG emits raw r||s,
// so the ECDSA result is re-encoded here.
func (s *systemSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlg := uint32(calgSHA256)
	if opts != nil && opts.HashFunc() == crypto.SHA1 {
		hashAlg = calgSHA1
	}

	// Prefer CNG: it supports RSA-PSS and ECDSA and is what modern keys use.
	sig, errNCrypt := s.signCNG(digest, opts)
	if errNCrypt == nil {
		return sig, nil
	}

	// Fall back to a legacy CryptoAPI CSP for RSA-PKCS1v15 keys.
	if _, ok := s.cert.PublicKey.(*rsa.PublicKey); ok {
		if _, pss := opts.(*rsa.PSSOptions); !pss {
			sig, err := s.signCAPI(digest, hashAlg)
			if err == nil {
				return sig, nil
			}
			return nil, fmt.Errorf("系统证书私钥签名失败: %w", err)
		}
	}
	return nil, fmt.Errorf("系统证书私钥签名失败: %w", errNCrypt)
}

// io_ was a placeholder for the crypto.Signer rand parameter; Sign now uses
// io.Reader directly, so no alias is needed.

type bcryptPKCS1PaddingInfo struct {
	pszAlgID *uint16
}

type bcryptPSSPaddingInfo struct {
	pszAlgID *uint16
	cbSalt   uint32
}

func (s *systemSigner) signCNG(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var keyHandle windows.Handle
	var keySpec uint32
	var free bool
	r, _, callErr := procCryptAcquireCertPrivKey.Call(
		uintptr(unsafe.Pointer(s.ctx)),
		cryptAcquireSilentFlag|cryptAcquireAllowNcryptFlag,
		0,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(&keySpec)),
		uintptr(unsafe.Pointer(&free)),
	)
	if r == 0 {
		return nil, callErr
	}
	if free {
		defer procNCryptFreeObject.Call(uintptr(keyHandle))
	}
	if keySpec != certNcryptKeySpec {
		return nil, errors.New("证书私钥位于旧版 CSP 中")
	}

	var padding uintptr
	var flags uint32
	algName := "SHA256"
	if opts != nil && opts.HashFunc() == crypto.SHA1 {
		algName = "SHA1"
	}

	switch pub := s.cert.PublicKey.(type) {
	case *rsa.PublicKey:
		algPtr, _ := windows.UTF16PtrFromString(algName)
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			// rsa.PSSSaltLengthEqualsHash (-1) and Auto (-2) both mean "salt
			// length equals the digest length" for the NCrypt layer.
			salt := uint32(len(digest))
			if pss.SaltLength > 0 {
				salt = uint32(pss.SaltLength)
			}
			info := bcryptPSSPaddingInfo{pszAlgID: algPtr, cbSalt: salt}
			padding = uintptr(unsafe.Pointer(&info))
			flags = 1 // BCRYPT_PAD_PSS
		} else {
			info := bcryptPKCS1PaddingInfo{pszAlgID: algPtr}
			padding = uintptr(unsafe.Pointer(&info))
			flags = 2 // BCRYPT_PAD_PKCS1
		}
	case *ecdsa.PublicKey:
		var curveAlg string
		switch pub.Curve {
		case elliptic.P256():
			curveAlg = "ECDSA_P256"
		case elliptic.P384():
			curveAlg = "ECDSA_P384"
		case elliptic.P521():
			curveAlg = "ECDSA_P521"
		default:
			return nil, fmt.Errorf("不支持的 ECDSA 曲线 %s", pub.Curve.Params().Name)
		}
		algPtr, _ := windows.UTF16PtrFromString(curveAlg)
		padding = uintptr(unsafe.Pointer(algPtr))
	default:
		return nil, fmt.Errorf("不支持的系统证书公钥类型 %T", pub)
	}

	var sigLen uint32
	r, _, callErr = procNCryptSignHash.Call(
		uintptr(keyHandle),
		padding,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(flags),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash 长度探测失败: %w", callErr)
	}

	sig := make([]byte, sigLen)
	r, _, callErr = procNCryptSignHash.Call(
		uintptr(keyHandle),
		padding,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(flags),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash 失败: %w", callErr)
	}
	sig = sig[:sigLen]

	if _, ok := s.cert.PublicKey.(*ecdsa.PublicKey); ok {
		return ecdsaRawToDER(sig)
	}
	return sig, nil
}

func (s *systemSigner) signCAPI(digest []byte, hashAlg uint32) ([]byte, error) {
	var prov windows.Handle
	var keySpec uint32
	var free bool
	r, _, callErr := procCryptAcquireCertPrivKey.Call(
		uintptr(unsafe.Pointer(s.ctx)),
		cryptAcquireSilentFlag,
		0,
		uintptr(unsafe.Pointer(&prov)),
		uintptr(unsafe.Pointer(&keySpec)),
		uintptr(unsafe.Pointer(&free)),
	)
	if r == 0 {
		return nil, callErr
	}
	if free {
		defer procCryptReleaseContext.Call(uintptr(prov), 0)
	}

	var hash windows.Handle
	r, _, callErr = procCryptCreateHash.Call(uintptr(prov), uintptr(hashAlg), 0, 0, uintptr(unsafe.Pointer(&hash)))
	if r == 0 {
		return nil, callErr
	}
	defer procCryptDestroyHash.Call(uintptr(hash))

	r, _, callErr = procCryptSetHashParam.Call(
		uintptr(hash), hpHashValue, uintptr(unsafe.Pointer(&digest[0])), 0,
	)
	if r == 0 {
		return nil, callErr
	}

	var sigLen uint32
	r, _, callErr = procCryptSignHash.Call(
		uintptr(hash), atSignature, 0, 0, 0, uintptr(unsafe.Pointer(&sigLen)),
	)
	if r == 0 {
		return nil, callErr
	}
	sig := make([]byte, sigLen)
	r, _, callErr = procCryptSignHash.Call(
		uintptr(hash), atSignature, 0, 0,
		uintptr(unsafe.Pointer(&sig[0])), uintptr(unsafe.Pointer(&sigLen)),
	)
	if r == 0 {
		return nil, callErr
	}
	return sig[:sigLen], nil
}

// ecdsaRawToDER converts the fixed-width r||s signature returned by CNG into
// the ASN.1 DER form crypto.Signer requires.
func ecdsaRawToDER(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("ECDSA 签名长度非法: %d", len(raw))
	}
	half := len(raw) / 2
	return asn1.Marshal(struct {
		R, S *big.Int
	}{
		R: new(big.Int).SetBytes(raw[:half]),
		S: new(big.Int).SetBytes(raw[half:]),
	})
}
