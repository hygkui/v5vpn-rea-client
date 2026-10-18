package protocol

import (
	"bytes"
	"io"
	"regexp"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// xmlEncodingDecl matches the encoding attribute in an XML declaration.
// encoding/xml rejects any charset other than UTF-8 unless a CharsetReader
// is installed, even after the body itself has been decoded.
var xmlEncodingDecl = regexp.MustCompile(`(?i)(<\?xml\b[^>]*?\bencoding\s*=\s*["'])[^"']*(["'])`)

// ensureUTF8 decodes a gateway body that is either UTF-8 or legacy GBK/GB18030.
// LeadSec gateways often label auth XML as gb2312. Go's XML decoder expects
// UTF-8 and rejects the raw GBK bytes, which used to hide the real result message.
func ensureUTF8(data []byte) []byte {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if utf8.Valid(data) {
		return data
	}

	reader := transform.NewReader(bytes.NewReader(data), simplifiedchinese.GBK.NewDecoder())
	if decoded, err := io.ReadAll(reader); err == nil && utf8.Valid(decoded) {
		return decoded
	}

	reader18030 := transform.NewReader(bytes.NewReader(data), simplifiedchinese.GB18030.NewDecoder())
	if decoded, err := io.ReadAll(reader18030); err == nil && utf8.Valid(decoded) {
		return decoded
	}
	return data
}

// prepareGatewayXML returns UTF-8 XML that encoding/xml will accept.
func prepareGatewayXML(data []byte) []byte {
	data = ensureUTF8(data)
	return xmlEncodingDecl.ReplaceAll(data, []byte("${1}UTF-8${2}"))
}
