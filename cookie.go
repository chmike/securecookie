package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

// KeyLen is the byte length of the key.
const KeyLen = 32

// GenerateRandomKey return a random key of KeyLen bytes.
// Use hex.EncodeToString(key) to get the key as hexadecimal string,
// and hex.DecodeString(keyStr) to convert back from string to byte slice.
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil || forceError {
		return nil, err
	}
	return key, nil
}

// An Params holds the cookie parameters. Use BytesToString() to convert
// a []byte value to a string value without allocation and data copy, but
// it requires that the value is not modified after the conversion.
// To delete a cookie, set expire in the past and the path and domain
// that are in the cookie to delete.
type Params struct {
	Name     string // Name of the cookie
	Value    string // Clear text value to store in the cookie
	Path     string // Optional : URL path to which the cookie will be returned
	Domain   string // Optional : domain to which the cookie will be returned
	MaxAge   uint   // Optional : second offset from now, 0 is undefined
	HTTPOnly bool   // Optional : disallow access to the cookie by user agent scripts
	Secure   bool   // Optional : cookie can only be send over HTTPS connections
}

// Check return nil if the cookie fields are all valid.
func Check(c *Params) error {
	if err := CheckName(c.Name); err != nil {
		return err
	}
	if err := CheckPath(c.Path); err != nil {
		return err
	}
	if err := CheckDomain(c.Domain); err != nil {
		return err
	}
	return nil
}

// CheckName return an error if the cookie name is invalid.
func CheckName(name string) error {
	if len(name) == 0 {
		return errors.New("cookie name: empty value")
	}
	if err := checkChars(name, isValidNameChar); err != nil {
		return fmt.Errorf("cookie name: %s", err)
	}
	return nil
}

// CheckPath return an error if the cookie path is invalid
func CheckPath(path string) error {
	if err := checkChars(path, isValidPathChar); err != nil {
		return fmt.Errorf("cookie path: %s", err)
	}
	return nil
}

// CheckDomain return an error if the domain name is not valid.
// See https://tools.ietf.org/html/rfc1034#section-3.5 and
// https://tools.ietf.org/html/rfc1123#section-2.
func CheckDomain(name string) error {
	if len(name) > 255 {
		return fmt.Errorf("cookie domain: name length is %d, can't exceed 255", len(name))
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '.' {
			if i == 0 {
				return errors.New("cookie domain: start with '.'")
			}
			if pc := name[i-1]; pc == '-' || pc == '.' {
				return fmt.Errorf("cookie domain: invalid character '%c' at offset %d", pc, i-1)
			}
			if i == len(name)-1 {
				return errors.New("cookie domain: ends with '.'")
			}
			if nc := name[i+1]; nc == '-' {
				return fmt.Errorf("cookie domain: invalid character '%c' at offset %d", nc, i+1)
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c <= 'A' && c >= 'Z') || (c >= 'a' && c <= 'z')) {
			if c < ' ' || c == 0x7F {
				return fmt.Errorf("cookie domain: invalid character %#02X at offset %d", c, i)
			}
			return fmt.Errorf("cookie domain: invalid character '%c' at offset %d", c, i)
		}
	}
	return nil
}

func isValidNameChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '!' || (c >= '#' && c < '(') || c == '*' || c == '+' || c == '-' ||
		c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~'
}

func isValidPathChar(c byte) bool {
	return (c >= ' ' && c < 0x7F) && c != ';'
}

func checkChars(s string, isValid func(c byte) bool) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isValid(c) {
			if c < ' ' || c >= 0x7F {
				return fmt.Errorf("invalid character %#02X at offset %d", c, i)
			}
			return fmt.Errorf("invalid character '%c' at offset %d", c, i)
		}
	}
	return nil
}

var dfltTime = time.Time{}

// SetSecure adds the given cookie to the server's response. The cokie value is
// encrypted and encoded in base64. Assume that c.Check() has returned nil.
func SetSecure(w http.ResponseWriter, c *Params, key []byte) error {
	bPtr := bufPool.Get().(*[]byte)
	b := *bPtr
	defer func() { *bPtr = b; bufPool.Put(bPtr) }()
	maxLen := len(c.Name) + 1 + EncodedValueLen(len(c.Value))
	if len(c.Path) > 0 {
		maxLen += 7 + len(c.Path)
	}
	if len(c.Domain) > 0 {
		maxLen += 9 + len(c.Domain)
	}
	if c.MaxAge > 0 {
		maxLen += 30
	}
	if c.HTTPOnly {
		maxLen += 10
	}
	if c.Secure {
		maxLen += 8
	}
	if cap(b) < maxLen {
		b = make([]byte, 0, maxLen+20)
	}
	var pos int
	b = b[:maxLen]
	pos += copy(b[pos:], c.Name)
	pos += copy(b[pos:], "=")
	encVal, err := encodeValue(b[pos:], *(*string)(unsafe.Pointer(&c.Value)), key)
	if err != nil {
		return err
	}
	pos += len(encVal)
	if len(c.Path) > 0 {
		pos += copy(b[pos:], "; Path=")
		pos += copy(b[pos:], c.Path)
	}
	if len(c.Domain) > 0 {
		pos += copy(b[pos:], "; Domain=")
		pos += copy(b[pos:], c.Domain)
	}
	if c.MaxAge > 0 {
		pos += copy(b[pos:], "; Max-Age=")
		pos = len(strconv.AppendInt(b[:pos], int64(c.MaxAge), 10))
	}
	if c.HTTPOnly {
		pos += copy(b[pos:], "; HttpOnly")
	}
	if c.Secure {
		pos += copy(b[pos:], "; Secure")
	}
	b = b[:pos]
	w.Header().Add("Set-Cookie", *(*string)(unsafe.Pointer(&b)))
	return nil
}

var bufPool = sync.Pool{New: func() interface{} { b := make([]byte, 64); return &b }}

// EncodedValueLen return the encoded byte length of the value of valLen bytes.
func EncodedValueLen(valLen int) int {
	l := valLen + 5 + macLen
	return ((l-l%3)*8 + 5) / 6
}

// encodeValue encodes the value in dst overriding it's content.
// Requires: cap(dst) >= EncodedValLen(len(val))
func encodeValue(dst []byte, val string, key []byte) ([]byte, error) {
	nRnd := 5 - (len(val)+5+macLen)%3
	msgLen := len(val) + nRnd
	if cap(dst) < ((msgLen+macLen)*8+5)/6 {
		return nil, errors.New("would overflow")
	}
	dst = dst[:msgLen]
	if _, err := io.ReadFull(rand.Reader, dst[copy(dst, val):]); err != nil || forceError {
		return nil, err
	}
	dst[len(dst)-1] = (dst[len(dst)-1] & 0xFC) | byte(nRnd)%3
	mac := hmac.New(md5.New, key[:macLen])
	mac.Write(dst)
	msg := dst
	dst = mac.Sum(dst)
	block, err := aes.NewCipher(key[macLen:])
	if err != nil {
		return nil, err
	}
	iv := dst[msgLen:]
	block.Encrypt(iv, iv)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(msg, msg)
	return encodeBase64(dst, dst)
}

// macLen is the byte length of the MAC.
const macLen = md5.Size

// encodeBase64 encodes src into dst in base64. src and dst may overlabe same slice.
// Requires: cap(dst) >= (len(src)*8+5)/6 && len(src)%3 == 0.
func encodeBase64(dst, src []byte) ([]byte, error) {
	if len(src)%3 != 0 {
		return nil, errors.New("invalid src size")
	}
	srcIdx, dstIdx := len(src), (len(src)*8+5)/6
	if cap(dst) < dstIdx {
		return nil, errors.New("would overflow")
	}
	dst = dst[:dstIdx]
	for srcIdx > 0 {
		srcIdx--
		v := uint64(src[srcIdx])
		srcIdx--
		v |= uint64(src[srcIdx]) << 8
		srcIdx--
		v |= uint64(src[srcIdx]) << 16
		dstIdx--
		dst[dstIdx] = base64Char(byte(v))
		dstIdx--
		dst[dstIdx] = base64Char(byte(v >> 6))
		dstIdx--
		dst[dstIdx] = base64Char(byte(v >> 12))
		dstIdx--
		dst[dstIdx] = base64Char(byte(v >> 18))
	}
	return dst, nil
}

// base64Char converts a byte to Base64 URL encoding character.
// The two most significant bits of the input byte are ignored.
// See https://tools.ietf.org/html/rfc4648#section-5.
func base64Char(b byte) byte {
	b &= 0x3F
	if b < 26 {
		return b + 'A'
	} else if b < 52 {
		return b + 'a' - 26
	} else if b < 62 {
		return b + '0' - 52
	} else if b == 62 {
		return '-'
	}
	return '_' // b == 63
}

// GetSecureValue get decoded value of cookie named name.
// Use BytesToString() if you need a string instead of a byte slice.
func GetSecureValue(r *http.Request, name string, key []byte) ([]byte, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return nil, err
	}
	return decodeValue(c.Value, key)
}

// decodeValue decode the encoded cookie value.
// Requires: cap(dst) >= (len(src)*6)/8 && len(src)%4 == 0.
func decodeValue(val string, key []byte) ([]byte, error) {
	if len(val) < 28 {
		return nil, errors.New("invalid value length")
	}
	if len(key) < macLen {
		return nil, errors.New("invalid key")
	}
	b := make([]byte, (len(val)*6)/8)
	if _, err := decodeBase64(b, val); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[macLen:])
	if err != nil {
		return nil, err
	}
	msgLen := len(b) - macLen
	msg, iv := b[:msgLen], b[msgLen:]
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(msg, msg)
	block.Decrypt(iv, iv)
	mac := hmac.New(md5.New, key[:macLen])
	mac.Write(msg)
	if !hmac.Equal(iv, mac.Sum(nil)) {
		return nil, errors.New("MAC mismatch")
	}
	nRnd := int(3 + msg[msgLen-1]&0x3)
	if nRnd == 6 {
		return nil, errors.New("invalid number of random bytes")
	}
	return msg[:msgLen-nRnd], nil
}

// decodeBase64 decode src into dst. src and dst may be the same slice.
// Requires len(src)%4 == 0 && cap(dst) >= (len(src)*6)/8.
func decodeBase64(dst []byte, src string) ([]byte, error) {
	if len(src)%4 != 0 {
		return nil, errors.New("invalid src size")
	}
	decLen := (len(src) * 6) / 8
	if cap(dst) < decLen {
		return nil, errors.New("would overflow")
	}
	var srcIdx, dstIdx int
	dst = dst[:decLen]
	for srcIdx < len(src) {
		var v uint64
		for i := 0; i < 4; i++ {
			b := src[srcIdx]
			if b >= 'A' && b <= 'Z' {
				v = (v << 6) | uint64(b-'A')
			} else if b >= 'a' && b <= 'z' {
				v = (v << 6) | uint64(b-'a'+26)
			} else if b >= '0' && b <= '9' {
				v = (v << 6) | uint64(b-'0'+52)
			} else if b == '-' {
				v = (v << 6) | uint64(62)
			} else if b == '_' {
				v = (v << 6) | uint64(63)
			} else {
				return nil, errors.New("invalid base64 char")
			}
			srcIdx++
		}
		dst[dstIdx] = byte(v >> 16)
		dstIdx++
		dst[dstIdx] = byte(v >> 8)
		dstIdx++
		dst[dstIdx] = byte(v)
		dstIdx++
	}
	return dst, nil
}

var forceError bool // for 100% test coverage

// BytesToString converts a byte slice to a string without
// making a copy. It is safe if, and only if, the byte slice
// is not modified during the lifetime of the string.
// See: https://syslog.ravelin.com/byte-vs-string-in-go-d645b67ca7ff
func BytesToString(bs []byte) string {
	// This is copied from runtime. It relies on the string
	// header being a prefix of the slice header!
	return *(*string)(unsafe.Pointer(&bs))
}

// Delete send a request to the remote user agent to delete the given
// cookie. Don't rely on the assumption that the user agent will delete
// the cookie. This function will at least clear the value.
// The specification requires that the cookie name, it's path and domain
// are provided. The Value, the Expires, MaxAge
func Delete(w http.ResponseWriter, c *Params) error {
	maxLen := len(c.Name) + 1
	if len(c.Path) > 0 {
		maxLen += 7 + len(c.Path)
	}
	if len(c.Domain) > 0 {
		maxLen += 9 + len(c.Domain)
	}
	maxLen += 30
	if c.HTTPOnly {
		maxLen += 10
	}
	if c.Secure {
		maxLen += 8
	}
	bPtr := bufPool.Get().(*[]byte)
	b := *bPtr
	defer func() { *bPtr = b; bufPool.Put(bPtr) }()
	if cap(b) < maxLen {
		b = make([]byte, 0, maxLen)
	}
	var pos int
	b = b[:maxLen]
	pos += copy(b[pos:], c.Name)
	pos += copy(b[pos:], "=")
	if len(c.Path) > 0 {
		pos += copy(b[pos:], "; Path=")
		pos += copy(b[pos:], c.Path)
	}
	if len(c.Domain) > 0 {
		pos += copy(b[pos:], "; Domain=")
		pos += copy(b[pos:], c.Domain)
	}
	dateInThePast := time.Now().Add(-365 * 24 * time.Hour)
	pos += copy(b[pos:], "; Expires=")
	pos = len(dateInThePast.UTC().AppendFormat(b[:pos], "Jan 2 15:04:05 2006"))
	if c.HTTPOnly {
		pos += copy(b[pos:], "; HttpOnly")
	}
	if c.Secure {
		pos += copy(b[pos:], "; Secure")
	}
	b = b[:pos]
	w.Header().Add("Set-Cookie", *(*string)(unsafe.Pointer(&b)))
	return nil
}
