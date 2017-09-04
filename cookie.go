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
	b = append(b[:0], c.Name...)
	b = append(b, '=')
	b, err := appendEncodedValue(b, *(*string)(unsafe.Pointer(&c.Value)), key)
	if err != nil {
		return err
	}
	if len(c.Path) > 0 {
		b = append(b, "; Path="...)
		b = append(b, c.Path...)
	}
	if len(c.Domain) > 0 {
		b = append(b, "; Domain="...)
		b = append(b, c.Domain...)
	}
	if c.MaxAge > 0 {
		b = append(b, "; Max-Age="...)
		b = strconv.AppendInt(b, int64(c.MaxAge), 10)
	}
	if c.HTTPOnly {
		b = append(b, "; HttpOnly"...)
	}
	if c.Secure {
		b = append(b, "; Secure"...)
	}
	w.Header().Add("Set-Cookie", *(*string)(unsafe.Pointer(&b)))
	return nil
}

var bufPool = sync.Pool{New: func() interface{} { b := make([]byte, 64); return &b }}

// encodedValueLen return the encoded byte length of the value of valLen bytes.
func encodedValueLen(valLen int) int {
	l := valLen + 5 + macLen
	return ((l-l%3)*8 + 5) / 6
}

// appendEncodedValue appends the encoded value val to dst.
// dst is allocated or grown if it is nil or too small.
// Return dst and the error if any.
func appendEncodedValue(dst []byte, val string, key []byte) ([]byte, error) {
	encLen := encodedValueLen(len(val))
	if cap(dst)-len(dst) < encLen {
		tmp := make([]byte, len(dst), getBufSize(len(dst)+encLen))
		copy(tmp, dst)
		dst = tmp
	}
	msgLen := len(val) + 5 + macLen
	msgLen -= macLen + msgLen%3
	buf := dst[len(dst) : len(dst)+msgLen]
	rnd := buf[copy(buf, val):]
	if _, err := io.ReadFull(rand.Reader, rnd); err != nil || forceError {
		return dst, err
	}
	rnd[len(rnd)-1] = (rnd[len(rnd)-1] & 0xFC) | byte(len(rnd))%3
	mac := hmac.New(md5.New, key[:macLen])
	mac.Write(buf)
	msg := buf
	buf = mac.Sum(buf)
	block, err := aes.NewCipher(key[macLen:])
	if err != nil {
		return dst, err
	}
	iv := buf[msgLen:]
	block.Encrypt(iv, iv)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(msg, msg)
	return appendEncodedBase64(dst, buf)
}

// getBufSize return the smallest power 2 bigger or equal to v.
// See https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
func getBufSize(v int) int {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v |= v >> 32
	v++
	return v
}

// macLen is the byte length of the MAC.
const macLen = md5.Size

// appendEncodedBase64 appends the base64 encoding of src to dst.
// dst is allocated or grown if it is nil or too small.
// Return dst and the error if any. Requires len(src)%3 == 0.
func appendEncodedBase64(dst, src []byte) ([]byte, error) {
	if len(src)%3 != 0 {
		return dst, errors.New("invalid src size")
	}
	srcIdx, dstIdx := len(src), len(dst)+(len(src)*8+5)/6
	if cap(dst) < dstIdx {
		tmp := make([]byte, len(dst), getBufSize(dstIdx))
		copy(tmp, dst)
		dst = tmp
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
// The two most significant bits of b are ignored.
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

// GetSecureValue append the decoded value of the cookie named name to dst.
// dst is allocated or grown if it is nil or too small.
// Return dst and the error if any.
// Use BytesToString() if you need a string instead of a byte slice.
func GetSecureValue(dst []byte, r *http.Request, name string, key []byte) ([]byte, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return nil, err
	}
	return appendDecodedValue(dst, c.Value, key)
}

// appendDecodedValue decode encVal and append the result to dst.
// dst is allocated or grown if it is nil or too small.
// Return dst and the error if any. Requires len(src)%4 == 0.
// Requires: len(encVal) >= 28 && len(src)%4 == 0.
func appendDecodedValue(dst []byte, encVal string, key []byte) ([]byte, error) {
	if len(encVal) < 28 {
		return dst, errors.New("invalid value length")
	}
	if len(key) < macLen {
		return dst, errors.New("invalid key")
	}
	valPos := len(dst)
	b, err := appendDecodedBase64(dst, encVal)
	dst, b = b[:valPos], b[valPos:]
	if err != nil {
		return dst, err
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
	return dst[:valPos+msgLen-nRnd], nil
}

// appendDecodedBase64 base64 decode src and append the result to dst.
// dst is allocated or grown if it is nil or too small.
// Return dst and the error if any. Requires len(src)%4 == 0.
func appendDecodedBase64(dst []byte, src string) ([]byte, error) {
	if len(src)%4 != 0 {
		return dst, errors.New("invalid src size")
	}
	decLen := (len(src) * 6) / 8
	if cap(dst)-len(dst) < decLen {
		tmp := make([]byte, len(dst), getBufSize(len(dst)+decLen))
		copy(tmp, dst)
		dst = tmp
	}
	var srcIdx int
	dstIdx := len(dst)
	dst = dst[:len(dst)+decLen]
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
	maxLen += 29
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
	b = append(b[:0], c.Name...)
	b = append(b, '=')
	if len(c.Path) > 0 {
		b = append(b, "; Path="...)
		b = append(b, c.Path...)
	}
	if len(c.Domain) > 0 {
		b = append(b, "; Domain="...)
		b = append(b, c.Domain...)
	}
	b = append(b, "; Expires=Jan 2 15:04:05 2006"...)
	if c.HTTPOnly {
		b = append(b, "; HttpOnly"...)
	}
	if c.Secure {
		b = append(b, "; Secure"...)
	}
	w.Header().Add("Set-Cookie", *(*string)(unsafe.Pointer(&b)))
	return nil
}
