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
	Path     string // Optional : URL path to which the cookie will be returned
	Domain   string // Optional : domain to which the cookie will be returned
	MaxAge   int    // Optional : time offset in seconds from now, must be > 0
	HTTPOnly bool   // Optional : disallow access to the cookie by user agent scripts
	Secure   bool   // Optional : cookie can only be send over HTTPS connections
}

// Obj is a validated cookie object.
type Obj struct {
	key      []byte
	name     string
	path     string
	domain   string
	maxAge   int
	httpOnly bool
	secure   bool
}

// New instantiate a validated cookie parameter field set with an associated key.
func New(name string, key []byte, p Params) (*Obj, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("key length is %d, expected %d", len(key), KeyLen)
	}
	if err := checkName(name); err != nil {
		return nil, err
	}
	if err := checkPath(p.Path); err != nil {
		return nil, err
	}
	if err := checkDomain(p.Domain); err != nil {
		return nil, err
	}
	if p.MaxAge < 0 {
		return nil, errors.New("max age can't be negative")
	}
	return &Obj{
		key:      key,
		name:     name,
		path:     p.Path,
		domain:   p.Domain,
		maxAge:   p.MaxAge,
		httpOnly: p.HTTPOnly,
		secure:   p.Secure,
	}, nil
}

// checkName return an error if the cookie name is invalid.
func checkName(name string) error {
	if len(name) == 0 {
		return errors.New("cookie name: empty value")
	}
	if err := checkChars(name, isValidNameChar); err != nil {
		return fmt.Errorf("cookie name: %s", err)
	}
	return nil
}

// checkPath return an error if the cookie path is invalid
func checkPath(path string) error {
	if err := checkChars(path, isValidPathChar); err != nil {
		return fmt.Errorf("cookie path: %s", err)
	}
	return nil
}

// checkDomain return an error if the domain name is not valid.
// See https://tools.ietf.org/html/rfc1034#section-3.5 and
// https://tools.ietf.org/html/rfc1123#section-2.
func checkDomain(name string) error {
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

// Path return the cookie path field value.
func (o *Obj) Path() string {
	return o.path
}

// Domain return the cookie domain field value.
func (o *Obj) Domain() string {
	return o.domain
}

// MaxAge return the cookie max age field value.
func (o *Obj) MaxAge() int {
	return o.maxAge
}

// HTTPOnly return the cookie HTTPOnly field value.
func (o *Obj) HTTPOnly() bool {
	return o.httpOnly
}

// Secure return the cookie HTTPOnly field value.
func (o *Obj) Secure() bool {
	return o.secure
}

// SetSecureValue adds the cookie with the value v to the server response w.
// The value v is encrypted and encoded in base64.
func (o *Obj) SetSecureValue(w http.ResponseWriter, v []byte) error {
	bPtr := bufPool.Get().(*[]byte)
	b := (*bPtr)[:0]
	defer func() { *bPtr = b; bufPool.Put(bPtr) }()
	b = append(b, o.name...)
	b = append(b, '=')
	b, err := appendEncodedValue(b, v, o.key)
	if err != nil {
		return err
	}
	if len(o.path) > 0 {
		b = append(b, "; Path="...)
		b = append(b, o.path...)
	}
	if len(o.domain) > 0 {
		b = append(b, "; Domain="...)
		b = append(b, o.domain...)
	}
	if o.maxAge > 0 {
		b = append(b, "; Max-Age="...)
		b = strconv.AppendInt(b, int64(o.maxAge), 10)
	}
	if o.httpOnly {
		b = append(b, "; HttpOnly"...)
	}
	if o.secure {
		b = append(b, "; Secure"...)
	}
	w.Header().Add("Set-Cookie", string(b))
	return nil
}

// appendEncodedValue appends the encoded value val to dst.
// dst is allocated or grown if it is nil or too small.
// Return dst and the error if any.
func appendEncodedValue(dst []byte, val []byte, key []byte) ([]byte, error) {
	encLen := encodedValueLen(len(val))
	if cap(dst)-len(dst) < encLen {
		tmp := make([]byte, len(dst), cap(dst)+encLen)
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

// encodedValueLen return the encoded byte length of the value of valLen bytes.
func encodedValueLen(valLen int) int {
	l := valLen + 5 + macLen
	return ((l-l%3)*8 + 5) / 6
}

// appendEncodedBase64 appends the base64 encoding of src to dst.
// dst is allocated or grown if it is nil or too small.
// Return dst and the error if any. Requires len(src)%3 == 0.
func appendEncodedBase64(dst, src []byte) ([]byte, error) {
	if len(src)%3 != 0 {
		return dst, errors.New("invalid src size")
	}
	encLen := (len(src)*8 + 5) / 6
	srcIdx, dstIdx := len(src), len(dst)+encLen
	if cap(dst) < dstIdx {
		tmp := make([]byte, len(dst), dstIdx)
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

// GetSecureValue return the decoded secure cookie value as a string or an error.
func (o *Obj) GetSecureValue(r *http.Request) ([]byte, error) {
	c, err := r.Cookie(o.name)
	if err != nil {
		return nil, err
	}
	return decodeValue(c.Value, o.key)
}

// decodeValue decode the encoded value val.
// Requires: len(val) >= 28 && len(val)%4 == 0 && len(key) == KeyLen.
func decodeValue(val string, key []byte) ([]byte, error) {
	if len(val) < 28 {
		return nil, errors.New("invalid value length")
	}
	b, err := decodeBase64(val)
	if err != nil {
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
	return b[:msgLen-nRnd], nil
}

// appendDecodedBase64 base64 decode src and append the result to dst.
// dst is allocated or grown if it is nil or too small.
// Return dst and the error if any. Requires len(src)%4 == 0.
func decodeBase64(src string) ([]byte, error) {
	if len(src)%4 != 0 {
		return nil, errors.New("invalid src size")
	}
	dst := make([]byte, (len(src)*6)/8)
	var srcIdx, dstIdx int
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

// Delete send a request to the remote user agent to delete the given
// cookie. Note that the user agent may not execute the request.
func (o *Obj) Delete(w http.ResponseWriter) error {
	bPtr := bufPool.Get().(*[]byte)
	b := (*bPtr)[:0]
	defer func() { *bPtr = b; bufPool.Put(bPtr) }()
	b = append(b, o.name...)
	b = append(b, '=')
	if len(o.path) > 0 {
		b = append(b, "; Path="...)
		b = append(b, o.path...)
	}
	if len(o.domain) > 0 {
		b = append(b, "; Domain="...)
		b = append(b, o.domain...)
	}
	b = append(b, "; Expires=Jan 2 15:04:05 2006"...)
	if o.httpOnly {
		b = append(b, "; HttpOnly"...)
	}
	if o.secure {
		b = append(b, "; Secure"...)
	}
	w.Header().Add("Set-Cookie", string(b))
	return nil
}

// macLen is the byte length of the MAC.
const macLen = md5.Size

// forceError is used for 100% test coverage
var forceError bool

// buffer pool
var bufPool = sync.Pool{New: func() interface{} { b := make([]byte, 64); return &b }}
