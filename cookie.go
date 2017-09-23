package cookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// KeyLen is the byte length of the key.
const KeyLen = 32

// GenerateRandomKey return a random key of KeyLen bytes.
// Use hex.EncodeToString(key) to get the key as hexadecimal string,
// and hex.DecodeString(keyStr) to convert back from string to byte slice.
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, KeyLen)
	if err := fillRandom(key); err != nil {
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
	begStr   string
	endStr   string
	maxAge   int
	httpOnly bool
	secure   bool
	ipad     [sha256.BlockSize]byte
	opad     [sha256.BlockSize]byte
	block    cipher.Block
}

// MustNew panic if New return a non-nil error, otherwise return o.
// MustNew is to instantiate global variables.
func MustNew(name string, key []byte, p Params) *Obj {
	o, err := New(name, key, p)
	if err != nil {
		panic(err)
	}
	return o
}

// New instantiate a validated cookie parameter field set with an associated key.
func New(name string, key []byte, p Params) (*Obj, error) {
	block, err := aes.NewCipher(key[len(key)/2:])
	if err != nil {
		return nil, err
	}
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
	var buf bytes.Buffer
	if len(p.Path) > 0 {
		buf.WriteString("; Path=")
		buf.WriteString(p.Path)
	}
	if len(p.Domain) > 0 {
		buf.WriteString("; Domain=")
		buf.WriteString(p.Domain)
	}
	if p.MaxAge > 0 {
		buf.WriteString("; Max-Age=")
		buf.Write(strconv.AppendInt(nil, int64(p.MaxAge), 10))
	}
	if p.HTTPOnly {
		buf.WriteString("; HttpOnly")
	}
	if p.Secure {
		buf.WriteString("; Secure")
	}
	var begStr = name + "="
	var o = &Obj{
		key:      key,
		name:     begStr[:len(name)],
		path:     p.Path,
		domain:   p.Domain,
		begStr:   begStr,
		endStr:   buf.String(),
		maxAge:   p.MaxAge,
		httpOnly: p.HTTPOnly,
		secure:   p.Secure,
		block:    block,
	}
	if len(key)/2 > sha256.BlockSize {
		var digest = sha256.Sum256(key[:len(key)/2])
		copy(o.ipad[:], digest[:])
	} else {
		copy(o.ipad[:], key[:len(key)/2])
	}
	for i := range o.ipad {
		o.ipad[i] ^= 0x36
		o.opad[i] = o.ipad[i] ^ 0x5C ^ 0x36
	}
	return o, nil
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
	b, err := o.encodeValue(b, v)
	if err != nil {
		return err
	}
	var valLen = len(o.begStr) + len(b) + len(o.endStr)
	if valLen > maxCookieLen {
		return fmt.Errorf("cookie too long: len is %d, max is %d", valLen, maxCookieLen)
	}
	w.Header().Add("Set-Cookie", o.begStr+string(b)+o.endStr)
	return nil
}

// encodeValue appends the encoded value val to dst.
// dst is allocated if nil, or grown if too small.
// Return dst and the error if any.
func (o *Obj) encodeValue(dst, val []byte) ([]byte, error) {
	var bPtr = bufPool.Get().(*[]byte)
	defer bufPool.Put(bPtr)
	var bLen = sha256.BlockSize + len(o.name) + ((1+ivLen+maxStampLen+len(val)+maxPaddingLen+hmacLen)*8+5)/6
	if cap(*bPtr) < bLen {
		*bPtr = make([]byte, bLen+20)
	}
	var b = (*bPtr)[:cap(*bPtr)]
	var endPos = copy(b, o.ipad[:])
	endPos += copy(b[endPos:], o.name)
	var encPos = endPos
	b[endPos] = byte(encodingVersion) << 2
	endPos++
	var iv = b[endPos : endPos+ivLen]
	if err := fillRandom(iv); err != nil {
		return dst, err
	}
	endPos += ivLen
	var xorPos = endPos
	endPos += encodeUint64(b[endPos:], uint64(time.Now().Unix())-epochOffset)
	endPos += copy(b[endPos:], val)
	var nPad = (3 - (endPos+hmacLen-encPos)%3) % 3
	b[encPos] |= byte(nPad)
	if err := fillRandom(b[endPos : endPos+nPad]); err != nil {
		return dst, err
	}
	endPos += nPad
	o.xorCtrAes(iv, b[xorPos:endPos])
	endPos += o.hmacsha256(b[endPos:], b[:endPos])
	var encLen = ((endPos-encPos)*8 + 5) / 6
	if cap(dst) < len(dst)+encLen {
		var tmp = make([]byte, len(dst), len(dst)+encLen)
		copy(tmp, dst)
		dst = tmp
	}
	return encodeBase64(dst, b[encPos:endPos])
}

// encodBase64 appends the base64 encoding of src to dst.
// Requires len(src)%3 == 0 && cap(dst) - len(dst) >= len(src)*4/3.
// May encode src in place if src is just after dst.
func encodeBase64(dst, src []byte) ([]byte, error) {
	if len(src)%3 != 0 {
		return dst, fmt.Errorf("invalid length %d, must be multiple of 3", len(src)%3)
	}
	var srcIdx, dstIdx = len(src), len(dst) + (len(src)/3)*4
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

// encodeUint64 encode v in b and return the bytes written.
// panic if b is not big enough. Max encoding length is 10.
func encodeUint64(b []byte, v uint64) int {
	var n int
	for v > 127 {
		b[n] = 0x80 | byte(v)
		v >>= 7
		n++
	}
	b[n] = byte(v)
	return n + 1
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

// GetSecureValue appends the decoded secure cookie value to dst.
// dst is allocated if nil, or grown if too small.
func (o *Obj) GetSecureValue(dst []byte, r *http.Request) ([]byte, error) {
	c, err := r.Cookie(o.name)
	if err != nil {
		return nil, err
	}
	return o.decodeValue(dst, c.Value)
}

// decodeValue append the encoded value val to dst.
// dst is allocated if nil, or grown if too small.
// Requires: len(val) >= minEncLen && len(val)%4 == 0.
func (o *Obj) decodeValue(dst []byte, val string) ([]byte, error) {
	if len(val) < minEncLen {
		return dst, errors.New("encoded value too short")
	}
	var bPtr = bufPool.Get().(*[]byte)
	defer bufPool.Put(bPtr)
	var bLen = sha256.BlockSize + len(o.name) + len(val)
	if cap(*bPtr) < bLen {
		*bPtr = make([]byte, bLen+20)
	}
	var b = (*bPtr)[:cap(*bPtr)]
	var endPos = copy(b, o.ipad[:])
	endPos += copy(b[endPos:], o.name)
	var encPos = endPos
	b, err := decodeBase64(b[:encPos], val)
	if err != nil {
		return dst, err
	}
	var version, nPad = int(b[encPos] >> 2), int(b[encPos] & 3)
	if version != encodingVersion {
		return dst, fmt.Errorf("invalid encoding version %d, expected value <= %d",
			version, encodingVersion)
	}
	if nPad > maxPaddingLen {
		return dst, fmt.Errorf("invalid padding length %d, expected value <= %d",
			nPad, maxPaddingLen)
	}
	var valMac = b[len(b)-hmacLen:]
	b = b[:len(b)-hmacLen]
	var locMac [hmacLen]byte
	o.hmacsha256(locMac[:], b)
	b = b[encPos:]
	var x byte
	for i := range locMac {
		x |= valMac[i] ^ locMac[i]
	}
	if x != 0 {
		return nil, errors.New("MAC mismatch")
	}
	var iv = b[1 : 1+ivLen]
	b = b[1+ivLen:]
	o.xorCtrAes(iv, b)
	stamp, stampLen := decodeUint64(b)
	if stampLen == 0 {
		return dst, errors.New("invalid time stamp encoding")
	}
	stamp += epochOffset
	var valStamp = time.Unix(int64(stamp), 0)
	var maxStamp = time.Unix(int64(stamp)+int64(o.maxAge), 0)
	if time.Now().Before(valStamp) || time.Now().After(maxStamp) {
		return dst, errors.New("invalid time stamp")
	}
	return append(dst, b[stampLen:len(b)-nPad]...), nil
}

// decodeBase64 append base64 encoded src to dst.
// Return an error if len(src)%4 != 0 or src is not valid base64 encoding.
// Requires cap(dst) - len(dst) >= (len(src)/4)*3.
func decodeBase64(dst []byte, src string) ([]byte, error) {
	if len(src)%4 != 0 {
		return dst, fmt.Errorf("invalid length %d, must be multiple of 4", len(src)%4)
	}
	var decLen = (len(src) / 4) * 3
	var srcIdx, dstIdx = 0, len(dst)
	if cap(dst) < len(dst)+decLen {
		var tmp = make([]byte, len(dst), len(dst)+decLen)
		copy(tmp, dst)
		dst = tmp
	}
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
				return dst, errors.New("invalid base64 char")
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

// decodeUint64 encode v in b and return the number of
// bytes read. If that value is 0, no value was read.
func decodeUint64(b []byte) (uint64, int) {
	var v uint64
	var s uint8
	for i, c := range b {
		if c < 0x80 {
			if i > 9 || i == 9 && c > 1 {
				return 0, 0
			}
			return v | uint64(c&0x7F)<<s, i + 1
		}
		v |= uint64(c&0x7F) << s
		s += 7
	}
	return 0, 0
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

func (o *Obj) hmacsha256(b []byte, data1 []byte) int {
	// ipad is already copied in front of the data
	var data2 [sha256.BlockSize + sha256.Size]byte
	copy(data2[:sha256.BlockSize], o.opad[:])
	var digest = sha256.Sum256(data1)
	copy(data2[sha256.BlockSize:], digest[:])
	digest = sha256.Sum256(data2[:])
	return copy(b, digest[:])
}

// xorCtrAes computes the xor of data with encrypted ctr counter initialized bith iv.
// It leaks timing information, but it is not a problem since the iv is public.
func (o *Obj) xorCtrAes(iv []byte, data []byte) {
	var buf = hmacBlockPool.Get().(*hmacBlock)
	defer hmacBlockPool.Put(buf)
	var ctr = buf[:blockLen]
	var bits = buf[blockLen:]
	for i := range ctr {
		ctr[i] = iv[i]
	}
	for len(data) > blockLen {
		o.block.Encrypt(bits, ctr)
		for i := range bits {
			data[i] ^= bits[i]
		}
		for i := blockLen - 1; i >= 0; i-- {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
		data = data[blockLen:]
	}
	o.block.Encrypt(bits, ctr)
	for i := range data {
		data[i] ^= bits[i]
	}
}

// fillRandom fill b with cryptographically secure pseudorandom bytes.
func fillRandom(b []byte) error {
	if forceError == 0 {
		_, err := rand.Read(b)
		return err
	}
	if forceError == 1 {
		return errors.New("force error")
	}
	forceError--
	return nil
}

// encodingVersion is the version of the generated encoding.
const encodingVersion = 0

// epochOffset is the number of seconds to subtract to the unix time to get
// the epoch used in these secure cookie.
const epochOffset uint64 = 1505230500

// hmacLen is the byte length of the hmac(SHA256) digest.
const hmacLen = sha256.Size

// hmacBlock is an array of hmacLen bytes.
type hmacBlock [hmacLen]byte

// ivLen is the byte length of the iv.
const ivLen = blockLen

// maxStampLen is the maximum byte length of the time stamp (seconds).
const maxStampLen = 10

// maxPaddingLen is the maximum number of padding bytes.
const maxPaddingLen = 2

// blockLen is the byte length of an AES block.
const blockLen = aes.BlockSize

// byteBlock is an array of blockLen bytes.
type byteBlock [blockLen]byte

// minEncLen is the minimum encoding length of a value.
const minEncLen = ((1+ivLen+hmacLen)*8 + 5) / 6

// maxCookieLen is the maximum len of a cookie.
const maxCookieLen = 4000

// forceError is used for 100% test coverage.
var forceError int

// buffer pool.
var bufPool = sync.Pool{New: func() interface{} { b := make([]byte, 128); return &b }}

// hmacBlockPool is a pool of hmac blocks.
var hmacBlockPool = sync.Pool{New: func() interface{} { return new(hmacBlock) }}
