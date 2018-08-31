/*
Package securecookie is a fast, efficient and safe cookie value
encoder/decoder.

A secure cookie has its value ciphered and signed with a message
authentication code. This prevents the remote cookie owner from
knowing what information is stored in the cookie or modifying it.
It also prevents an attacker from forging a fake securecookie.

What makes this secure cookie package different is that it is fast
(faster than the Gorilla secure cookie), and the value encoding
and decoding needs no heap allocations.

The intended use is to instantiate all secure cookie objects of
your web site at program start up. In the following example "session"
is the cookie name. The key is a byte sequence generated with the
GenerateRandomKey() function. The same key must be used to retrieve
the value.

	obj, err := securecookie.New("session", key, securecookie.Params{
		Path:     "/sec",        // cookie received only when URL
		                         // starts with this path.
		Domain:   "example.com", // cookie received only when URL
		                         // domain matches this one.
		MaxAge:   3600,          // cookie becomes invalid 3600
		                         // seconds after it is set.
		HTTPOnly: true,          // disallow access by remote
		                         // javascript code.
		Secure:   true,          // cookie received only with HTTPS,
		                         // never with HTTP.
	})
	if err != nil {
		// ...
	}

An securecookie can also be instantiated as a global variable with the
MustNew function. The function will panic if an error occurs.

	var obj = securecookie.MustNew("session", key, securecookie.Params{
		Path:     "/sec",
		Domain:   "example.com",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   true,
	})


A securecookie object is immutable. It's methods can be called from
different goroutines. The Delete(), SetValue() and GetValue() methods
are independent.

To set a cookie value, call the SetValue() method with a http.ResponseWriter
w, and a value val as arguments.

    var val = []byte("some value")
    if err := obj.SetValue(w, val); err != nil {
		// ...
	}

A securecookie value is retrieved from an http.Request with the GetValue()
method and is appended to the given buffer, extending it if required. If
buf is nil, a new buffer is allocated.

    val, err := obj.GetValue(buf, r)
	if err != nil {
		// ...
	}

A securecookie is deleted by calling the Delete() method with the
http.ResponseWriter w as argument.

    if err := obj.Delete(r); err != nil {
		// ...
	}
*/
package securecookie

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
	"unicode/utf8"
)

// KeyLen is the byte length of the key.
const KeyLen = 32

// GenerateRandomKey returns a random key of KeyLen bytes.
// Use hex.EncodeToString(key) to get the key as hexadecimal string,
// and hex.DecodeString(keyStr) to convert back from string to byte slice.
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, KeyLen)
	if err := fillRandom(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Params holds the optional cookie parameters.
type Params struct {
	Path     string // Optional : URL path to which the cookie will be returned
	Domain   string // Optional : domain to which the cookie will be returned
	MaxAge   int    // Optional : time offset in seconds from now, must be >= 0
	HTTPOnly bool   // Optional : disallow access by remote javascript code
	Secure   bool   // Optional : cookie is only sent through HTTPS connections
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

// MustNew panics if New returns a non-nil error, otherwise returns a cookie
// object. The intended use is to instantiate the object as a global variable.
func MustNew(name string, key []byte, p Params) *Obj {
	o, err := New(name, key, p)
	if err != nil {
		panic(err)
	}
	return o
}

// New instantiates a validated cookie object with the given cookie name, key
// and parameters.
func New(name string, key []byte, p Params) (*Obj, error) {
	block, err := aes.NewCipher(key[len(key)/2:])
	if err != nil {
		return nil, err
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("securecookie: key length is %d, expected %d", len(key), KeyLen)
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
		return nil, errors.New("securecookie: MaxAge can't be negative")
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
	for i := range o.ipad {
		o.ipad[i] = 0x36
		o.opad[i] = 0x5C
	}
	for i := range key[:len(key)/2] {
		o.ipad[i] ^= key[i]
		o.opad[i] ^= key[i]
	}
	return o, nil
}

// checkName returns an error if the cookie name is invalid.
func checkName(name string) error {
	if len(name) == 0 {
		return errors.New("securecookie: cookie name must not be empty")
	}
	if err := checkChars(name, isValidNameChar); err != nil {
		return fmt.Errorf("securecookie: name has %s", err)
	}
	return nil
}

// checkPath returns an error if the cookie path is invalid.
func checkPath(path string) error {
	if err := checkChars(path, isValidPathChar); err != nil {
		return fmt.Errorf("securecookie: path has %s", err)
	}
	return nil
}

// checkDomain returns an error if the domain name is not valid.
// See https://tools.ietf.org/html/rfc1034#section-3.5 and
// https://tools.ietf.org/html/rfc1123#section-2.
func checkDomain(name string) error {
	switch {
	case len(name) == 0:
		return nil // an empty domain name will result in a cookie without a domain restriction
	case len(name) > 255:
		return fmt.Errorf("securecookie: domain name length is %d, can't exceed 255", len(name))
	}
	var l int
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '.' {
			// check domain labels validity
			switch {
			case i == l:
				return fmt.Errorf("securecookie: domain has invalid character '.' at offset %d, label can't begin with a period", i)
			case i-l > 63:
				return fmt.Errorf("securecookie: domain byte length of label '%s' is %d, can't exceed 63", name[l:i], i-l)
			case name[l] == '-':
				return fmt.Errorf("securecookie: domain label '%s' at offset %d begins with a hyphen", name[l:i], l)
			case name[i-1] == '-':
				return fmt.Errorf("securecookie: domain label '%s' at offset %d ends with a hyphen", name[l:i], l)
			}
			l = i + 1
			continue
		}
		// test label character validity, note: tests are ordered by decreasing validity frequency
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b >= 'A' && b <= 'Z') {
			// show the printable unicode character starting at byte offset i
			c, _ := utf8.DecodeRuneInString(name[i:])
			if c == utf8.RuneError {
				return fmt.Errorf("securecookie: domain has invalid rune at offset %d", i)
			}
			return fmt.Errorf("securecookie: domain has invalid character '%c' at offset %d", c, i)
		}
	}
	// check top level domain validity
	switch {
	case l == len(name):
		return fmt.Errorf("securecookie: domain has missing top level domain, domain can't end with a period")
	case len(name)-l > 63:
		return fmt.Errorf("securecookie: domain's top level domain '%s' has byte length %d, can't exceed 63", name[l:], len(name)-l)
	case name[l] == '-':
		return fmt.Errorf("securecookie: domain's top level domain '%s' at offset %d begin with a hyphen", name[l:], l)
	case name[len(name)-1] == '-':
		return fmt.Errorf("securecookie: domain's top level domain '%s' at offset %d ends with a hyphen", name[l:], l)
	case name[l] >= '0' && name[l] <= '9':
		return fmt.Errorf("securecookie: domain's top level domain '%s' at offset %d begins with a digit", name[l:], l)
	}
	return nil
}

func isValidNameChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'Z') || c == '!' || (c >= '#' && c < '(') || c == '*' ||
		c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' ||
		c == '|' || c == '~'
}

func isValidPathChar(c byte) bool {
	return (c >= ' ' && c < 0x7F) && c != ';'
}

func checkChars(s string, isValid func(c byte) bool) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isValid(c) {
			if c < ' ' || c >= 0x7F {
				return fmt.Errorf("invalid character 0x%02X at offset %d", c, i)
			}
			return fmt.Errorf("invalid character '%c' at offset %d", c, i)
		}
	}
	return nil
}

// Path returns the securecookie path field value.
func (o *Obj) Path() string {
	return o.path
}

// Domain returns the securecookie domain field value.
func (o *Obj) Domain() string {
	return o.domain
}

// MaxAge returns the securecookie max age field value.
func (o *Obj) MaxAge() int {
	return o.maxAge
}

// HTTPOnly returns the securecookie HTTPOnly field value.
func (o *Obj) HTTPOnly() bool {
	return o.httpOnly
}

// Secure returns the securecookie HTTPOnly field value.
func (o *Obj) Secure() bool {
	return o.secure
}

// SetValue adds the securecookie with the value v to the server response w.
// The value v is encrypted, signed with a MAC, and encoded in base64.
func (o *Obj) SetValue(w http.ResponseWriter, v []byte) error {
	bPtr := bufPool.Get().(*[]byte)
	b := (*bPtr)[:0]
	defer func() { *bPtr = b; bufPool.Put(bPtr) }()
	b, err := o.encodeValue(b, v)
	if err != nil {
		return err
	}
	var valLen = len(o.begStr) + len(b) + len(o.endStr)
	if valLen > maxCookieLen {
		return fmt.Errorf("securecookie: cookie value has byte length %d, can't exceed %d", valLen, maxCookieLen)
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
	var padPos = endPos
	var nPad = (endPos + hmacLen - encPos) % 3
	nPad = (nPad>>1 | nPad<<1) & 3 // computes : 0 -> 0; 1 -> 2; 2 -> 1
	b[encPos] |= byte(nPad)
	endPos += nPad
	if err := fillRandom(b[padPos:endPos]); err != nil {
		return dst, err
	}
	o.xorCtrAes(iv, b[xorPos:endPos])
	endPos += o.hmacSha256(b[endPos:], b[:endPos])
	return encodeBase64(dst, b[encPos:endPos]), nil
}

// encodeUint64 encodes v in b and returns the bytes written.
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

// encodeBase64 appends the base64 encoding of src to dst. Grow dst if needed.
// Requires that length of src is a multiple of three, and that src and dst
// don't overlap.
func encodeBase64(dst, src []byte) []byte {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	dstLen := len(dst) + len(src)*8/6
	if cap(dst) < dstLen {
		dst = append(make([]byte, 0, dstLen), dst...)
	}
	dstIdx, srcIdx := len(dst), 0
	dst = dst[:dstLen]
	for dstIdx != dstLen {
		v := uint64(src[srcIdx])<<16 | uint64(src[srcIdx+1])<<8 | uint64(src[srcIdx+2])
		srcIdx += 3
		dst[dstIdx] = base64Chars[(v>>18)&0x3F]
		dst[dstIdx+1] = base64Chars[(v>>12)&0x3F]
		dst[dstIdx+2] = base64Chars[(v>>6)&0x3F]
		dst[dstIdx+3] = base64Chars[v&0x3F]
		dstIdx += 4
	}
	return dst
}

// GetValue appends the decoded securecookie value to dst.
// dst is allocated if nil, or grown if too small.
func (o *Obj) GetValue(dst []byte, r *http.Request) ([]byte, error) {
	c, err := r.Cookie(o.name)
	if err != nil {
		return nil, err
	}
	return o.decodeValue(dst, c.Value)
}

// decodeValue appends the encoded value val to dst.
// dst is allocated if nil, or grown if too small.
// Requires: len(val) >= minEncLen && len(val)%4 == 0.
func (o *Obj) decodeValue(dst []byte, val string) ([]byte, error) {
	if len(val) < minEncLen {
		return dst, errors.New("securecookie: encoded value is too short")
	}
	var bPtr = bufPool.Get().(*[]byte)
	defer bufPool.Put(bPtr)
	var bLen = sha256BlockLen + len(o.name) + len(val)
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
		return dst, fmt.Errorf("securecookie: invalid encoding version %d, expected value <= %d",
			version, encodingVersion)
	}
	if nPad > maxPaddingLen {
		return dst, fmt.Errorf("securecookie: invalid padding length %d, expected value <= %d",
			nPad, maxPaddingLen)
	}
	var valMac = b[len(b)-hmacLen:]
	b = b[:len(b)-hmacLen]
	var locMac [hmacLen]byte
	o.hmacSha256(locMac[:], b)
	b = b[encPos:]
	var x byte
	for i := range locMac {
		x |= valMac[i] ^ locMac[i]
	}
	if x != 0 {
		return nil, errors.New("securecookie: invalid encoded cookie value (MAC mismatch)")
	}
	var iv = b[1 : 1+ivLen]
	b = b[1+ivLen:]
	o.xorCtrAes(iv, b)
	stamp, stampLen := decodeUint64(b)
	if stampLen == 0 {
		return dst, errors.New("securecookie: invalid cookie time stamp encoding")
	}
	stamp += epochOffset
	var valStamp = time.Unix(int64(stamp), 0)
	var maxStamp = time.Unix(int64(stamp)+int64(o.maxAge), 0)
	if time.Now().Before(valStamp) || time.Now().After(maxStamp) {
		return dst, errors.New("securecookie: invalid cookie time stamp value")
	}
	return append(dst, b[stampLen:len(b)-nPad]...), nil
}

// decodeBase64 appends base64 decoded src to dst. Grow dst if needed.
// Returns an error if len(src)%4 != 0 or src doesn't contain a valid base64 encoding.
// Requires src and dst don't overlap.
func decodeBase64(dst []byte, src string) ([]byte, error) {
	var tbl = []int8{
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
		-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
		-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	}
	if len(src)%4 != 0 {
		return dst, fmt.Errorf("securecookie: invalid encoded cookie length %d, must be multiple of 4", len(src)%4)
	}
	var dstLen = len(dst) + len(src)*3/4
	if cap(dst) < dstLen {
		dst = append(make([]byte, 0, dstLen), dst...)
	}
	var srcIdx, dstIdx = 0, len(dst)
	dst = dst[:dstLen]
	for srcIdx < len(src) {
		var v = int64(tbl[src[srcIdx]])<<18 | int64(tbl[src[srcIdx+1]])<<12 | int64(tbl[src[srcIdx+2]])<<6 | int64(tbl[src[srcIdx+3]])
		srcIdx += 4
		if v < 0 {
			return dst, errors.New("securecookie: invalid base64 char")
		}
		dst[dstIdx] = byte(v >> 16)
		dst[dstIdx+1] = byte(v >> 8)
		dst[dstIdx+2] = byte(v)
		dstIdx += 3
	}
	return dst, nil
}

// decodeUint64 encodes v in b and returns the number of
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

// Delete adds a request to the delete the securecookie to the server
// response w. The user agent may ignore the request.
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

func (o *Obj) hmacSha256(b []byte, data1 []byte) int {
	// ipad is already copied in front of data1
	var digest = sha256.Sum256(data1)
	var data2 [sha256BlockLen + hmacLen]byte
	copy(data2[:sha256BlockLen], o.opad[:])
	copy(data2[sha256BlockLen:], digest[:])
	digest = sha256.Sum256(data2[:])
	return copy(b, digest[:])
}

// xorCtrAes computes the xor of data with encrypted ctr counter initialized
// with iv.
func (o *Obj) xorCtrAes(iv []byte, data []byte) {
	var buf = aesBufPool.Get().(*aesBuf)
	defer aesBufPool.Put(buf)
	var ctr = buf[:aesBlockLen]
	var bits = buf[aesBlockLen:]
	for i := range ctr {
		ctr[i] = iv[i]
	}
	for len(data) > aesBlockLen {
		o.block.Encrypt(bits, ctr)
		for i := range bits {
			data[i] ^= bits[i]
		}
		for i := aesBlockLen - 1; i >= 0; i-- {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
		data = data[aesBlockLen:]
	}
	o.block.Encrypt(bits, ctr)
	for i := range data {
		data[i] ^= bits[i]
	}
}

// fillRandom fills b with cryptographically secure pseudorandom bytes.
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

// epochOffset is the number of seconds to subtract from the unix time to get
// the epoch used in these secure cookies.
const epochOffset uint64 = 1505230500

// hmacLen is the byte length of the hmac(SHA256) digest.
const hmacLen = sha256.Size

// sha256BlockLen is the size of a sha256 block.
const sha256BlockLen = sha256.BlockSize

// aesBlockSize is the AES blockSize.
const aesBlockLen = aes.BlockSize

// aesBuf is a buffer used by xorCtrAES.
type aesBuf [2 * aesBlockLen]byte

// ivLen is the byte length of the iv.
const ivLen = aesBlockLen

// maxStampLen is the maximum byte length of the time stamp (seconds).
const maxStampLen = 10

// maxPaddingLen is the maximum number of padding bytes.
const maxPaddingLen = 2

// minEncLen is the minimum encoding length of a value.
const minEncLen = ((1+ivLen+hmacLen)*8 + 5) / 6

// maxCookieLen is the maximum length of a cookie.
const maxCookieLen = 4000

// forceError is used for 100% test coverage.
var forceError int

// pool of buffers used for value encoding and decoding.
var bufPool = sync.Pool{New: func() interface{} { var b []byte; return &b }}

// pool of aesBuf used to cipher and decipher with XOR-CTR-AES.
var aesBufPool = sync.Pool{New: func() interface{} { return new(aesBuf) }}
