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
your web site at program start up. In the following example
"session" is the cookie name, and the cookie value becomes invalid
two hours after it is set. The key is a byte sequence generated with
the GenerateRandomKey() function. The same key must be used to
retrieve the value.

	obj, err := securecookie.New("session", key, 2*time.Hour)
	if err != nil {
		// ...
	}

The cookie name is prefixed with "__Host-", and the cookie has the
attributes "Path=/", "HttpOnly", "Secure" and "SameSite=Lax". The
SameSite attribute may be changed with an option.

	obj, err := securecookie.New("session", key, 2*time.Hour,
		securecookie.WithSameSiteStrict())

A securecookie can also be instantiated as a global variable with the
MustNew function. The function will panic if an error occurs.

	var obj = securecookie.MustNew("session", key, 2*time.Hour)

A securecookie object is immutable. Its methods can be called from
different goroutines. The Delete(), SetValue() and GetValues() methods
are independent.

To set a cookie value, call the SetValue() method with a http.ResponseWriter
w, and a value val as arguments.

	var val = []byte("some value")
	if err := obj.SetValue(w, val); err != nil {
		// ...
	}

A request may contain several cookies with the same name. Securecookie
values are retrieved from an http.Request with the GetValues() method.
The following example accepts the request only if all the valid values
are equal.

	var val []byte
	var found bool
	for _, res := range obj.GetValues(r.Cookies()) {
		if res.Error != nil {
			continue // ignore invalid or expired values
		}
		if found && !bytes.Equal(val, res.Value) {
			// different valid values: reject the request
		}
		val, found = res.Value, true
	}
	if !found {
		// no valid value
	}

A securecookie is deleted by calling the Delete() method with the
http.ResponseWriter w as argument.

	if err := obj.Delete(w); err != nil {
		// ...
	}

# Security

The "__Host-" name prefix added by New instructs the user agent to only
accept the cookie when it is set by the host itself, with Secure, without
Domain, and with Path "/". Another host, like a sibling subdomain, or a
network attacker, can then not set a cookie with the same name in the
user agent (cookie tossing).

The value is rejected by the server when it is older than the max age,
even if the user agent didn't delete the cookie. A copied value can thus
only be used during that time.

Keep the key secret. Anyone knowing the key can read and forge values.
*/
package securecookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KeyLen is the byte length of the key.
const KeyLen = 32

// SameSite is the value of the SameSite cookie attribute. It restricts
// when the user agent sends the cookie with requests initiated by other
// sites.
type SameSite int

const (
	// SameSiteLax sends the cookie with requests from the same site, and
	// with top-level navigations from other sites using a safe method like
	// GET (e.g. following a link). It is the default.
	SameSiteLax SameSite = iota + 1

	// SameSiteStrict sends the cookie only with requests from the same
	// site. A user following a link from another site arrives without
	// the cookie.
	SameSiteStrict
)

// MaxMaxAge is the maximum cookie max age. User agents limit the cookie
// lifetime to about 400 days.
const MaxMaxAge = 400 * 24 * time.Hour

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

// MustGenerateRandomKey returns a random key of KeyLen bytes.
// It calls GenerateRandomKey and panics if it returns an error.
func MustGenerateRandomKey() []byte {
	key, err := GenerateRandomKey()
	if err != nil {
		panic("securecookie: generate random key: " + err.Error())
	}
	return key
}

// Obj is a validated cookie object.
type Obj struct {
	name     string
	begStr   string
	endStr   string
	delStr   string
	maxAge   int
	sameSite SameSite
	ipad     [sha256.BlockSize]byte
	opad     [sha256.BlockSize]byte
	block    cipher.Block
}

// Option is an optional parameter of New and MustNew.
type Option func(o *Obj)

// WithSameSite sets the SameSite cookie attribute to s.
func WithSameSite(s SameSite) Option {
	return func(o *Obj) { o.sameSite = s }
}

// WithSameSiteLax sets the SameSite cookie attribute to Lax. It is the default.
func WithSameSiteLax() Option {
	return WithSameSite(SameSiteLax)
}

// WithSameSiteStrict sets the SameSite cookie attribute to Strict.
func WithSameSiteStrict() Option {
	return WithSameSite(SameSiteStrict)
}

// MustNew panics if New returns a non-nil error, otherwise returns a cookie
// object. The intended use is to instantiate the object as a global variable.
func MustNew(name string, key []byte, maxAge time.Duration, opts ...Option) *Obj {
	o, err := New(name, key, maxAge, opts...)
	if err != nil {
		panic(err)
	}
	return o
}

// New instantiates a validated cookie object with the given cookie name, key,
// maximum age and options.
//
// The cookie name is prefixed with "__Host-". The user agent then only
// accepts the cookie when it is set by the host itself, and no other host
// can set a cookie with the same name. The name must not already start with
// "__Host-" or "__Secure-".
//
// The cookie attributes are always "Path=/", "HttpOnly" and "Secure", without
// Domain, as required by the "__Host-" prefix. The cookie is thus only sent
// over HTTPS, for all URL paths of the host.
//
// maxAge is truncated to seconds. It must be at least one second and can't
// exceed MaxMaxAge. The value is rejected by the server when it is older than
// maxAge.
//
// The SameSite attribute is Lax by default.
func New(name string, key []byte, maxAge time.Duration, opts ...Option) (*Obj, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("securecookie: key length is %d, expected %d", len(key), KeyLen)
	}
	block, err := aesCipher(key[len(key)/2:])
	if err != nil {
		return nil, err
	}
	if err := checkName(name); err != nil {
		return nil, err
	}
	if hasPrefixFold(name, hostPrefix) || hasPrefixFold(name, "__Secure-") {
		return nil, fmt.Errorf("securecookie: name '%s' must not start with __Host- or __Secure-, New adds the __Host- prefix", name)
	}
	var maxAgeSec = int64(maxAge / time.Second)
	if maxAgeSec < 1 {
		return nil, fmt.Errorf("securecookie: max age %s must be at least one second", maxAge)
	}
	if maxAge > MaxMaxAge {
		return nil, fmt.Errorf("securecookie: max age %s can't exceed %s", maxAge, MaxMaxAge)
	}
	var o = &Obj{sameSite: SameSiteLax, block: block}
	for _, opt := range opts {
		opt(o)
	}
	var sameSiteStr string
	switch o.sameSite {
	case SameSiteLax:
		sameSiteStr = "; SameSite=Lax"
	case SameSiteStrict:
		sameSiteStr = "; SameSite=Strict"
	default:
		return nil, fmt.Errorf("securecookie: invalid SameSite value %d", o.sameSite)
	}
	var fullName = hostPrefix + name
	o.name = fullName
	o.begStr = fullName + "="
	o.maxAge = int(maxAgeSec)
	o.endStr = "; Path=/; Max-Age=" + strconv.FormatInt(maxAgeSec, 10) + "; HttpOnly; Secure" + sameSiteStr
	o.delStr = fullName + "=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure" + sameSiteStr
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

// hostPrefix is the cookie name prefix added by New.
const hostPrefix = "__Host-"

// aesCipher returns the AES cipher block for key, or the wrapped error
// returned by aes.NewCipher. When forceAesError is true, the key is
// truncated so that aes.NewCipher returns an error.
func aesCipher(key []byte) (cipher.Block, error) {
	if forceAesError {
		key = key[:1]
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("securecookie: %w", err)
	}
	return block, nil
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

// hasPrefixFold returns true if s starts with prefix, ignoring case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func isValidNameChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'Z') || c == '!' || (c >= '#' && c < '(') || c == '*' ||
		c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' ||
		c == '|' || c == '~'
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

// Name returns the cookie name, including the "__Host-" prefix.
func (o *Obj) Name() string {
	return o.name
}

// MaxAge returns the cookie max age, truncated to seconds.
func (o *Obj) MaxAge() time.Duration {
	return time.Duration(o.maxAge) * time.Second
}

// SameSite returns the SameSite cookie attribute value.
func (o *Obj) SameSite() SameSite {
	return o.sameSite
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
	nowUnix := time.Now().Unix()
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
	endPos += encodeUint64(b[endPos:], uint64(nowUnix)-epochOffset)
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

// encodeBase64 appends the base64 encoding of src to dst. Grow dst if needed.
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

// GetValue returns the value of the first cookie with a matching name.
// The function uses the dst slice as storage if not nil and big enough.
//
// Deprecated: a request may contain several cookies with the same name,
// for instance one set by another host (cookie tossing), and GetValue
// only decodes the first one. Use GetValues instead.
func (o *Obj) GetValue(dst []byte, r *http.Request) ([]byte, error) {
	c, err := r.Cookie(o.name)
	if err != nil {
		return nil, err
	}
	return o.decodeValue(dst, c.Value)
}

// ValueResult is a decoded value with its time stamp, or the error if any. ValueResult
// are returned by the GetValues method.
type ValueResult struct {
	Value []byte
	Stamp time.Time
	Error error
}

// GetValues returns the values and stamp of cookies with a matching
// name in cookies, or nil if none. A request may contain multiple
// cookies with the same name, and cookies is usually r.Cookies().
// For each returned value, Error is nil and Value holds the decoded
// value (nil when the value is empty), or Error is not nil and Value
// is nil.
func (o *Obj) GetValues(cookies []*http.Cookie) []ValueResult {
	var res []ValueResult
	for _, c := range cookies {
		if c.Name == o.name {
			val, stamp, err := o.decodeValueAndStamp(nil, c.Value)
			res = append(res, ValueResult{Value: val, Stamp: stamp, Error: err})
		}
	}
	return res
}

// decodeValue appends the decoded value val to dst.
// dst is allocated if nil, or grown if too small.
// Requires: len(val) >= minEncLen && len(val)%4 == 0.
func (o *Obj) decodeValue(dst []byte, val string) ([]byte, error) {
	if len(val) < minEncLen {
		return dst, errors.New("securecookie: encoded value is too short")
	}
	if len(val) > maxCookieLen {
		return dst, errTooLong
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
		return dst, fmt.Errorf("securecookie: invalid encoding version %d, expected %d",
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
	if subtle.ConstantTimeCompare(valMac, locMac[:]) != 1 {
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
	if time.Now().Before(valStamp) || (o.maxAge != 0 && time.Now().After(maxStamp)) {
		return dst, errors.New("securecookie: invalid cookie time stamp value")
	}
	return append(dst, b[stampLen:len(b)-nPad]...), nil
}

// GetValueAndStamp appends the decoded securecookie value to dst.
// dst is allocated if nil, or grown if too small.
// Returns the value and the time stamp truncated to seconds when the
// cookie was generated and added to an http response with SetValue.
//
// Deprecated: a request may contain several cookies with the same name,
// for instance one set by another host (cookie tossing), and
// GetValueAndStamp only decodes the first one. Use GetValues instead.
func (o *Obj) GetValueAndStamp(dst []byte, r *http.Request) ([]byte, time.Time, error) {
	c, err := r.Cookie(o.name)
	if err != nil {
		return nil, time.Time{}, err
	}
	return o.decodeValueAndStamp(dst, c.Value)
}

// decodeValueAndStamp appends the decoded value val to dst.
// dst is allocated if nil, or grown if too small.
// Requires: len(val) >= minEncLen && len(val)%4 == 0.
func (o *Obj) decodeValueAndStamp(dst []byte, val string) ([]byte, time.Time, error) {
	if len(val) < minEncLen {
		return dst, time.Time{}, errors.New("securecookie: encoded value is too short")
	}
	if len(val) > maxCookieLen {
		return dst, time.Time{}, errTooLong
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
		return dst, time.Time{}, err
	}
	var version, nPad = int(b[encPos] >> 2), int(b[encPos] & 3)
	if version != encodingVersion {
		return dst, time.Time{}, fmt.Errorf("securecookie: invalid encoding version %d, expected %d",
			version, encodingVersion)
	}
	if nPad > maxPaddingLen {
		return dst, time.Time{}, fmt.Errorf("securecookie: invalid padding length %d, expected value <= %d",
			nPad, maxPaddingLen)
	}
	var valMac = b[len(b)-hmacLen:]
	b = b[:len(b)-hmacLen]
	var locMac [hmacLen]byte
	o.hmacSha256(locMac[:], b)
	b = b[encPos:]
	if subtle.ConstantTimeCompare(valMac, locMac[:]) != 1 {
		return nil, time.Time{}, errors.New("securecookie: invalid encoded cookie value (MAC mismatch)")
	}
	var iv = b[1 : 1+ivLen]
	b = b[1+ivLen:]
	o.xorCtrAes(iv, b)
	stamp, stampLen := decodeUint64(b)
	if stampLen == 0 {
		return dst, time.Time{}, errors.New("securecookie: invalid cookie time stamp encoding")
	}
	stamp += epochOffset
	var valStamp = time.Unix(int64(stamp), 0)
	var maxStamp = time.Unix(int64(stamp)+int64(o.maxAge), 0)
	if time.Now().Before(valStamp) || (o.maxAge != 0 && time.Now().After(maxStamp)) {
		return dst, time.Time{}, errors.New("securecookie: invalid cookie time stamp value")
	}
	return append(dst, b[stampLen:len(b)-nPad]...), valStamp, nil
}

// decodeBase64 appends base64 decoded src to dst. Grow dst if needed.
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
		return dst, fmt.Errorf("securecookie: invalid encoded cookie length %d, must be multiple of 4", len(src))
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

// decodeUint64 decodes a value from b and returns it with the number of
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

// Delete adds a request to delete the securecookie to the server
// response w. The user agent may ignore the request.
func (o *Obj) Delete(w http.ResponseWriter) error {
	w.Header().Add("Set-Cookie", o.delStr)
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

// sha256BlockLen is the size of a sha256 block.
const sha256BlockLen = sha256.BlockSize

// aesBlockLen is the AES block size.
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

// errTooLong is returned when an encoded value to decode is longer than
// maxCookieLen. Such a value can't have been produced by SetValue, and is
// rejected before any processing.
var errTooLong = fmt.Errorf("securecookie: encoded value is too long, can't exceed %d", maxCookieLen)

// forceError is used for 100% test coverage.
var forceError int

// forceAesError forces aesCipher to return an error. It is used for 100%
// test coverage.
var forceAesError bool

// pool of buffers used for value encoding and decoding.
var bufPool = sync.Pool{New: func() interface{} { var b []byte; return &b }}

// pool of aesBuf used to cipher and decipher with XOR-CTR-AES.
var aesBufPool = sync.Pool{New: func() interface{} { return new(aesBuf) }}
