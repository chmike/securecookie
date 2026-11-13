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

The intended use is to instantiate the key store and all secure cookie
objects of your web site at program start up. The key store derives the
keys from a secret seed of SeedLen bytes, generated once with the
GenerateSeed() function and kept in a file readable only by the program.
All servers sharing the same seed can decode the values encoded by the
others.

	keys, err := securecookie.NewKeyStore(seed)
	if err != nil {
		// ...
	}

In the following example "session" is the cookie name, and the cookie
value becomes invalid two hours after it is set.

	obj, err := securecookie.New("session", keys, 2*time.Hour)
	if err != nil {
		// ...
	}

The cookie name is prefixed with "__Host-", and the cookie has the
attributes "Path=/", "HttpOnly", "Secure" and "SameSite=Lax". The
SameSite attribute may be changed with an option.

	obj, err := securecookie.New("session", keys, 2*time.Hour,
		securecookie.WithSameSiteStrict())

The key store and the securecookie can also be instantiated as global
variables with the MustNewKeyStore and MustNew functions. These functions
panic if an error occurs.

	var keys = securecookie.MustNewKeyStore(seed)
	var obj = securecookie.MustNew("session", keys, 2*time.Hour)

A securecookie object is immutable. Its methods can be called from
different goroutines.

To set a cookie value, call the SetValue() method with a http.ResponseWriter
w, and a value val as arguments.

	var val = []byte("some value")
	if err := obj.SetValue(w, val); err != nil {
		// ...
	}

The value is retrieved from an http.Request r with the Value() method. The
value is appended to buf, which may be nil, and returned with the time when
it was set.

	val, stamp, err := obj.Value(buf, r)
	if err != nil {
		// ...
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

Values are encrypted and authenticated with AES-128-GCM. The cookie name
is authenticated with the value, so that a value of a cookie can't be used
as value of another cookie. The key changes every two days. It is derived
from the seed and the time, so that no key synchronization is needed
between servers sharing the seed.

Keep the seed secret. Anyone knowing the seed can read and forge values.
For this reason, prefer storing a random session id in the cookie, and
the session data on the server, rather than sensitive data like a user id.
A forged value would then only hold a session id unknown to the server.
*/
package securecookie

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

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

// Obj is a validated cookie object.
type Obj struct {
	name     string
	begStr   string
	endStr   string
	delStr   string
	maxAge   int
	sameSite SameSite
	ks       *KeyStore
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
func MustNew(name string, ks *KeyStore, maxAge time.Duration, opts ...Option) *Obj {
	o, err := New(name, ks, maxAge, opts...)
	if err != nil {
		panic(err)
	}
	return o
}

// New instantiates a validated cookie object with the given cookie name, key
// store, maximum age and options.
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
func New(name string, ks *KeyStore, maxAge time.Duration, opts ...Option) (*Obj, error) {
	if ks == nil {
		return nil, errors.New("securecookie: key store must not be nil")
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
	var o = &Obj{sameSite: SameSiteLax, ks: ks}
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
	return o, nil
}

// hostPrefix is the cookie name prefix added by New.
const hostPrefix = "__Host-"

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
	b, err := o.encodeValue(b, v, time.Now().Unix())
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

// encodeValue appends the encoded value val to dst, with now as time stamp.
// now is the unix time in seconds. dst is allocated if nil, or grown if too
// small. Return dst and the error if any.
//
// The encoded value is the base64 encoding of
//
//	[header][nonce][AES-GCM(stamp ‖ value ‖ padding)][GCM tag]
//
// The cookie name and the header are the additional authenticated data.
func (o *Obj) encodeValue(dst, val []byte, now int64) ([]byte, error) {
	if now < int64(epochOffset) {
		return dst, errClock
	}
	var key = o.ks.current(now)
	var bPtr = bufPool.Get().(*[]byte)
	defer bufPool.Put(bPtr)
	var bLen = len(o.name) + headerLen + nonceLen + maxStampLen + len(val) + maxPaddingLen + tagLen
	if cap(*bPtr) < bLen {
		*bPtr = make([]byte, bLen+20)
	}
	var b = (*bPtr)[:cap(*bPtr)]
	var encPos = copy(b, o.name)
	var noncePos = encPos + headerLen
	var ptPos = noncePos + nonceLen
	b[encPos] = byte(encodingVersion) << 2
	b[encPos+1] = byte(key.period)
	var nonce = b[noncePos:ptPos]
	if err := fillRandom(nonce); err != nil {
		return dst, err
	}
	var endPos = ptPos
	endPos += encodeUint64(b[endPos:], uint64(now)-epochOffset)
	endPos += copy(b[endPos:], val)
	var padPos = endPos
	var nPad = (endPos + tagLen - encPos) % 3
	nPad = (nPad>>1 | nPad<<1) & 3 // computes : 0 -> 0; 1 -> 2; 2 -> 1
	b[encPos] |= byte(nPad)
	endPos += nPad
	for i := padPos; i < endPos; i++ {
		b[i] = 0
	}
	var ct = key.aead.Seal(b[ptPos:ptPos], nonce, b[ptPos:endPos], b[:noncePos])
	return encodeBase64(dst, b[encPos:ptPos+len(ct)]), nil
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

// Value appends the decoded value of the cookie to dst, and returns it with
// the time stamp, truncated to seconds, of when the value was set with
// SetValue. dst is allocated if nil, or grown if too small.
//
// Value returns http.ErrNoCookie when the request has no cookie with the
// object name, and ErrMultipleCookies when it has more than one. The latter
// can't happen with user agents supporting the "__Host-" prefix, unless the
// request was forged. On error, the returned value is nil.
func (o *Obj) Value(dst []byte, r *http.Request) ([]byte, time.Time, error) {
	val, err := o.cookieValue(r.Header["Cookie"])
	if err != nil {
		return nil, time.Time{}, err
	}
	v, stamp, err := o.decodeValue(dst, val, time.Now().Unix())
	if err != nil {
		return nil, time.Time{}, err
	}
	return v, stamp, nil
}

// ErrMultipleCookies is returned by Value when the request has more than
// one cookie with the object name.
var ErrMultipleCookies = errors.New("securecookie: multiple cookies with the same name")

// cookieValue returns the value of the unique cookie with the object name
// in the Cookie header lines. It returns http.ErrNoCookie if there is
// none, and ErrMultipleCookies if there is more than one. The returned
// value is a substring of a line, so no memory is allocated.
func (o *Obj) cookieValue(lines []string) (string, error) {
	var val string
	var found bool
	for _, line := range lines {
		for len(line) > 0 {
			var part string
			if i := strings.IndexByte(line, ';'); i >= 0 {
				part, line = line[:i], line[i+1:]
			} else {
				part, line = line, ""
			}
			part = trimSpace(part)
			if !strings.HasPrefix(part, o.begStr) {
				continue
			}
			if found {
				return "", ErrMultipleCookies
			}
			val, found = part[len(o.begStr):], true
		}
	}
	if !found {
		return "", http.ErrNoCookie
	}
	return val, nil
}

// trimSpace returns s without leading and trailing spaces and tabs.
func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// decodeValue appends the decoded value val to dst, and returns it with
// the time stamp of the value. now is the unix time in seconds. dst is
// allocated if nil, or grown if too small.
func (o *Obj) decodeValue(dst []byte, val string, now int64) ([]byte, time.Time, error) {
	if now < int64(epochOffset) {
		return dst, time.Time{}, errClock
	}
	if len(val) < minEncLen {
		return dst, time.Time{}, errors.New("securecookie: encoded value is too short")
	}
	if len(val) > maxCookieLen {
		return dst, time.Time{}, errTooLong
	}
	var bPtr = bufPool.Get().(*[]byte)
	defer bufPool.Put(bPtr)
	var bLen = len(o.name) + len(val)
	if cap(*bPtr) < bLen {
		*bPtr = make([]byte, bLen+20)
	}
	var b = (*bPtr)[:cap(*bPtr)]
	var encPos = copy(b, o.name)
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
	var key = o.ks.find(b[encPos+1], now)
	if key == nil {
		return dst, time.Time{}, fmt.Errorf("securecookie: invalid key id %d", b[encPos+1])
	}
	var noncePos = encPos + headerLen
	var ptPos = noncePos + nonceLen
	b, err = key.aead.Open(b[ptPos:ptPos], b[noncePos:ptPos], b[ptPos:], b[:noncePos])
	if err != nil {
		return nil, time.Time{}, errors.New("securecookie: invalid encoded cookie value (authentication failed)")
	}
	if nPad > len(b) {
		return dst, time.Time{}, errors.New("securecookie: invalid padding length")
	}
	var pad byte
	for _, c := range b[len(b)-nPad:] {
		pad |= c
	}
	if pad != 0 {
		return dst, time.Time{}, errors.New("securecookie: invalid padding bytes, expected zeros")
	}
	b = b[:len(b)-nPad]
	stamp, stampLen := decodeUint64(b)
	if stampLen == 0 {
		return dst, time.Time{}, errors.New("securecookie: invalid cookie time stamp encoding")
	}
	var valStamp = int64(stamp + epochOffset)
	if now < valStamp || now > valStamp+int64(o.maxAge) {
		return dst, time.Time{}, errors.New("securecookie: invalid cookie time stamp value")
	}
	return append(dst, b[stampLen:]...), time.Unix(valStamp, 0), nil
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

// fillRandom fills b with cryptographically secure pseudorandom bytes.
func fillRandom(b []byte) error {
	if forceError != 0 {
		return errors.New("force error")
	}
	_, err := rand.Read(b)
	return err
}

// encodingVersion is the version of the generated encoding. Version 0 was
// used by the v1 package.
const encodingVersion = 1

// headerLen is the byte length of the encoded value header. The first byte
// holds the encoding version in its 6 most significant bits, and the number
// of padding bytes in its 2 least significant bits. The second byte is the
// id of the key used to encode the value. The header is not encrypted, but
// it is authenticated by AES-GCM.
const headerLen = 2

// epochOffset is the number of seconds to subtract from the unix time to get
// the epoch used in these secure cookies.
const epochOffset uint64 = 1505230500

// nonceLen is the byte length of the AES-GCM nonce.
const nonceLen = 12

// tagLen is the byte length of the AES-GCM authentication tag.
const tagLen = 16

// maxStampLen is the maximum byte length of the time stamp (seconds).
const maxStampLen = 10

// maxPaddingLen is the maximum number of padding bytes.
const maxPaddingLen = 2

// minEncLen is the minimum encoding length of a value.
const minEncLen = ((headerLen+nonceLen+tagLen)*8 + 5) / 6

// maxCookieLen is the maximum length of a cookie.
const maxCookieLen = 4000

// errClock is returned when the system time is before the epoch used for the
// value time stamps (2017-09-12).
var errClock = errors.New("securecookie: invalid system time, before 2017-09-12")

// errTooLong is returned when an encoded value to decode is longer than
// maxCookieLen. Such a value can't have been produced by SetValue, and is
// rejected before any processing.
var errTooLong = fmt.Errorf("securecookie: encoded value is too long, can't exceed %d", maxCookieLen)

// forceError is used for 100% test coverage.
var forceError int

// forceAesError forces aesGCM to return an error. It is used for 100%
// test coverage.
var forceAesError bool

// pool of buffers used for value encoding and decoding.
var bufPool = sync.Pool{New: func() interface{} { var b []byte; return &b }}
