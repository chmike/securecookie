package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"unsafe"
)

// MACLen is the byte length of the MAC.
const MACLen = md5.Size

/*
Value Encoding: [value][rand][mac]

There are 3,4 or 5 random bytes to randomize the mac. The two less significant bit of the
last random byte encode 0, 1 or 2 which is the number of random bytes minus 3.

The mac is MACLen byte long. It is the size of a hmac md5 and an aes block. The encrypted
mac is used as iv for the aes with ctr that encrypt the value and the random bytes.

The encrypted value, random bytes and the mac is encoded in base64 using the URLEncoding
as defined here https://tools.ietf.org/html/rfc4648#section-5. 0 bits are added to fill the
last byte. No padding is needed because the length of the encrypted bytes is a multiple of
3.
*/

// EncodedValLen return the byte length of the encrypted and base64 encoded value
// of length valLen.
func EncodedValLen(valLen int) int {
	l := valLen + 5 + MACLen
	return ((l-l%3)*8 + 5) / 6
}

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

// KeyLen is the byte length of the key.
const KeyLen = 32

var forceError bool // for 100% coverage

// AppendEncodedStringValue encrypt and encode val in base64 and append it to out.
// Grows out if cap(out) - len(out) < encodedValLen(len(val)).
// Key is a random sequence of KeyLen bytes. Don't use a string.
func AppendEncodedStringValue(out []byte, val string, key []byte) ([]byte, error) {
	// grow out capacity if required
	maxRawLen := len(val) + 5 + MACLen
	encLen := ((maxRawLen-maxRawLen%3)*8 + 5) / 6
	if cap(out)-len(out) < encLen {
		tmp := make([]byte, len(out), encLen)
		copy(tmp, out)
		out = tmp
	}
	// append val to out
	valPos := len(out)
	out = out[:valPos+len(val)]
	copy(out[valPos:], val)
	// append random bytes
	nRnd := 5 - maxRawLen%3
	rndPos := len(out)
	out = out[:rndPos+nRnd]
	if _, err := io.ReadFull(rand.Reader, out[rndPos:]); err != nil || forceError {
		return nil, err
	}
	out[len(out)-1] = (out[len(out)-1] & 0xFC) | byte(nRnd)%3
	// compute and append mac
	mac := hmac.New(md5.New, key[:MACLen])
	mac.Write(out[valPos:])
	ivPos := len(out)
	out = mac.Sum(out)
	iv := out[ivPos:]
	// encrypt value, random bytes and mac
	block, err := aes.NewCipher(key[MACLen:])
	if err != nil {
		return nil, err
	}
	block.Encrypt(iv, iv) // encrypt mac to get iv
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(out[valPos:ivPos], out[valPos:ivPos])
	// encode in base64
	return appendEncodedBase64(out[:valPos], out[valPos:]), nil
}

// AppendEncodedValue encrypt and encode val in base64 and append it to out.
// Grows out if cap(out) - len(out) < encodedValLen(len(val)).
// Key is a random sequence of KeyLen bytes. Don't use a string.
func AppendEncodedValue(out, val []byte, key []byte) ([]byte, error) {
	return AppendEncodedStringValue(out, *(*string)(unsafe.Pointer(&val)), key)
}

var bufPool = sync.Pool{New: func() interface{} { b := make([]byte, 64); return &b }}

// AppendDecodedValue decode base64 and decrypt value in place.
// Return the slice of decoded value.
// Key is a random sequence of KeyLen bytes. Don't use a string.
func AppendDecodedValue(out []byte, val string, key []byte) ([]byte, error) {
	var err error
	if len(val) < (21*8+5)/6 || len(val)%4 != 0 {
		return nil, errors.New("invalid encoded value length")
	}
	// decode base64 encoded val into a temporary buffer
	bPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bPtr)
	b := (*bPtr)[:0]
	if b, err = appendDecodedBase64(b, val); err != nil {
		return nil, err
	}
	bPtr = &b
	// decrypt value
	ivPos := len(b) - MACLen
	iv := b[ivPos:]
	b = b[:ivPos]
	block, err := aes.NewCipher(key[MACLen:])
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(b, b)
	block.Decrypt(iv, iv) // decrypt iv to get mac
	// compute and check mac
	mac := hmac.New(md5.New, key[:MACLen])
	mac.Write(b)
	if !hmac.Equal(iv, mac.Sum(nil)) {
		return nil, errors.New("MAC mismatch")
	}
	// drop random bytes and return slice
	nRnd := int(3 + b[len(b)-1]&0x3)
	if nRnd == 6 {
		return nil, errors.New("invalid number of random bytes")
	}
	b = b[:len(b)-nRnd]
	// append decoded value to out
	return append(out, b...), nil
}

// DecodeStringValue return the encoded value extracted from val using the given key.
func DecodeStringValue(val string, key []byte) (string, error) {
	res, err := AppendDecodedValue(nil, val, key)
	if err != nil {
		return "", err
	}
	return *(*string)(unsafe.Pointer(&res)), nil
}

// encodeBase64 encodes val in place into base64. src and dst may overlap.
// Requires: val != nil && cap(val) >= (len(val)*8+5)/6 && len(val)%3 == 0.
func appendEncodedBase64(dst, src []byte) []byte {
	encLen := (len(src)*8 + 5) / 6
	if cap(dst)-len(dst) < encLen {
		tmp := make([]byte, len(dst), len(dst)+encLen)
		copy(tmp, dst)
		dst = tmp
	}
	srcIdx := len(src)
	dstIdx := len(dst) + encLen
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
	return dst
}

// base64Char converts a byte to Base64 URL encoding.
// The two most significant bits are ignored.
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

// appendDecodedBase64 decode src into dst. src and dst may be the same buffer.
// Requires len(src)%4 == 0 && cap(dst) - len(dst) >= (len(src)*6)/8.
func appendDecodedBase64(dst []byte, src string) ([]byte, error) {
	decLen := (len(src) * 6) / 8
	if cap(dst)-len(dst) < decLen {
		tmp := make([]byte, len(dst), len(dst)+decLen)
		copy(tmp, dst)
		dst = tmp
	}
	var srcIdx int
	dstIdx := len(dst)
	dst = dst[:dstIdx+decLen]
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
