package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"io"
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

// KeyLen is the byte length of the key.
const KeyLen = 32

// EncodeValue encrypt and encode in base64 the content of val in place.
// Grows val when cap(val) < encodedValLen(len(val)).
// Key is a random sequence of KeyLen bytes. Don't use a string.
func EncodeValue(val []byte, key []byte) ([]byte, error) {
	// grow val capacity if required
	maxRawLen := len(val) + 5 + MACLen
	encLen := ((maxRawLen-maxRawLen%3)*8 + 5) / 6
	if cap(val) < encLen {
		tmp := make([]byte, len(val), encLen)
		copy(tmp, val)
		val = tmp
	}
	// append random bytes
	nRnd := 5 - maxRawLen%3
	val = val[:len(val)+nRnd]
	if _, err := io.ReadFull(rand.Reader, val[len(val)-nRnd:]); err != nil {
		return nil, err
	}
	val[len(val)-1] = (val[len(val)-1] & 0xFC) | byte(nRnd)%3
	// compute and append mac
	mac := hmac.New(md5.New, key[:hmacKeyLen])
	if _, err := mac.Write(val); err != nil {
		return nil, err
	}
	ivPos := len(val)
	mac.Sum(val)
	// encrypt value, random bytes and mac
	iv := val[ivPos:]
	block, err := aes.NewCipher(key[hmacKeyLen:])
	if err != nil {
		return nil, err
	}
	block.Encrypt(iv, iv) // encrypt mac to get iv
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(val[:ivPos], val[:ivPos])
	// encode in base64
	return encodeBase64(val), nil
}

// DecodeValue decode base64 and decrypt value in place.
// Return the slice of value bytes.
// Key is a random sequence of KeyLen bytes. Don't use a string.
func DecodeValue(val []byte, key []byte) ([]byte, error) {
	if len(val)%4 != 0 {
		return errors.New("invalid encoded value length")
	}
	// decode base64
	val, err := decodeBase64(val)
	if err != nil {
		return nil, err
	}
	// decrypt value
	ivPos := len(val) - MACLen
	iv := val[ivPos:]
	val = val[:ivPos]
	block, err := aes.NewCipher(key[hmacKeyLen:])
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(val, val)
	block.Decrypt(iv, iv) // decrypt iv to get mac
	// compute and check mac
	mac := hmac.New(md5.New, key[:hmacKeyLen])
	if _, err := mac.Write(val); err != nil {
		return nil, err
	}
	if !hmac.Equal(iv, mac.Sum(nil)) {
		return nil, errors.New("MAC mismatch")
	}
	// drop random bytes and return value
	nRnd := int(3 + val[len(val)-1]&0x3)
	if nRnd == 6 {
		return nil, errors.New("invalid number of random bytes")
	}
	return val[:len(val)-nRnd], nil
}

// encodeBase64 encodes val in place into base64.
// Requires: val != nil && cap(val) >= (len(val)*8+5)/6 && len(val)%3 == 0.
func encodeBase64(val []byte) []byte {
	src := len(val)
	dst := (src*8 + 5) / 6
	val = val[:dst]
	for src > 0 {
		v := uint64(val[src-1]) | uint64(val[src-2])<<8 | uint64(val[src-3])<<16
		val[dst-1] = base64Char(byte(v))
		val[dst-2] = base64Char(byte(v >> 6))
		val[dst-3] = base64Char(byte(v >> 12))
		val[dst-4] = base64Char(byte(v >> 18))
		src -= 3
		dst -= 4
	}
	return val
}

// base64Byte2Char converts a byte to Base64 URL encoding.
// The two most significant bits are ignored.
// See https://tools.ietf.org/html/rfc4648#section-5.
func base64Char(b byte) byte {
	b &= 0x3F
	switch {
	case b < 26:
		return b + 'A'
	case b < 52:
		return b + 'a' - 26
	case b < 62:
		return b + '0' - 52
	case b == 62:
		return '-'
	case b == 63:
		return '_'
	}
	return 0 // never reached
}

// decodeBase64 decode base64 encoded val in place.
// requires len(val)%4 == 0.
func decodeBase64(val []byte) ([]byte, error) {
	var src, dst int
	for dst < len(val) {
		var v uint64
		for i := 0; i < 4; i++ {
			b := val[src]
			src++
			switch {
			case b >= 'A' && b <= 'Z':
				v = (v << 6) | uint64(b-'A')
			case b >= 'a' && b <= 'z':
				v = (v << 6) | uint64(b-'a'+26)
			case b >= '0' && b <= '9':
				v = (v << 6) | uint64(b-'0'+52)
			case b == '-':
				v = (v << 6) | uint64(62)
			case b == '_':
				v = (v << 6) | uint64(63)
			default:
				return nil, errors.New("invalid base64 char")
			}
		}
		val[dst] = byte(v >> 16)
		dst++
		val[dst] = byte(v >> 8)
		dst++
		val[dst] = byte(v)
		dst++
	}
	return val[:src], nil
}
