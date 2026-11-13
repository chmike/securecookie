package securecookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

// SeedLen is the byte length of the key store seed.
const SeedLen = 32

// keyPeriod is the duration in seconds of a key period. A new key is used to
// encode values every key period. Periods are counted from the unix epoch, so
// a new period starts every other day at midnight UTC.
const keyPeriod int64 = 2 * 24 * 3600

// maxPast is the number of past periods whose key is still accepted to decode
// values. maxPast*keyPeriod covers MaxMaxAge. The accepted periods, from
// maxPast periods before the current period to the next period, must not
// exceed 256, the number of distinct key ids.
const maxPast = 200

// aesKeyLen is the byte length of the AES-128 keys derived from the seed.
const aesKeyLen = 16

// kdfInfo is the prefix of the HKDF info used to derive the period keys.
const kdfInfo = "securecookie v2 key"

// GenerateSeed returns a random seed of SeedLen bytes.
// Use hex.EncodeToString(seed) to get the seed as hexadecimal string,
// and hex.DecodeString(seedStr) to convert back from string to byte slice.
func GenerateSeed() ([]byte, error) {
	seed := make([]byte, SeedLen)
	if err := fillRandom(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

// MustGenerateSeed returns a random seed of SeedLen bytes.
// It calls GenerateSeed and panics if it returns an error.
func MustGenerateSeed() []byte {
	seed, err := GenerateSeed()
	if err != nil {
		panic("securecookie: generate seed: " + err.Error())
	}
	return seed
}

// KeyStore derives the keys used to encode and decode values from a secret
// seed. A new key is used every two days, and keys of the 200 previous
// periods are still accepted to decode values. The key ids and the keys
// only depend on the seed and the time, so servers sharing the same seed
// use the same keys without any synchronization.
//
// A KeyStore may be shared by different cookie objects and used by
// different goroutines.
type KeyStore struct {
	prk   [sha256.Size]byte // HKDF pseudo random key extracted from the seed
	cur   atomic.Value      // *keyEntry of the current period
	slots [256]atomic.Value // *keyEntry indexed by key id
}

// keyEntry is an immutable key cache entry.
type keyEntry struct {
	period int64 // period index: unix time / keyPeriod
	until  int64 // end of the period in unix time seconds, excluded
	aead   cipher.AEAD
}

// NewKeyStore returns a key store deriving its keys from seed. The seed must
// be SeedLen bytes long and kept secret. Anyone knowing the seed can read
// and forge values.
func NewKeyStore(seed []byte) (*KeyStore, error) {
	if len(seed) != SeedLen {
		return nil, fmt.Errorf("securecookie: seed length is %d, expected %d", len(seed), SeedLen)
	}
	ks := &KeyStore{}
	// HKDF-Extract with a zero salt (RFC 5869)
	mac := hmac.New(sha256.New, make([]byte, sha256.Size))
	mac.Write(seed)
	mac.Sum(ks.prk[:0])
	return ks, nil
}

// MustNewKeyStore panics if NewKeyStore returns a non-nil error, otherwise
// returns the key store. The intended use is to instantiate the key store
// as a global variable.
func MustNewKeyStore(seed []byte) *KeyStore {
	ks, err := NewKeyStore(seed)
	if err != nil {
		panic(err)
	}
	return ks
}

// current returns the key entry of the period containing now. now is the
// unix time in seconds and must not be negative.
func (ks *KeyStore) current(now int64) *keyEntry {
	if e, _ := ks.cur.Load().(*keyEntry); e != nil && now < e.until && now >= e.until-keyPeriod {
		return e // fast path: two comparisons
	}
	e := ks.entry(now / keyPeriod) // once per period
	ks.cur.Store(e)
	return e
}

// find returns the key entry with key id at time now, or nil if id doesn't
// match one of the accepted periods: the next period, the current period,
// and the maxPast previous periods. now is the unix time in seconds and must
// not be negative.
func (ks *KeyStore) find(id byte, now int64) *keyEntry {
	cur := ks.current(now)
	// most frequent case: the value was encoded during the current period
	if byte(cur.period) == id {
		return cur
	}
	period := idToPeriod(id, cur.period)
	if period < 0 || period < cur.period-maxPast {
		return nil // id doesn't match a valid period of the window
	}
	return ks.entry(period)
}

// idToPeriod returns the most recent period with key id, not after the period
// following curPeriod.
func idToPeriod(id byte, curPeriod int64) int64 {
	lastPeriod := curPeriod + 1 // allow one period ahead of the current period
	period := lastPeriod&^0xFF | int64(id)
	if period > lastPeriod {
		period -= 256
	}
	return period
}

// entry returns the key entry of period, deriving the key if the cached entry
// is missing or holds another period.
func (ks *KeyStore) entry(period int64) *keyEntry {
	slot := &ks.slots[byte(period)]
	if e, _ := slot.Load().(*keyEntry); e != nil && e.period == period {
		return e
	}
	e := &keyEntry{period: period, until: (period + 1) * keyPeriod, aead: ks.derive(period)}
	slot.Store(e)
	return e
}

// derive returns the AES-128-GCM AEAD with the key of period. It panics if
// the AEAD can't be created, which can only happen with a bug.
func (ks *KeyStore) derive(period int64) cipher.AEAD {
	key := ks.deriveKey(period)
	aead, err := aesGCM(key[:])
	if err != nil {
		panic(err)
	}
	return aead
}

// deriveKey returns the key of period, derived from the seed with
// HKDF-SHA256 (RFC 5869), where info is kdfInfo followed by the period as a
// big endian 64 bit integer.
func (ks *KeyStore) deriveKey(period int64) [aesKeyLen]byte {
	// HKDF-Expand for a single block: HMAC(prk, info ‖ 0x01)
	var info [len(kdfInfo) + 8 + 1]byte
	copy(info[:], kdfInfo)
	binary.BigEndian.PutUint64(info[len(kdfInfo):], uint64(period))
	info[len(info)-1] = 1
	mac := hmac.New(sha256.New, ks.prk[:])
	mac.Write(info[:])
	var okm [sha256.Size]byte
	mac.Sum(okm[:0])
	var key [aesKeyLen]byte
	copy(key[:], okm[:])
	return key
}

// aesGCM returns the AES-GCM AEAD for key, or the wrapped error returned by
// aes.NewCipher or cipher.NewGCM. When forceAesError is true, the key is
// truncated so that aes.NewCipher returns an error.
func aesGCM(key []byte) (cipher.AEAD, error) {
	if forceAesError {
		key = key[:1]
	}
	block, err := aes.NewCipher(key)
	if err == nil {
		var aead cipher.AEAD
		if aead, err = cipher.NewGCM(block); err == nil {
			return aead, nil
		}
	}
	return nil, fmt.Errorf("securecookie: %w", err)
}
