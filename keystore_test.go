package securecookie

import (
	"crypto/aes"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGenerateSeed(t *testing.T) {
	seed, err := GenerateSeed()
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if len(seed) != SeedLen {
		t.Errorf("got seed length %d, expected %d", len(seed), SeedLen)
	}
	forceError = 1
	defer func() { forceError = 0 }()
	if _, err := GenerateSeed(); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestMustGenerateSeed(t *testing.T) {
	if seed := MustGenerateSeed(); len(seed) != SeedLen {
		t.Errorf("got seed length %d, expected %d", len(seed), SeedLen)
	}
	forceError = 1
	defer func() { forceError = 0 }()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	MustGenerateSeed()
}

func TestNewKeyStore(t *testing.T) {
	for _, n := range []int{0, 16, SeedLen - 1, SeedLen + 1, 64} {
		if _, err := NewKeyStore(make([]byte, n)); err == nil {
			t.Errorf("got nil error, expected seed length error for seed length %d", n)
		}
	}
	if _, err := NewKeyStore(nil); err == nil {
		t.Errorf("got nil error, expected seed length error for nil seed")
	}
	if _, err := NewKeyStore(make([]byte, SeedLen)); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestMustNewKeyStore(t *testing.T) {
	MustNewKeyStore(make([]byte, SeedLen))
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	MustNewKeyStore(nil)
}

func TestDeriveKey(t *testing.T) {
	// expected keys computed independently with HKDF-SHA256 (RFC 5869), with
	// a zero salt, the seed 0x00, 0x01, ..., 0x1F, and the info
	// "securecookie v2 key" followed by the big endian 64 bit period.
	seed := make([]byte, SeedLen)
	for i := range seed {
		seed[i] = byte(i)
	}
	ks := MustNewKeyStore(seed)
	tests := []struct {
		period int64
		key    string
	}{
		{period: 0, key: "c20ae69f4cd695f100bdfb2fad418d19"},
		{period: 10000, key: "062098014f2962d90e4b11baeb12b8a4"},
		{period: -1, key: "6f576247083dd0861cdedcdce899707d"},
	}
	for _, test := range tests {
		key := ks.deriveKey(test.period)
		if got := hex.EncodeToString(key[:]); got != test.key {
			t.Errorf("got key %s for period %d, expected %s", got, test.period, test.key)
		}
	}
}

func TestDeriveAesError(t *testing.T) {
	ks := MustNewKeyStore(make([]byte, SeedLen))
	forceAesError = true
	defer func() { forceAesError = false }()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}
		err, ok := r.(error)
		var keyErr aes.KeySizeError
		if !ok || !errors.As(err, &keyErr) {
			t.Errorf("got panic value '%v', expected wrapped aes.KeySizeError", r)
		}
	}()
	ks.derive(0)
}

func TestIdToPeriod(t *testing.T) {
	tests := []struct {
		id        byte
		curPeriod int64
		period    int64
	}{
		// 20406 = 79*256 + 182
		{id: 181, curPeriod: 20405, period: 20405}, // current period
		{id: 182, curPeriod: 20405, period: 20406}, // next period
		{id: 180, curPeriod: 20405, period: 20404}, // previous period
		{id: 183, curPeriod: 20405, period: 20151}, // 255 periods before the next period
		{id: 0, curPeriod: 20405, period: 20224},
		{id: 255, curPeriod: 20405, period: 20223},
		// the next period 20480 = 80*256 has key id 0
		{id: 0, curPeriod: 20479, period: 20480},
		{id: 255, curPeriod: 20479, period: 20479},
		{id: 254, curPeriod: 20479, period: 20478},
		// small periods, with long periods or a clock near the unix epoch
		{id: 57, curPeriod: 56, period: 57},
		{id: 0, curPeriod: 56, period: 0},
		{id: 200, curPeriod: 56, period: -56},
	}
	for _, test := range tests {
		if got := idToPeriod(test.id, test.curPeriod); got != test.period {
			t.Errorf("got period %d for id %d and current period %d, expected %d",
				got, test.id, test.curPeriod, test.period)
		}
	}
}

func TestKeyStoreCurrent(t *testing.T) {
	ks := MustNewKeyStore(make([]byte, SeedLen))
	const p = 20405
	e := ks.current(p * keyPeriod)
	if e.period != p || e.until != (p+1)*keyPeriod {
		t.Fatalf("got period %d until %d, expected period %d until %d", e.period, e.until, p, (p+1)*keyPeriod)
	}
	if e2 := ks.current((p+1)*keyPeriod - 1); e2 != e {
		t.Errorf("got another entry for the last second of the period")
	}
	e3 := ks.current((p + 1) * keyPeriod)
	if e3.period != p+1 {
		t.Errorf("got period %d, expected %d", e3.period, p+1)
	}
	// clock going backward: the cached entry of the period is returned
	if e4 := ks.current(p * keyPeriod); e4 != e {
		t.Errorf("got another entry for period %d", p)
	}
}

func TestKeyStoreFind(t *testing.T) {
	ks := MustNewKeyStore(make([]byte, SeedLen))
	var p int64 = 20405 // a variable, so that byte(p) truncates instead of overflowing
	now := p*keyPeriod + 100
	cur := ks.current(now)
	if e := ks.find(byte(p), now); e != cur {
		t.Errorf("expected the current period entry")
	}
	tests := []struct {
		id     byte
		period int64 // -1 when find must return nil
	}{
		{id: byte(p - 1), period: p - 1},
		{id: byte(p + 1), period: p + 1},
		{id: byte(p - maxPast), period: p - maxPast},
		{id: byte(p - maxPast - 1), period: -1},
		{id: byte(p + 2), period: -1},
	}
	for _, test := range tests {
		e := ks.find(test.id, now)
		if test.period == -1 {
			if e != nil {
				t.Errorf("got period %d for id %d, expected nil", e.period, test.id)
			}
			continue
		}
		if e == nil || e.period != test.period {
			t.Errorf("got entry %+v for id %d, expected period %d", e, test.id, test.period)
		}
	}
	// key ids matching a negative period are rejected
	now = 56 * keyPeriod
	if e := ks.find(200, now); e != nil {
		t.Errorf("got period %d, expected nil", e.period)
	}
	if e := ks.find(0, now); e == nil || e.period != 0 {
		t.Errorf("got entry %+v, expected period 0", e)
	}
}

func TestKeyStoreEntry(t *testing.T) {
	ks := MustNewKeyStore(make([]byte, SeedLen))
	e1 := ks.entry(5)
	if e2 := ks.entry(5); e2 != e1 {
		t.Errorf("expected the cached entry")
	}
	e3 := ks.entry(5 + 256) // same slot, other period
	if e3 == e1 || e3.period != 5+256 {
		t.Errorf("expected a new entry for period %d", 5+256)
	}
	e4 := ks.entry(5) // derived again
	if e4 == e1 || e4.period != 5 {
		t.Errorf("expected a new entry for period 5")
	}
	// the derived keys only depend on the seed and the period
	nonce := make([]byte, nonceLen)
	ct := e1.aead.Seal(nil, nonce, []byte("value"), nil)
	if _, err := e4.aead.Open(nil, nonce, ct, nil); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if _, err := e3.aead.Open(nil, nonce, ct, nil); err == nil {
		t.Errorf("unexpected nil error")
	}
}

// TestKeyStoreConcurrency is meant to be run with the race detector:
// go test -race -run Concurrency
func TestKeyStoreConcurrency(t *testing.T) {
	ks := MustNewKeyStore(make([]byte, SeedLen))
	const p = 20405
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				now := int64(p+i%3) * keyPeriod
				if e := ks.find(byte(p+i%3-g), now); e == nil {
					t.Errorf("unexpected nil entry")
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestKeyRotationBoundary(t *testing.T) {
	obj := MustNew("test", MustNewKeyStore(make([]byte, SeedLen)), time.Hour)
	boundary := (time.Now().Unix()/keyPeriod + 1) * keyPeriod // start of the next period
	last := boundary - 1                                      // last second of the current period

	before, err := obj.encodeValue(nil, []byte("before"), last)
	if err != nil {
		t.Fatal(err)
	}
	after, err := obj.encodeValue(nil, []byte("after"), boundary)
	if err != nil {
		t.Fatal(err)
	}

	// the key changes at the boundary
	decBefore, err := decodeBase64(nil, string(before))
	if err != nil {
		t.Fatal(err)
	}
	decAfter, err := decodeBase64(nil, string(after))
	if err != nil {
		t.Fatal(err)
	}
	if idBefore, idAfter := decBefore[1], decAfter[1]; idAfter != idBefore+1 {
		t.Errorf("got key ids %d and %d, expected consecutive key ids", idBefore, idAfter)
	}

	// a value encoded in the last second of a period is decoded in the
	// first second of the next period
	v, stamp, err := obj.decodeValue(nil, string(before), boundary)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else if string(v) != "before" || stamp.Unix() != last {
		t.Errorf("got value '%s' with stamp %d, expected 'before' with stamp %d", v, stamp.Unix(), last)
	}
	// a value encoded at the boundary is decoded in the same second
	if v, _, err = obj.decodeValue(nil, string(after), boundary); err != nil || string(v) != "after" {
		t.Errorf("got value '%s' and error '%v', expected 'after' and no error", v, err)
	}
	// a value encoded at the boundary is rejected one second before, since
	// its time stamp is in the future
	if _, _, err = obj.decodeValue(nil, string(after), last); err == nil || !strings.Contains(err.Error(), "time stamp value") {
		t.Errorf("got error '%v', expected time stamp value error", err)
	}
	// the value encoded before the boundary stays valid until its max age,
	// with the key of the previous period
	if _, _, err = obj.decodeValue(nil, string(before), last+3600); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if _, _, err = obj.decodeValue(nil, string(before), last+3601); err == nil || !strings.Contains(err.Error(), "time stamp value") {
		t.Errorf("got error '%v', expected time stamp value error", err)
	}
}
