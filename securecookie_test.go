package securecookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
)

func TestGenerateKeyErrors(t *testing.T) {
	if _, err := GenerateRandomKey(); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	forceError = 1
	defer func() { forceError = 0 }()
	if _, err := GenerateRandomKey(); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestMustGenerateRandomKey(t *testing.T) {
	key := MustGenerateRandomKey()
	if len(key) != KeyLen {
		t.Errorf("len of key is %d, expected %d", len(key), KeyLen)
	}
	forceError = 1
	defer func() { forceError = 0 }()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	MustGenerateRandomKey()
}

func TestCheckName(t *testing.T) {
	if err := checkName("toto"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := checkName("TOTO"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := checkName("?"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkName(""); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkName("\t"); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func (o1 *Obj) Equal(o2 *Obj) bool {
	if o1 == nil || o2 == nil {
		return o1 == o2
	}
	return o1.name == o2.name && o1.maxAge == o2.maxAge && o1.sameSite == o2.sameSite
}

func TestMustNew(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	MustNew("test", nil, time.Hour)
}

func TestNewKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 24, KeyLen - 1, KeyLen + 1, 48, 64} {
		_, err := New("test", make([]byte, n), time.Hour)
		if err == nil {
			t.Errorf("got nil error, expected key length error for key length %d", n)
			continue
		}
		if !strings.Contains(err.Error(), "key length") {
			t.Errorf("got error '%s', expected key length error for key length %d", err, n)
		}
	}
	if _, err := New("test", nil, time.Hour); err == nil || !strings.Contains(err.Error(), "key length") {
		t.Errorf("got error '%v', expected key length error for nil key", err)
	}
}

func TestNewAesError(t *testing.T) {
	forceAesError = true
	defer func() { forceAesError = false }()
	_, err := New("test", make([]byte, KeyLen), time.Hour)
	if err == nil {
		t.Fatal("unexpected nil error")
	}
	var keyErr aes.KeySizeError
	if !errors.As(err, &keyErr) {
		t.Errorf("got error '%s', expected wrapped aes.KeySizeError", err)
	}
}

func TestNew(t *testing.T) {
	k := make([]byte, KeyLen)
	kb := make([]byte, KeyLen*3)
	n := "test"
	fn := "__Host-test"
	h := time.Hour
	tests := []struct {
		k    []byte
		n    string
		m    time.Duration
		opts []Option
		o    *Obj
		fail bool
	}{
		{k: k, n: n, m: h, o: &Obj{name: fn, maxAge: 3600, sameSite: SameSiteLax}},
		{k: k[:len(k)-1], n: n, m: h, fail: true},
		{k: kb, n: n, m: h, fail: true},
		{k: k, n: "", m: h, fail: true},
		{k: k, n: "te;st", m: h, fail: true},
		{k: k, n: "__Host-test", m: h, fail: true},
		{k: k, n: "__host-test", m: h, fail: true},
		{k: k, n: "__Secure-test", m: h, fail: true},
		{k: k, n: "__SECURE-test", m: h, fail: true},
		{k: k, n: "_Host-test", m: h, o: &Obj{name: "__Host-_Host-test", maxAge: 3600, sameSite: SameSiteLax}},
		{k: k, n: n, m: 0, fail: true},
		{k: k, n: n, m: -h, fail: true},
		{k: k, n: n, m: 999 * time.Millisecond, fail: true},
		{k: k, n: n, m: 1500 * time.Millisecond, o: &Obj{name: fn, maxAge: 1, sameSite: SameSiteLax}},
		{k: k, n: n, m: MaxMaxAge, o: &Obj{name: fn, maxAge: 400 * 24 * 3600, sameSite: SameSiteLax}},
		{k: k, n: n, m: MaxMaxAge + time.Second, fail: true},
		{k: k, n: n, m: h, opts: []Option{WithSameSiteLax()}, o: &Obj{name: fn, maxAge: 3600, sameSite: SameSiteLax}},
		{k: k, n: n, m: h, opts: []Option{WithSameSiteStrict()}, o: &Obj{name: fn, maxAge: 3600, sameSite: SameSiteStrict}},
		{k: k, n: n, m: h, opts: []Option{WithSameSite(SameSiteStrict)}, o: &Obj{name: fn, maxAge: 3600, sameSite: SameSiteStrict}},
		{k: k, n: n, m: h, opts: []Option{WithSameSiteStrict(), WithSameSiteLax()}, o: &Obj{name: fn, maxAge: 3600, sameSite: SameSiteLax}},
		{k: k, n: n, m: h, opts: []Option{WithSameSite(0)}, fail: true},
		{k: k, n: n, m: h, opts: []Option{WithSameSite(SameSiteStrict + 1)}, fail: true},
	}
	for _, test := range tests {
		obj, err := New(test.n, test.k, test.m, test.opts...)
		if err != nil && !test.fail {
			t.Errorf("got error '%s', expected no error for %+v", err, test)
			continue
		}
		if err == nil && test.fail {
			t.Errorf("got nil error, expected to fail for %+v", test)
			continue
		}
		if err != nil || test.fail {
			continue
		}
		if !obj.Equal(test.o) {
			t.Errorf("got object %+v, expected %+v for input %+v", *obj, *test.o, test)
		}
	}
}

func TestAccessorsMethods(t *testing.T) {
	key := MustGenerateRandomKey()
	obj, err := New("test", key, time.Hour, WithSameSiteStrict())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if obj.Name() != "__Host-test" {
		t.Errorf("got name '%s', expected '%s'", obj.Name(), "__Host-test")
	}
	if obj.MaxAge() != time.Hour {
		t.Errorf("got max age %s, expected %s", obj.MaxAge(), time.Hour)
	}
	if obj.SameSite() != SameSiteStrict {
		t.Errorf("got same site %d, expected SameSiteStrict (%d)", obj.SameSite(), SameSiteStrict)
	}
}

func TestEncodeBase64(t *testing.T) {
	tests := []struct {
		in, out []byte
	}{ // requires that len(in)%3 == 0
		{in: []byte{}, out: []byte{}},
		{in: []byte{0, 0, 0}, out: []byte{65, 65, 65, 65}},
		{in: []byte{255, 255, 255}, out: []byte{95, 95, 95, 95}},
		{in: []byte{0, 1, 2, 3, 4, 5}, out: []byte{65, 65, 69, 67, 65, 119, 81, 70}},
		{in: []byte{3, 200, 254}, out: []byte{65, 56, 106, 45}},
	} // out == base64.URLEncoding.WithPadding(base64.NoPadding).Encode(out, in)
	for _, test := range tests {
		var encLen = (len(test.in)*8 + 5) / 6
		var buf = make([]byte, 0, encLen+10)
		out := encodeBase64(buf, test.in)
		if !bytes.Equal(out, test.out) {
			t.Errorf("got base64 encoding output %v, expected %v for input %v", out, test.out, test.in)
			continue
		}

		outStr := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(test.in)
		if !bytes.Equal([]byte(outStr), test.out) {
			t.Errorf("got base64 encoding output %v, expected %v for input %v", out, test.out, test.in)
			continue
		}
	}
}

func TestDecodeBase64(t *testing.T) {
	tests := []struct {
		in   string
		out  []byte
		fail bool
	}{ // requires that len(in)%4 == 0
		{in: "", out: []byte{}},
		{in: "AAAA", out: []byte{0, 0, 0}},
		{in: "____", out: []byte{255, 255, 255}},
		{in: "AAECAwQF", out: []byte{0, 1, 2, 3, 4, 5}},
		{in: "AAEC AwQF", out: nil, fail: true},
		{in: "A8j-", out: []byte{3, 200, 254}},
		{in: " A8j", out: nil, fail: true},
	} // out == base64.URLEncoding.WithPadding(base64.NoPadding).Encode(out, in)
	for _, test := range tests {
		out, err := decodeBase64(nil, test.in)
		if err != nil && !test.fail {
			t.Errorf("got base64 decoding error '%s', expected no error", err)
			continue
		}
		if err == nil && test.fail {
			t.Errorf("got base64 decoding nil error, expected to fail")
			continue
		}
		if test.fail || err != nil {
			continue
		}
		if !bytes.Equal(out, test.out) {
			t.Errorf("got base64 decoding output %v, expected %v for input '%v'", out, test.out, test.in)
		}
		stdOut, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(test.in)
		if err != nil {
			t.Errorf("unexpected error for input '%s': %s", test.in, err)
			continue
		}
		if !bytes.Equal(test.out, stdOut) {
			t.Errorf("got base64 decoding output %v, expected %v for input '%v'", stdOut, test.out, test.in)
		}
	}
}

func bytes2Str(b []byte) string {
	var out bytes.Buffer
	out.Grow(len(b) * 6)
	out.WriteByte('[')
	for i := range b {
		out.WriteString(fmt.Sprintf("0x%02X, ", b[i]))
	}
	res := out.Bytes()
	res[len(res)-2] = ']'
	return string(res[:len(res)-1])
}

func TestEncodedUint64(t *testing.T) {
	tests := []struct {
		in  uint64
		out []byte
	}{
		{in: 0x0000000000000001, out: []byte{0x01}},
		{in: 0x0000000000000080, out: []byte{0x80, 0x01}},
		{in: 0x0000000000004000, out: []byte{0x80, 0x80, 0x01}},
		{in: 0x0002000000000000, out: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}},
		{in: 0x8000000000000000, out: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}},
		{in: 0xFFFFFFFFFFFFFFFF, out: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}},
	}
	for _, test := range tests {
		out := make([]byte, 10)
		out = out[:encodeUint64(out, test.in)]
		if !bytes.Equal(out, test.out) {
			t.Errorf("got %s, expected %s for %#X", bytes2Str(out), bytes2Str(test.out), test.in)
		}
	}
}

func TestDecodeUint64(t *testing.T) {
	tests := []struct {
		in  []byte
		out uint64
		n   int
	}{
		{out: 0x0000000000000001, in: []byte{0x01}, n: 1},
		{out: 0x0000000000000080, in: []byte{0x80, 0x01}, n: 2},
		{out: 0x0000000000004000, in: []byte{0x80, 0x80, 0x01}, n: 3},
		{out: 0x0002000000000000, in: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, n: 8},
		{out: 0x8000000000000000, in: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, n: 10},
		{out: 0xFFFFFFFFFFFFFFFF, in: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}, n: 10},
		{in: nil},
		{in: []byte{}},
		{in: []byte{0x80}},
		{in: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}},
	}
	for _, test := range tests {
		out, n := decodeUint64(test.in)
		if n != test.n {
			t.Errorf("got n %d, expected %d", n, test.n)
		}
		if out != test.out {
			t.Errorf("got 0x%X, expected 0x%X for %s", out, test.out, bytes2Str(test.in))
		}
	}
}

func TestXorCtrAes(t *testing.T) {
	var iv = make([]byte, aes.BlockSize)
	var txt = []byte(strings.Repeat("test ", 10))
	var ref = []byte(strings.Repeat("test ", 10))
	var key = make([]byte, aes.BlockSize*2)
	obj, err := New("name", key, time.Hour)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	// cipher
	obj.xorCtrAes(iv, txt)
	// decipher
	block, err := aes.NewCipher(key[len(key)/2:])
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	var stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(txt, txt)
	if !bytes.Equal(txt, ref) {
		t.Errorf("ctr aes ciphering error")
	}
}

func TestHmacSha256(t *testing.T) {
	var txt = []byte(strings.Repeat("test ", 10))
	var key = make([]byte, aes.BlockSize*2)
	obj, err := New("name", key, time.Hour)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	var mac1 = make([]byte, hmacLen)
	// ipad must be prepended to the txt to hash
	var tmp = make([]byte, sha256.BlockSize+len(txt))
	copy(tmp[copy(tmp, obj.ipad[:]):], txt)
	var n = obj.hmacSha256(mac1, tmp)
	if n != len(mac1) {
		t.Fatalf("got n %d, expected %d", n, len(mac1))
	}
	var mac = hmac.New(sha256.New, key[:len(key)/2])
	mac.Write(txt)
	var mac2 = mac.Sum(nil)
	if !bytes.Equal(mac1, mac2) {
		t.Errorf("got mac: \n%s\n expected mac: \n%s", bytes2Str(mac1), bytes2Str(mac2))
	}
}

func TestEncodeDecodeValue(t *testing.T) {
	tests := []struct {
		in               []byte
		encFail, decFail bool
	}{
		{in: []byte{}},
		{in: []byte{0}},
		{in: []byte{0, 0, 0}},
		{in: []byte{255, 255, 255}},
		{in: []byte{0, 1, 2, 3, 4}},
		{in: []byte{0, 1, 2, 3, 4, 5}},
		{in: []byte{3, 200, 254}},
	}
	obj, err := New("test", make([]byte, KeyLen), time.Hour)
	if err != nil {
		panic(err)
	}
	for _, test := range tests {
		out, err := obj.encodeValue(nil, test.in)
		if (err == nil) == test.encFail {
			if err == nil {
				t.Errorf("got nil encoding error, expected error for in: %+v", test.in)
			} else {
				t.Errorf("got encoding error '%s', expected nil error for in: %+v", err, test.in)
			}
		} else {
			in, _, err := obj.decodeValue(nil, string(out))
			if (err == nil) == test.decFail {
				if err == nil {
					t.Errorf("got nil decoding error, expected failure for in: %+v", test.in)
				} else {
					t.Errorf("got decoding error '%s', expected nil error for in: %+v", err, test.in)
				}
			} else {
				if !bytes.Equal(in, test.in) {
					t.Errorf("encoding->decoding mismatch")
				}
			}
		}
	}
}

func TestEncodeValueErrors(t *testing.T) {
	obj, err := New("test", make([]byte, KeyLen), time.Hour)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 0, 59)
	forceError = 1
	defer func() { forceError = 0 }()
	if _, err := obj.encodeValue(buf, []byte{}); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func purgeBufPool() {
	for {
		var bPtr = bufPool.Get().(*[]byte)
		if len(*bPtr) == 0 {
			break
		}
	}
}

func TestDecodeValueErrorsA(t *testing.T) {
	obj, err := New("test", make([]byte, KeyLen), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := obj.decodeValue(nil, ""); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, _, err := obj.decodeValue(nil, " "+strings.Repeat("A", minEncLen)); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, _, err := obj.decodeValue(nil, "zA"+strings.Repeat("A", minEncLen)); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, _, err := obj.decodeValue(nil, strings.Repeat("A", maxCookieLen+4)); err != errTooLong {
		t.Errorf("got error '%v', expected '%v'", err, errTooLong)
	}
	buf, err := obj.encodeValue(nil, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	buf[len(buf)-1]--
	if _, _, err := obj.decodeValue(nil, string(buf)); err == nil {
		t.Errorf("unexpected nil error")
	}
	buf[len(buf)-1]++

	obj.maxAge -= 10000
	if _, _, err := obj.decodeValue(nil, string(buf)); err == nil {
		t.Errorf("unexpected nil error")
	}
	obj.maxAge += 10000
}

func TestDecodeValueErrorsB(t *testing.T) {
	obj, err := New("test", make([]byte, KeyLen), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := obj.encodeValue(nil, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	// set an invalid paddingLen value
	dec, err := decodeBase64(nil, string(buf))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	dec[0] |= 3
	dec = dec[:len(dec)-hmacLen]
	var hm = hmac.New(sha256.New, make([]byte, KeyLen/2))
	hm.Write([]byte(obj.name))
	hm.Write(dec)
	dec = hm.Sum(dec)
	buf = encodeBase64(buf[:0], dec)
	if _, _, err := obj.decodeValue(nil, string(buf)); err == nil {
		t.Errorf("unexpected nil error")
	}
	// set an invalid stamp encoding
	buf, err = obj.encodeValue(nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	dec, err = decodeBase64(nil, string(buf))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	dec = dec[:len(dec)-hmacLen]
	obj.xorCtrAes(dec[headerLen:headerLen+ivLen], dec[headerLen+ivLen:])
	for i := headerLen + ivLen; i < headerLen+ivLen+10; i++ {
		dec[i] |= 0x80
	}
	obj.xorCtrAes(dec[headerLen:headerLen+ivLen], dec[headerLen+ivLen:])
	hm.Reset()
	hm.Write([]byte(obj.name))
	hm.Write(dec)
	dec = hm.Sum(dec)
	buf = encodeBase64(buf[:0], dec)
	purgeBufPool()
	if _, _, err := obj.decodeValue(nil, string(buf)); err == nil {
		t.Errorf("unexpected nil error")
	}
	// set an unknown key id with a valid MAC
	buf, err = obj.encodeValue(nil, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	dec, err = decodeBase64(nil, string(buf))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if dec[1] != 0 {
		t.Errorf("got key id %d, expected 0", dec[1])
	}
	dec[1] = 1
	dec = dec[:len(dec)-hmacLen]
	hm.Reset()
	hm.Write([]byte(obj.name))
	hm.Write(dec)
	dec = hm.Sum(dec)
	buf = encodeBase64(buf[:0], dec)
	if _, _, err := obj.decodeValue(nil, string(buf)); err == nil || !strings.Contains(err.Error(), "unknown key id 1") {
		t.Errorf("got error '%v', expected unknown key id error", err)
	}
	// modify the key id without updating the MAC
	dec[1] = 0
	buf = encodeBase64(buf[:0], dec)
	if _, _, err := obj.decodeValue(nil, string(buf)); err == nil || !strings.Contains(err.Error(), "MAC mismatch") {
		t.Errorf("got error '%v', expected MAC mismatch error", err)
	}
	// check the encoding version
	if dec[0]>>2 != encodingVersion {
		t.Errorf("got encoding version %d, expected %d", dec[0]>>2, encodingVersion)
	}
	// check that padding bytes are zero, and set a non-zero padding byte
	// with a valid MAC
	var nPad int
	for n := 0; nPad == 0; n++ {
		buf, err = obj.encodeValue(nil, make([]byte, n))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		dec, err = decodeBase64(nil, string(buf))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		nPad = int(dec[0] & 3)
	}
	dec = dec[:len(dec)-hmacLen]
	obj.xorCtrAes(dec[headerLen:headerLen+ivLen], dec[headerLen+ivLen:])
	for i, c := range dec[len(dec)-nPad:] {
		if c != 0 {
			t.Errorf("got padding byte %d with value %d, expected 0", i, c)
		}
	}
	dec[len(dec)-1] = 1
	obj.xorCtrAes(dec[headerLen:headerLen+ivLen], dec[headerLen+ivLen:])
	hm.Reset()
	hm.Write([]byte(obj.name))
	hm.Write(dec)
	dec = hm.Sum(dec)
	buf = encodeBase64(buf[:0], dec)
	if _, _, err := obj.decodeValue(nil, string(buf)); err == nil || !strings.Contains(err.Error(), "invalid padding bytes") {
		t.Errorf("got error '%v', expected invalid padding bytes error", err)
	}
	// padding length bigger than the encrypted data, with a valid MAC
	dec = make([]byte, headerLen+ivLen+1)
	dec[0] = byte(encodingVersion)<<2 | 2
	hm.Reset()
	hm.Write([]byte(obj.name))
	hm.Write(dec)
	dec = hm.Sum(dec)
	buf = encodeBase64(buf[:0], dec)
	if _, _, err := obj.decodeValue(nil, string(buf)); err == nil || !strings.Contains(err.Error(), "invalid padding length") {
		t.Errorf("got error '%v', expected invalid padding length error", err)
	}
}

func TestDecodeValueErrorsC(t *testing.T) {
	obj, err := New("test", make([]byte, KeyLen), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := obj.decodeValue(nil, ""); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, _, err := obj.decodeValue(nil, " "+strings.Repeat("A", minEncLen)); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, _, err := obj.decodeValue(nil, "zA"+strings.Repeat("A", minEncLen)); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, _, err := obj.decodeValue(nil, strings.Repeat("A", maxCookieLen+4)); err != errTooLong {
		t.Errorf("got error '%v', expected '%v'", err, errTooLong)
	}
	buf, err := obj.encodeValue(nil, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	buf[len(buf)-1]--
	if _, _, err := obj.decodeValue(nil, string(buf)); err == nil {
		t.Errorf("unexpected nil error")
	}
	buf[len(buf)-1]++

	if _, _, err := obj.decodeValue(nil, string(buf)); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestSetAndGetCookie(t *testing.T) {
	obj, err := New("test", make([]byte, KeyLen), time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	recorder := httptest.NewRecorder()
	inValue := []byte("some value")
	now := time.Now().Truncate(time.Second)
	err = obj.SetValue(recorder, inValue)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	request := &http.Request{Header: http.Header{"Cookie": recorder.Header().Values("Set-Cookie")}}
	outValue, stamp, err := obj.Value(nil, request)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else if !bytes.Equal(outValue, inValue) {
		t.Errorf("got value '%s', expected '%s'", outValue, inValue)
	}
	if stampDiff := stamp.Sub(now); stampDiff > time.Second || stampDiff < -time.Second {
		t.Error("invalid stamp diff:", stampDiff)
	}

	// value appended to dst
	dst := []byte("prefix:")
	outValue, _, err = obj.Value(dst, request)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else if string(outValue) != "prefix:some value" {
		t.Errorf("got value '%s', expected '%s'", outValue, "prefix:some value")
	}

	// invalid value
	badRequest := &http.Request{Header: http.Header{"Cookie": {obj.Name() + "=AAAA"}}}
	outValue, stamp, err = obj.Value(nil, badRequest)
	if err == nil {
		t.Errorf("unexpected nil error")
	}
	if outValue != nil || !stamp.IsZero() {
		t.Errorf("got value %v and stamp %v, expected nil and zero time", outValue, stamp)
	}

	// non-existent cookie
	obj.begStr = "xxx="
	outValue, _, err = obj.Value(nil, request)
	if err != http.ErrNoCookie {
		t.Errorf("got error '%v', expected '%v'", err, http.ErrNoCookie)
	} else if outValue != nil {
		t.Errorf("unexpected non-nil value")
	}

	// force too big cookie error
	recorder = httptest.NewRecorder()
	err = obj.SetValue(recorder, []byte(strings.Repeat(" ", maxCookieLen)))
	if err == nil {
		t.Errorf("unexpected nil error")
	}

	// force encoding error
	forceError = 1
	defer func() { forceError = 0 }()
	recorder = httptest.NewRecorder()
	err = obj.SetValue(recorder, []byte(strings.Repeat(" ", maxCookieLen)))
	if err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestMultipleCookies(t *testing.T) {
	obj, err := New("test", make([]byte, KeyLen), time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	recorder := httptest.NewRecorder()
	if err = obj.SetValue(recorder, []byte("some value")); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if err = obj.SetValue(recorder, []byte("other value")); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	request := &http.Request{Header: http.Header{"Cookie": recorder.Header().Values("Set-Cookie")}}
	outValue, stamp, err := obj.Value(nil, request)
	if err != ErrMultipleCookies {
		t.Errorf("got error '%v', expected '%v'", err, ErrMultipleCookies)
	}
	if outValue != nil || !stamp.IsZero() {
		t.Errorf("got value %v and stamp %v, expected nil and zero time", outValue, stamp)
	}
}

func TestCookieValue(t *testing.T) {
	obj, err := New("test", make([]byte, KeyLen), time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	tests := []struct {
		lines []string
		val   string
		err   error
	}{
		{lines: nil, err: http.ErrNoCookie},
		{lines: []string{""}, err: http.ErrNoCookie},
		{lines: []string{"a=b; c=d"}, err: http.ErrNoCookie},
		{lines: []string{"test=v"}, err: http.ErrNoCookie},
		{lines: []string{"__Host-test2=v"}, err: http.ErrNoCookie},
		{lines: []string{"x__Host-test=v"}, err: http.ErrNoCookie},
		{lines: []string{"__Host-test"}, err: http.ErrNoCookie},
		{lines: []string{"__host-test=v"}, err: http.ErrNoCookie},
		{lines: []string{"__Host-test=v"}, val: "v"},
		{lines: []string{"__Host-test="}, val: ""},
		{lines: []string{"a=b; __Host-test=v; c=d"}, val: "v"},
		{lines: []string{"a=b;__Host-test=v;c=d"}, val: "v"},
		{lines: []string{"a=b; \t__Host-test=v \t; c=d"}, val: "v"},
		{lines: []string{"a=b", "__Host-test=v"}, val: "v"},
		{lines: []string{"__Host-test=v; __Host-test=w"}, err: ErrMultipleCookies},
		{lines: []string{"__Host-test=v", "__Host-test=v"}, err: ErrMultipleCookies},
		{lines: []string{"__Host-test=v; a=b", "c=d; __Host-test=x"}, err: ErrMultipleCookies},
	}
	for _, test := range tests {
		val, err := obj.cookieValue(test.lines)
		if err != test.err {
			t.Errorf("got error '%v', expected '%v' for %q", err, test.err, test.lines)
			continue
		}
		if val != test.val {
			t.Errorf("got value %q, expected %q for %q", val, test.val, test.lines)
		}
	}
}

func TestDeleteCookie(t *testing.T) {
	tests := []struct {
		opt  Option
		want string
	}{
		{opt: WithSameSiteLax(), want: "__Host-test=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax"},
		{opt: WithSameSiteStrict(), want: "__Host-test=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict"},
	}
	for _, test := range tests {
		obj, err := New("test", make([]byte, KeyLen), time.Hour, test.opt)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		recorder := httptest.NewRecorder()
		if err := obj.Delete(recorder); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if got := recorder.Header().Get("Set-Cookie"); got != test.want {
			t.Errorf("got Set-Cookie %q, expected %q", got, test.want)
		}
	}
}

func TestChmikeValueLen(t *testing.T) {
	var name = "test"
	var inValue = []byte("some value")
	var recorder = httptest.NewRecorder()
	var key = make([]byte, KeyLen)
	obj, err := New(name, key, time.Hour)
	if err != nil {
		panic(err)
	}
	err = obj.SetValue(recorder, inValue)
	if err != nil {
		panic(err)
	}
	request := &http.Request{Header: http.Header{"Cookie": recorder.Header().Values("Set-Cookie")}}
	c, err := request.Cookie(obj.Name())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Chmike value:", c.Value, "len:", len(c.Value))
}

func TestGorillaValueLen(t *testing.T) {
	var name = "__Host-test"
	var inValue = []byte("some value")
	for _, nop := range []bool{false, true} {
		encoded, err := gorillaCodec(nop).Encode(name, inValue)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("Gorilla value (NopEncoder:", nop, "):", encoded, "len:", len(encoded))
	}
}

func TestCookieText(t *testing.T) {
	key := MustGenerateRandomKey()
	loginCookie, err := New("login", key, 15*24*time.Hour, WithSameSiteStrict())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	var recorder = httptest.NewRecorder()
	if err := loginCookie.SetValue(recorder, []byte{}); err != nil {
		t.Fatal("unexpected error:", err)
	}
	hdr := recorder.Header().Get("Set-Cookie")
	const wantPrefix = "__Host-login="
	const wantSuffix = "; Path=/; Max-Age=1296000; HttpOnly; Secure; SameSite=Strict"
	if !strings.HasPrefix(hdr, wantPrefix) || !strings.HasSuffix(hdr, wantSuffix) {
		t.Errorf("got Set-Cookie %q, expected prefix %q and suffix %q", hdr, wantPrefix, wantSuffix)
	}
}

var buf1 = make([]byte, 512)
var buf2 = make([]byte, 512)
var val = []byte("some value")
var obj = MustNew("test", make([]byte, KeyLen), time.Hour)
var enc string

func BenchmarkChmikeEncodeValue(b *testing.B) {
	for n := 0; n < b.N; n++ {
		obj.encodeValue(buf1[:0], val)
	}
}

func init() {
	b1, err := obj.encodeValue(buf1[:0], val)
	if err != nil {
		panic(err)
	}
	enc = string(b1)
}

func BenchmarkChmikeDecodeValue(b *testing.B) {
	for n := 0; n < b.N; n++ {
		obj.decodeValue(buf2[:0], enc)
	}
}

// benchCookieHeader returns a request header with a realistic Cookie line:
// the cookie name=value surrounded by two other cookies.
func benchCookieHeader(name, value string) http.Header {
	return http.Header{"Cookie": {"a=1; " + name + "=" + value + "; b=2"}}
}

// gorillaCodec returns a Gorilla secure cookie codec with keys of the same
// length as this package: 16 bytes for HMAC-SHA256 and 16 bytes for
// AES-128. When nop is true, the value is not serialized with encoding/gob.
func gorillaCodec(nop bool) *securecookie.SecureCookie {
	s := securecookie.New(make([]byte, 16), make([]byte, 16))
	if nop {
		s.SetSerializer(securecookie.NopEncoder{})
	}
	return s
}

func BenchmarkChmikeSetCookie(b *testing.B) {
	obj, err := New("test", make([]byte, KeyLen), time.Hour)
	if err != nil {
		panic(err)
	}
	recorder := httptest.NewRecorder()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if err := obj.SetValue(recorder, val); err != nil {
			panic(err)
		}
		recorder.Header().Del("Set-Cookie")
	}
}

// benchmarkGorillaSetCookie sets a cookie with the same name and attributes
// as BenchmarkChmikeSetCookie.
func benchmarkGorillaSetCookie(b *testing.B, nop bool) {
	s := gorillaCodec(nop)
	recorder := httptest.NewRecorder()
	cookie := http.Cookie{
		Name:     "__Host-test",
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		encoded, err := s.Encode(cookie.Name, val)
		if err != nil {
			panic(err)
		}
		cookie.Value = encoded
		http.SetCookie(recorder, &cookie)
		recorder.Header().Del("Set-Cookie")
	}
}

func BenchmarkGorillaSetCookie(b *testing.B) {
	benchmarkGorillaSetCookie(b, false)
}

func BenchmarkGorillaNopSetCookie(b *testing.B) {
	benchmarkGorillaSetCookie(b, true)
}

func BenchmarkChmikeGetCookie(b *testing.B) {
	obj, err := New("test", make([]byte, KeyLen), time.Hour)
	if err != nil {
		panic(err)
	}
	encoded, err := obj.encodeValue(nil, val)
	if err != nil {
		panic(err)
	}
	request := &http.Request{Header: benchCookieHeader(obj.Name(), string(encoded))}
	out := make([]byte, 0, 64)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, _, err := obj.Value(out[:0], request); err != nil {
			panic(err)
		}
	}
}

// benchmarkGorillaGetCookie gets a cookie from the same Cookie header line
// as BenchmarkChmikeGetCookie.
func benchmarkGorillaGetCookie(b *testing.B, nop bool) {
	s := gorillaCodec(nop)
	name := "__Host-test"
	encoded, err := s.Encode(name, val)
	if err != nil {
		panic(err)
	}
	request := &http.Request{Header: benchCookieHeader(name, encoded)}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c, err := request.Cookie(name)
		if err != nil {
			panic(err)
		}
		var out []byte
		if err = s.Decode(name, c.Value, &out); err != nil {
			panic(err)
		}
	}
}

func BenchmarkGorillaGetCookie(b *testing.B) {
	benchmarkGorillaGetCookie(b, false)
}

func BenchmarkGorillaNopGetCookie(b *testing.B) {
	benchmarkGorillaGetCookie(b, true)
}
