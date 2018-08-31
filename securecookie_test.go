package securecookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestCheckPath(t *testing.T) {
	if err := checkPath("toto"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := checkPath(";"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkPath("\t"); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestCheckDomain(t *testing.T) {
	if err := checkDomain(""); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := checkDomain("example.com"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := checkDomain("EXAMPLE.com"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := checkDomain("foo-bar.com"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := checkDomain("www1.foo-bar.com"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := checkDomain("192.168.1.1.example.com"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := checkDomain(strings.Repeat("a", 300)); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain(strings.Repeat("a", 70) + ".com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("example.com" + strings.Repeat("a", 70)); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("?"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("\t"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("exàmple.com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("www.\xbd\xb2.com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("-example.com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("example-.com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("example.-com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("example.com-"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("example.1com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain(".example.com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("example..com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("example.com."); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func (o1 *Obj) Equal(o2 *Obj) bool {
	if o1 == nil || o2 == nil {
		return o1 == o2
	}
	return o1.name == o2.name && bytes.Equal(o1.key, o2.key) &&
		o1.path == o2.path && o1.domain == o2.domain &&
		o1.maxAge == o2.maxAge && o1.httpOnly == o2.httpOnly &&
		o1.secure == o2.secure
}

func TestMustNew(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	MustNew("test", nil, Params{})
}

func TestNew(t *testing.T) {
	k := make([]byte, KeyLen)
	kb := make([]byte, KeyLen*3)
	n := "test"
	tests := []struct {
		k    []byte
		n    string
		p    Params
		o    *Obj
		fail bool
	}{
		{k: k, n: n, p: Params{}, o: &Obj{key: k, name: n}},
		{k: k[:len(k)-1], n: n, p: Params{}, o: nil, fail: true},
		{k: make([]byte, KeyLen+1), n: n, p: Params{}, o: nil, fail: true},
		{k: k, n: "", p: Params{}, o: nil, fail: true},
		{k: k, n: n, p: Params{Path: "path"}, o: &Obj{key: k, name: n, path: "path"}},
		{k: k, n: n, p: Params{Path: ";"}, o: nil, fail: true},
		{k: k, n: n, p: Params{Domain: "example.com"}, o: &Obj{key: k, name: n, domain: "example.com"}},
		{k: k, n: n, p: Params{Domain: "example..com"}, o: nil, fail: true},
		{k: k, n: n, p: Params{MaxAge: 3600}, o: &Obj{key: k, name: n, maxAge: 3600}},
		{k: k, n: n, p: Params{MaxAge: -3600}, o: nil, fail: true},
		{k: k, n: n, p: Params{HTTPOnly: true}, o: &Obj{key: k, name: n, httpOnly: true}},
		{k: k, n: n, p: Params{Secure: true}, o: &Obj{key: k, name: n, secure: true}},
		{k: kb, n: n, p: Params{Secure: true}, o: &Obj{key: kb, name: n, secure: true}, fail: true},
	}
	for _, test := range tests {
		obj, err := New(test.n, test.k, test.p)
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
	key := make([]byte, KeyLen)
	name := "test"
	params := Params{
		Path:     "path",
		Domain:   "example.com",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   true,
	}
	obj, err := New(name, key, params)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if obj.Path() != params.Path {
		t.Errorf("got path '%s', expected '%s'", obj.Path(), params.Path)
	}
	if obj.Domain() != params.Domain {
		t.Errorf("got domain '%s', expected '%s'", obj.Domain(), params.Domain)
	}
	if obj.MaxAge() != params.MaxAge {
		t.Errorf("got max age %d, expected %d", obj.MaxAge(), params.MaxAge)
	}
	if obj.HTTPOnly() != params.HTTPOnly {
		t.Errorf("got HTTP only %t, expected %t", obj.HTTPOnly(), params.HTTPOnly)
	}
	if obj.Secure() != params.Secure {
		t.Errorf("got secure %t, expected %t", obj.Secure(), params.Secure)
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
	obj, err := New("name", key, Params{})
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
	obj, err := New("name", key, Params{})
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
	obj, err := New("test", make([]byte, KeyLen), Params{MaxAge: 3600})
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
			in, err := obj.decodeValue(nil, string(out))
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
	obj, err := New("test", make([]byte, KeyLen), Params{})
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 0, 59)
	forceError = 2
	defer func() { forceError = 0 }()
	if _, err := obj.encodeValue(buf, []byte{1}); err == nil {
		t.Errorf("unexpected nil error")
	}
	forceError = 1
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
	obj, err := New("test", make([]byte, KeyLen), Params{MaxAge: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := obj.decodeValue(nil, ""); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, err := obj.decodeValue(nil, " "+strings.Repeat("A", minEncLen)); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, err := obj.decodeValue(nil, "zA"+strings.Repeat("A", minEncLen)); err == nil {
		t.Errorf("unexpected nil error")
	}
	buf, err := obj.encodeValue(nil, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	buf[len(buf)-1]--
	if _, err := obj.decodeValue(nil, string(buf)); err == nil {
		t.Errorf("unexpected nil error")
	}
	buf[len(buf)-1]++

	obj.maxAge -= 10000
	if _, err := obj.decodeValue(nil, string(buf)); err == nil {
		t.Errorf("unexpected nil error")
	}
	obj.maxAge += 10000

}

func TestDecodeValueErrorsB(t *testing.T) {
	obj, err := New("test", make([]byte, KeyLen), Params{MaxAge: 3600})
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
	var hm = hmac.New(sha256.New, obj.key[:len(obj.key)/2])
	hm.Write([]byte(obj.name))
	hm.Write(dec)
	dec = hm.Sum(dec)
	buf = encodeBase64(buf[:0], dec)
	if _, err := obj.decodeValue(nil, string(buf)); err == nil {
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
	obj.xorCtrAes(dec[1:1+ivLen], dec[1+ivLen:])
	for i := 1 + ivLen; i < 1+ivLen+10; i++ {
		dec[i] |= 0x80
	}
	obj.xorCtrAes(dec[1:1+ivLen], dec[1+ivLen:])
	hm.Reset()
	hm.Write([]byte(obj.name))
	hm.Write(dec)
	dec = hm.Sum(dec)
	buf = encodeBase64(buf[:0], dec)
	purgeBufPool()
	if _, err := obj.decodeValue(nil, string(buf)); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestSetAndGetCookie(t *testing.T) {
	p := Params{
		Path:     "path",
		Domain:   "example.com",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   true,
	}
	obj, err := New("test", make([]byte, KeyLen), p)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	recorder := httptest.NewRecorder()
	inValue := []byte("some value")
	err = obj.SetValue(recorder, inValue)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
	outValue, err := obj.GetValue(nil, request)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else if !bytes.Equal(outValue, inValue) {
		t.Errorf("got value '%s', expected '%s'", outValue, inValue)
	}

	// test retrieve non-existent cookie.
	obj.name = "xxx"
	outValue, err = obj.GetValue(nil, request)
	if err == nil {
		t.Errorf("unexpected nil error")
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

func TestDeleteCookie(t *testing.T) {
	purgeBufPool()
	p := Params{
		Path:     "path",
		Domain:   "example.com",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   true,
	}
	obj, err := New("test", make([]byte, KeyLen), p)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	recorder := httptest.NewRecorder()
	err = obj.Delete(recorder)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}

	c, err := request.Cookie("test")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else {
		if len(c.Value) != 0 {
			t.Errorf("got value '%s', expected empty string", c.Value)
		}
	}
}

func TestChmikeValueLen(t *testing.T) {
	var name = "test"
	var inValue = []byte("some value")
	var recorder = httptest.NewRecorder()
	var key = make([]byte, KeyLen)
	obj, err := New(name, key, Params{
		Path:     "path",
		Domain:   "example.com",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   true,
	})
	if err != nil {
		panic(err)
	}
	err = obj.SetValue(recorder, inValue)
	if err != nil {
		panic(err)
	}
	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
	c, err := request.Cookie("test")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Chmike value:", c.Value, "len:", len(c.Value))
}

func TestGorillaValueLen(t *testing.T) {
	var name = "test"
	var inValue = []byte("some value")
	var recorder = httptest.NewRecorder()
	var hashKey = make([]byte, 16)
	var blockKey = make([]byte, 16)
	var s = securecookie.New(hashKey, blockKey)
	var cookie = http.Cookie{Name: name}
	encoded, err := s.Encode(name, inValue)
	if err != nil {
		panic(err)
	}
	cookie.Value = encoded
	http.SetCookie(recorder, &cookie)
	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
	c, err := request.Cookie("test")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Gorilla value:", c.Value, "len:", len(c.Value))
}

var buf1 = make([]byte, 512)
var buf2 = make([]byte, 512)
var val = []byte("some value")
var obj = MustNew("test", make([]byte, KeyLen), Params{MaxAge: 3600})
var res []byte
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

func BenchmarkChmikeSetCookie(b *testing.B) {
	var name = "test"
	var inValue = []byte("some value")
	var recorder = httptest.NewRecorder()
	var key = make([]byte, KeyLen)
	obj, err := New(name, key, Params{
		Path:     "path",
		Domain:   "example.com",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   true,
	})
	if err != nil {
		panic(err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		err = obj.SetValue(recorder, inValue)
		if err != nil {
			panic(err)
		}
		recorder.Header().Del(name)
	}
}

func BenchmarkGorillaSetCookie(b *testing.B) {
	var name = "test"
	var inValue = []byte("some value")
	var recorder = httptest.NewRecorder()
	var hashKey = make([]byte, 16)
	var blockKey = make([]byte, 16)
	var s = securecookie.New(hashKey, blockKey)
	var cookie = http.Cookie{
		Name:     name,
		Path:     "path",
		Domain:   "example.com",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		encoded, err := s.Encode(name, inValue)
		if err != nil {
			panic(err)
		}
		cookie.Value = encoded
		http.SetCookie(recorder, &cookie)
		recorder.Header().Del(name)
	}
}

func BenchmarkChmikeGetCookie(b *testing.B) {
	var name = "test"
	var inValue = []byte("some value")
	var recorder = httptest.NewRecorder()
	var key = make([]byte, KeyLen)
	obj, err := New(name, key, Params{MaxAge: 3600})
	if err != nil {
		panic(err)
	}
	err = obj.SetValue(recorder, inValue)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(inValue))
	//fmt.Println("Chmike cookie:", recorder.HeaderMap["Set-Cookie"])
	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, err := obj.GetValue(out[:0], request)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkGorillaGetCookie(b *testing.B) {
	var name = "test"
	var inValue = []byte("some value")
	var recorder = httptest.NewRecorder()
	var hashKey = make([]byte, 16)
	var blockKey = make([]byte, 16)
	var s = securecookie.New(hashKey, blockKey)
	var cookie = http.Cookie{Name: name}
	encoded, err := s.Encode(name, inValue)
	if err != nil {
		panic(err)
	}
	cookie.Value = encoded
	http.SetCookie(recorder, &cookie)
	//fmt.Println("Gorilla cookie:", recorder.HeaderMap["Set-Cookie"])
	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		outCookie, err := request.Cookie(name)
		if err != nil {
			panic(err)
		}
		var outValue []byte
		if err = s.Decode(name, outCookie.Value, &outValue); err != nil {
			panic(err)
		}
	}
}
