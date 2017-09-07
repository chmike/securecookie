package cookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unsafe"

	"github.com/gorilla/securecookie"
)

func TestGenerateKeyErrors(t *testing.T) {
	forceError = true
	defer func() { forceError = false }()
	if _, err := GenerateRandomKey(); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestCheckName(t *testing.T) {
	if err := checkName("toto"); err != nil {
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
	if err := checkDomain("example.com"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := checkDomain(strings.Repeat("a", 300)); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("?"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("\t"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain(".example.com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("example-.com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := checkDomain("example.-com"); err == nil {
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

func TestNew(t *testing.T) {
	k := make([]byte, KeyLen)
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
		{k: k, n: "", p: Params{}, o: nil, fail: true},
		{k: k, n: n, p: Params{Path: "path"}, o: &Obj{key: k, name: n, path: "path"}},
		{k: k, n: n, p: Params{Path: ";"}, o: nil, fail: true},
		{k: k, n: n, p: Params{Domain: "example.com"}, o: &Obj{key: k, name: n, domain: "example.com"}},
		{k: k, n: n, p: Params{Domain: "example..com"}, o: nil, fail: true},
		{k: k, n: n, p: Params{MaxAge: 3600}, o: &Obj{key: k, name: n, maxAge: 3600}},
		{k: k, n: n, p: Params{MaxAge: -3600}, o: nil, fail: true},
		{k: k, n: n, p: Params{HTTPOnly: true}, o: &Obj{key: k, name: n, httpOnly: true}},
		{k: k, n: n, p: Params{Secure: true}, o: &Obj{key: k, name: n, secure: true}},
	}
	for _, test := range tests {
		obj, err := New(test.k, test.n, test.p)
		if err != nil {
			if !test.fail {
				t.Errorf("got error '%s', expected no error for %+v", err, test)
			}
		} else if test.fail {
			t.Errorf("got nil error, expected to fail for %+v", test)
		}
		if test.fail == (err != nil) && !obj.Equal(test.o) {
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
	obj, err := New(key, name, params)
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
		t.Errorf("got HTTP only %t, expected %t", obj.Secure(), params.Secure)
	}
	obj.SetMaxAge(100)
	if obj.MaxAge() != 100 {
		t.Errorf("got max age %d, expected %d", obj.MaxAge(), 100)
	}
	obj.SetMaxAge(-3600)
	if obj.MaxAge() != 0 {
		t.Errorf("got max age %d, expected %d", obj.MaxAge(), 0)
	}
}

func TestAppendEncodedBase64(t *testing.T) {
	tests := []struct {
		in, out []byte
		fail    bool
	}{ // requires that len(in)%3 == 0
		{in: []byte{}, out: []byte{}},
		{in: []byte{0, 0, 0}, out: []byte{65, 65, 65, 65}},
		{in: []byte{255, 255, 255}, out: []byte{95, 95, 95, 95}},
		{in: []byte{0, 1, 2, 3, 4, 5}, out: []byte{65, 65, 69, 67, 65, 119, 81, 70}},
		{in: []byte{3, 200, 254}, out: []byte{65, 56, 106, 45}},
		{in: []byte{3, 200, 254, 1}, out: nil, fail: true},
	} // out == base64.URLEncoding.WithPadding(base64.NoPadding).Encode(out, in)
	for _, test := range tests {
		out, err := appendEncodedBase64(nil, test.in)
		if err != nil {
			if !test.fail {
				t.Errorf("got error '%s', expected no error", err)
			}
		} else if test.fail {
			t.Errorf("got nil error, expected to fail")
		}
		if test.fail == (err != nil) && !bytes.Equal(out, test.out) {
			t.Errorf("got output %v, expected %v for input %v", out, test.out, test.in)
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
		out, err := decodeBase64(test.in)
		if err != nil {
			if !test.fail {
				t.Errorf("got error '%s', expected no error", err)
			}
		} else if test.fail {
			t.Errorf("got nil error, expected to fail")
		}
		if test.fail == (err != nil) && !bytes.Equal(out, test.out) {
			t.Errorf("got output %v, expected %v for input %v", out, test.out, test.in)
		}
	}
}

func TestEncodedValLen(t *testing.T) {
	tests := []struct {
		in, out int
	}{
		{in: 0, out: 28},
		{in: 1, out: 28},
		{in: 2, out: 28},
		{in: 3, out: 32},
		{in: 4, out: 32},
		{in: 5, out: 32},
		{in: 6, out: 36},
	}
	for _, test := range tests {
		out := encodedValueLen(test.in)
		if out != test.out {
			t.Errorf("got %d, expected %d for %d", out, test.out, test.in)
		}
	}
}

func TestEncodeDecodeValue(t *testing.T) {
	tests := []struct {
		in               []byte
		encFail, decFail bool
	}{
		{in: []byte{}},
		{in: []byte{0, 0, 0}},
		{in: []byte{255, 255, 255}},
		{in: []byte{0, 1, 2, 3, 4, 5}},
		{in: []byte{3, 200, 254}},
	}
	key, err := GenerateRandomKey()
	if err != nil {
		panic(err)
	}
	for _, test := range tests {
		out, err := appendEncodedValue(nil, test.in, key)
		if (err == nil) == test.encFail {
			if err == nil {
				t.Errorf("got nil encoding error, expected error for in: %+v", test.in)
			} else {
				t.Errorf("got encoding error '%s', expected nil error for in: %+v", err, test.in)
			}
		} else {
			in, err := decodeValue(*(*string)(unsafe.Pointer(&out)), key)
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

func TestDecodeValueErrors(t *testing.T) {
	if _, err := decodeValue("", nil); err == nil {
		t.Errorf("unexpected nil error")
	}
	key := make([]byte, 32)
	if _, err := decodeValue(" AAAAAAAAAAAAAAAAAAAAAAAAAAA", key); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, err := decodeValue("AAAAAAAAAAAAAAAAAAAAAAAAAAAA", key); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, err := decodeValue("AAAAAAAAAAAAAAAAAAAAAAAAAAAA", key[:len(key)-1]); err == nil {
		t.Errorf("unexpected nil error")
	}
	buf := make([]byte, 5, 32)
	buf[4] = 3 // set invalid number of random bytes
	mac := hmac.New(md5.New, key[:macLen])
	mac.Write(buf)
	ivPos := len(buf)
	buf = mac.Sum(buf)
	iv := buf[ivPos:]
	block, _ := aes.NewCipher(key[macLen:])
	block.Encrypt(iv, iv)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(buf[:ivPos], buf[:ivPos])
	buf, _ = appendEncodedBase64(buf[:0], buf)
	if _, err := decodeValue(*(*string)(unsafe.Pointer(&buf)), key); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestEncodeValueErrors(t *testing.T) {
	key := make([]byte, 32)
	buf := make([]byte, 0, 28)
	if _, err := appendEncodedValue(buf, []byte{}, key[:len(key)-1]); err == nil {
		t.Errorf("unexpected nil error")
	}
	forceError = true
	defer func() { forceError = false }()
	if _, err := appendEncodedValue(buf, []byte{}, key); err != nil {
		t.Errorf("unexpected error: %s", err)
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
	obj, err := New(make([]byte, KeyLen), "test", p)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	recorder := httptest.NewRecorder()
	inValue := []byte("some value")
	err = obj.SetSecureValue(recorder, inValue)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
	outValue, err := obj.GetSecureValue(request)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else if !bytes.Equal(outValue, inValue) {
		t.Errorf("got value '%s', expected '%s'", outValue, inValue)
	}

	// test retrieve non-existant cookie.
	obj.name = "xxx"
	outValue, err = obj.GetSecureValue(request)
	if err == nil {
		t.Errorf("unexpected nil error")
	} else if outValue != nil {
		t.Errorf("unexpected non-nil value")
	}

	// force encoding error
	obj.key = obj.key[:len(obj.key)-1]
	recorder = httptest.NewRecorder()
	err = obj.SetSecureValue(recorder, inValue)
	if err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestDeleteCookie(t *testing.T) {
	// purge bufPool
	bPtr := bufPool.Get().(*[]byte)
	if len(*bPtr) > 64 {
		bPtr = bufPool.Get().(*[]byte)
	}
	p := Params{
		Path:     "path",
		Domain:   "example.com",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   true,
	}
	obj, err := New(make([]byte, KeyLen), "test", p)
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

func BenchmarkChmikeSetCookie(b *testing.B) {
	var name = "test"
	var inValue = []byte("some value")
	var recorder = httptest.NewRecorder()
	var key = make([]byte, KeyLen)
	obj, err := New(key, name, Params{
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
		err = obj.SetSecureValue(recorder, inValue)
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
	obj, err := New(key, name, Params{})
	if err != nil {
		panic(err)
	}
	err = obj.SetSecureValue(recorder, inValue)
	if err != nil {
		panic(err)
	}
	//fmt.Println(recorder.HeaderMap["Set-Cookie"])
	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, err := obj.GetSecureValue(request)
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
	// fmt.Println(recorder.HeaderMap["Set-Cookie"])
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
