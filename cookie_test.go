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
)

func TestGenerateKeyErrors(t *testing.T) {
	forceError = true
	defer func() { forceError = false }()
	if _, err := GenerateRandomKey(); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestEncodeBase64(t *testing.T) {
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
		buf := make([]byte, 100)
		out, err := encodeBase64(buf, test.in)
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
	_, err := encodeBase64(nil, []byte{0, 0, 0})
	if err == nil {
		t.Errorf("unexpected nil error")
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
		buf := make([]byte, 100)
		out, err := decodeBase64(buf, test.in)
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
	_, err := decodeBase64(nil, "AAAA")
	if err == nil {
		t.Errorf("unexpected nil error")
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
		out := EncodedValueLen(test.in)
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
		buf := make([]byte, 100)
		out, err := encodeValue(buf, BytesToString(test.in), key)
		if (err == nil) == test.encFail {
			if err == nil {
				t.Errorf("got nil encoding error, expected error for in: %+v", test.in)
			} else {
				t.Errorf("got encoding error '%s', expected nil error for in: %+v", err, test.in)
			}
		} else {
			in, err := decodeValue(BytesToString(out), key)
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
	if _, err := decodeValue("AAAAAAAAAAAAAAAAAAAAAAAAAAAA", nil); err == nil {
		t.Errorf("unexpected nil error")
	}
	key := make([]byte, 32)
	if _, err := decodeValue(" AAAAAAAAAAAAAAAAAAAAAAAAAAA", key); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, err := decodeValue("AAAAAAAAAAAAAAAAAAAAAAAAAAAA", key[:len(key)-1]); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, err := decodeValue("AAAAAAAAAAAAAAAAAAAAAAAAAAAA", key); err == nil {
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
	buf, _ = encodeBase64(buf[:0], buf)
	if _, err := decodeValue(BytesToString(buf), key); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestEncodeValueErrors(t *testing.T) {
	key := make([]byte, 32)
	if _, err := encodeValue(make([]byte, 27), "", key); err == nil {
		t.Errorf("unexpected nil error")
	}
	buf := make([]byte, 28)
	if _, err := encodeValue(buf, "", key[:len(key)-1]); err == nil {
		t.Errorf("unexpected nil error")
	}
	forceError = true
	defer func() { forceError = false }()
	if _, err := encodeValue(buf, "", key); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestCheckName(t *testing.T) {
	if err := CheckName("toto"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := CheckName("?"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := CheckName(""); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := CheckName("\t"); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestCheckPath(t *testing.T) {
	if err := CheckPath("toto"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := CheckPath(";"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := CheckPath("\t"); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestCheckDomain(t *testing.T) {
	if err := CheckDomain("example.com"); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := CheckDomain(strings.Repeat("a", 300)); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := CheckDomain("?"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := CheckDomain("\t"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := CheckDomain(".example.com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := CheckDomain("example-.com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := CheckDomain("example.-com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := CheckDomain("example..com"); err == nil {
		t.Errorf("unexpected nil error")
	}
	if err := CheckDomain("example.com."); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestCheck(t *testing.T) {
	c := &Params{Name: "name", Value: "value"}
	if err := Check(c); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	c.Domain = "?"
	if err := Check(c); err == nil {
		t.Errorf("unexpected nil error")
	}
	c.Path = "\t"
	if err := Check(c); err == nil {
		t.Errorf("unexpected nil error")
	}
	c.Name = ""
	if err := Check(c); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestSetAndGetCookie(t *testing.T) {
	key := make([]byte, KeyLen)
	// Create a new HTTP Recorder (implements http.ResponseWriter)
	recorder := httptest.NewRecorder()
	cookie := &Params{
		Name:     "test",
		Value:    "expected",
		Path:     "path",
		Domain:   "example.com",
		HTTPOnly: true,
		Secure:   true,
	}
	err := SetSecure(recorder, cookie, key)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}

	// Extract the dropped cookie from the request.
	value, err := GetSecureValue(request, "test", key)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else if BytesToString(value) != cookie.Value {
		t.Errorf("got value '%s', expected '%s'", value, cookie.Value)
	}

	// Extract the dropped cookie from the request.
	value, err = GetSecureValue(request, "xxx", key)
	if err == nil {
		t.Errorf("unexpected nil error")
	} else if value != nil {
		t.Errorf("unexpected nil value")
	}

	// Create a new HTTP Recorder (implements http.ResponseWriter)
	recorder = httptest.NewRecorder()
	err = SetSecure(recorder, cookie, key[:len(key)-1])
	if err == nil {
		t.Errorf("unexpected nil error")
	}
}
