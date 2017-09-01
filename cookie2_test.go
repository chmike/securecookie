package cookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"testing"
)

func TestAppendEncodedBase64(t *testing.T) {
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
		out := appendEncodedBase64(nil, test.in)
		if !bytes.Equal(out, test.out) {
			t.Errorf("got output %v, expected %v for input %v", out, test.out, test.in)
		}
	}
}

func TestAppendDecodedBase64(t *testing.T) {
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
	} // out == base64.URLEncoding.WithPadding(base64.NoPadding).Encode(out, in)
	for _, test := range tests {
		out, err := appendDecodedBase64(nil, test.in)
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
		out := EncodedValLen(test.in)
		if out != test.out {
			t.Errorf("got %d, expected %d for %d", out, test.out, test.in)
		}
	}
}

func TestEncodDecodeValue(t *testing.T) {
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
		out, err := AppendEncodedValue(nil, test.in, key)
		if (err == nil) == test.encFail {
			if err == nil {
				t.Errorf("got nil encoding error, expected error for in: %+v", test.in)
			} else {
				t.Errorf("got encoding error '%s', expected nil error for in: %+v", err, test.in)
			}
		} else {
			in, err := AppendDecodedValue(nil, string(out), key)
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

func TestAppendDecodedValueErrors(t *testing.T) {
	key := make([]byte, 32)
	if _, err := AppendDecodedValue(nil, "", nil); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, err := AppendDecodedValue(nil, " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, err := AppendDecodedValue(nil, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key); err == nil {
		t.Errorf("unexpected nil error")
	}
	if _, err := AppendDecodedValue(nil, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key[:len(key)-1]); err == nil {
		t.Errorf("unexpected nil error")
	}
	buf := make([]byte, 5, 32)
	buf[4] = 3 // set invalid number of random bytes
	mac := hmac.New(md5.New, key[:MACLen])
	mac.Write(buf)
	ivPos := len(buf)
	buf = mac.Sum(buf)
	iv := buf[ivPos:]
	block, _ := aes.NewCipher(key[MACLen:])
	block.Encrypt(iv, iv)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(buf[:ivPos], buf[:ivPos])
	buf = appendEncodedBase64(buf[:0], buf)
	if _, err := AppendDecodedValue(nil, string(buf), key); err == nil {
		t.Errorf("unexpected nil error")
	}
}

func TestAppendEncodeValueErrors(t *testing.T) {
	key := make([]byte, 32)
	if _, err := AppendEncodedValue(nil, nil, key[:len(key)-1]); err == nil {
		t.Errorf("unexpected nil error")
	}
	forceError = true
	defer func() { forceError = false }()
	if _, err := AppendEncodedValue(nil, nil, key); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestGenerateKeyErrors(t *testing.T) {
	forceError = true
	defer func() { forceError = false }()
	if _, err := GenerateRandomKey(); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}
