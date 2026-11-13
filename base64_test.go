package securecookie

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// b64Data returns n bytes of deterministic test data.
func b64Data(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + 7)
	}
	return b
}

// TestBase64SameAsStdlib checks that encodeBase64 and decodeBase64 are
// compatible with base64.RawURLEncoding of the standard library, which uses
// the same alphabet and no padding.
func TestBase64SameAsStdlib(t *testing.T) {
	for n := 0; n <= 300; n += 3 {
		src := b64Data(n)
		want := base64.RawURLEncoding.EncodeToString(src)
		if got := encodeBase64(nil, src); string(got) != want {
			t.Fatalf("encoding of %d bytes: got %q, expected %q", n, got, want)
		}
		// appended to a non-empty dst, with and without enough capacity
		for _, c := range []int{3, 3 + len(want)} {
			dst := append(make([]byte, 0, c), "abc"...)
			if got := encodeBase64(dst, src); string(got) != "abc"+want {
				t.Fatalf("encoding of %d bytes appended with capacity %d: got %q, expected %q",
					n, c, got, "abc"+want)
			}
		}
		dec, err := decodeBase64(nil, want)
		if err != nil {
			t.Fatalf("decoding of %d bytes: unexpected error: %s", n, err)
		}
		if !bytes.Equal(dec, src) {
			t.Fatalf("decoding of %d bytes: got %x, expected %x", n, dec, src)
		}
	}
}
