package cookie

import "testing"
import "bytes"

func TestEncodeBase64(t *testing.T) {
	tests := []struct {
		in, out []byte
	}{ // requires that len(in)%3 == 0
		{in: []byte{}, out: []byte{}},
		{in: []byte{0, 0, 0}, out: []byte{65, 65, 65, 65}},
		{in: []byte{FF, FF, FF}, out: []byte{65, 65, 65, 65}},
	}

	for _, test := range tests {
		out := string(encodeBase64(test.in))
		if !bytes.Equal(out, test.out) {
			t.Errorf("got output %v, expected %v for input %v", out, test.out, test.in)
		}
	}
}
