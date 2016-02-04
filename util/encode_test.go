package util

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		input   []byte
		encoded string
		size    int
	}{
		{
			input:   nil,
			encoded: "5df6e0e2",
			size:    4,
		},
		{
			input:   []byte{},
			encoded: "5df6e0e2",
			size:    4,
		},
		{
			input:   []byte("hello"),
			encoded: "68656c6c6f9595c9df",
			size:    4,
		},
		{
			input:   []byte("Some longer text aslfajdslkfaj;dlfkjabwqj;elkalkdj"),
			encoded: "536f6d65206c6f6e67657220746578742061736c66616a64736c6b66616a3b646c666b6a616277716a3b656c6b616c6b646afb9ceff2",
			size:    4,
		},
	}

	for i, test := range tests {
		s := HexChecksumEncode(test.input, test.size)

		if s != test.encoded {
			t.Errorf("HexChecksumEncode #(%d): unexpected encoding -- "+
				"got: %s, want %s", i, s, test.encoded)
		}
	}
}

func TestHexChecksumDecode(t *testing.T) {
	tests := []struct {
		encoded string
		size    int
		output  []byte
		err     error
	}{
		{
			encoded: "5df6e0e2",
			output:  []byte{},
			size:    4,
		},
		{
			encoded: "68656c6c6f9595c9df",
			output:  []byte("hello"),
			size:    4,
		},
		{
			encoded: "536f6d65206c6f6e67657220746578742061736c66616a64736c6b66616a3b646c666b6a616277716a3b656c6b616c6b646afb9ceff2",
			output:  []byte("Some longer text aslfajdslkfaj;dlfkjabwqj;elkalkdj"),
			size:    4,
		},
		{
			encoded: "",
			size:    4,
			err:     ErrInvalidChecksum,
		},
		{
			encoded: "11111111111111",
			size:    4,
			err:     ErrInvalidChecksum,
		},
		{
			encoded: "111111111111111",
			size:    4,
			err:     hex.ErrLength,
		},
	}

	for i, test := range tests {
		b, err := HexChecksumDecode(test.encoded, test.size)
		if err != test.err {
			t.Errorf("HexChecksumDecode #(%d): unexpected error -- "+
				"got %s, want %s", i, err, test.err)
		}

		if bytes.Compare(b, test.output) != 0 {
			t.Errorf("HexChecksumDecode #(%d): unexpected output -- "+
				"got %s, want %s", i, b, test.output)
		}
	}
}
