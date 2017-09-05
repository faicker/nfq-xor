package main

import (
	"bytes"
	"testing"
)

func TestTransform(t *testing.T) {
	b := []byte("abcd")
	key := byte('a')
	transform(b, key)
	w := []byte{0, 3, 2, 5}
	if !bytes.Equal(b, w) {
		t.Errorf("transform result %v. want %v", b, w)
	}

	b = []byte{}
	transform(b, key)
	w = []byte{}
	if !bytes.Equal(b, w) {
		t.Errorf("transform result %v. want %v", b, w)
	}
}
