//	Author: Serhat Sevki Dincer, jfcgaussGmail

package sponge

import (
	"fmt"
	"testing"
	"unsafe"
)

func equal(x, y []uint64) bool { // returns true iff slice data are equal & inputs have different buffers
	s := (*slice)(unsafe.Pointer(&y))
	t := (*slice)(unsafe.Pointer(&x))
	if s.Data == t.Data || len(x) != len(y) {
		return false
	}

	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func equalb(a, b []byte) bool { // returns true iff slice data are equal
	var x, y []uint64
	setslc(&x, &a)
	setslc(&y, &b)
	return equal(x, y)
}

func Test1(t *testing.T) {
	ic := []uint32{0, 1, 13, 14} // invalid capacities
	ir := []uint32{0, 1, 25, 26} // invalid rounds
	for i, c := range ic {
		for k, r := range ir {
			if New(c, r, uint32(4*i+k)) != nil {
				t.Fatal("invalid capacity/rounds accepted", c, r)
			}
		}
	}

	e := make([]uint64, 0) // invalid input length
	e2 := make([]uint64, 5)
	s := New(3, 13, 0)
	if s.Perm(e) != nil || s.Perm(e2) != nil {
		t.Fatal("should return nil slice")
	}

	b := make([]uint64, 22)      // all zeros
	c := s.Perm(b)               // s must be not-permuted-yet
	d := New(3, 13, 0).Perm(nil) // nil input means we want squeezing, equals all zeros input
	if len(c) != 22 || !equal(c, d) {
		t.Fatal("must have equal output")
	}

	res := make([][]uint64, 0)
	for v := uint64(0); v < 3; v++ {
		b[0] = v
		for r := uint32(10); r < 15; r++ {
			for n := uint32(0); n < 3; n++ {
				res = append(res, New(3, r, n).Perm(b)) // different (rounds, namespace, input)
			}
		}
	}

	if len(res[0]) != 22 {
		t.Fatal("wrong length", len(res[0]))
	}
	for r := 0; r < len(res)-1; r++ {
		for n := r + 1; n < len(res); n++ {
			if equal(res[r], res[n]) {
				t.Fatal("must have different output", r, n)
			}
		}
	}
}

func tst2(x []byte, t *testing.T) {
	r := make([][]byte, 0)

	for c := uint32(2); c < 4; c++ {
		h := NewHash(c, 13, 0)

		for i := 0; i <= len(x); i++ {
			h.Write(x[:i]) // whole input
			a := h.Sum()

			h.Write(x[:i/2]) // input as two pieces
			h.Write(x[i/2 : i])
			b := h.Sum()

			if len(a) != int(8*c) || !equalb(a, b) {
				t.Fatal("must have same hash", c, i)
			}
			r = append(r, a)
		}
	}

	for i := 0; i < len(r)-1; i++ {
		for k := i + 1; k < len(r); k++ {
			if equalb(r[i], r[k]) {
				t.Fatal("must be different", i, k)
			}
		}
	}
}

func Test2(t *testing.T) {
	x := make([]byte, 400, 400)
	tst2(x, t)

	for i := range x {
		x[i] = byte(i)
	}
	tst2(x, t)
}

func Test3(t *testing.T) {
	p := NewPrng(3, 13, 1)
	a1, a2 := p.I(), p.I()

	p.Seed([]uint64{1})
	a3, a4 := p.I(), p.I()

	for i := 999; i > 0; i-- {
		d := p.U()
		if d < 0 || d >= 1 {
			t.Fatal("incorrect float", d)
		}

		d2 := p.U2()
		if d2 <= -1 || d2 >= 1 {
			t.Fatal("incorrect float", d2)
		}

		x, y := p.G()
		if x*x+y*y > 9 {
			fmt.Println(x, y, d2)
		}
	}
	p.Reset()
	b1, b2 := p.I(), p.I()

	p.Seed([]uint64{1})
	b3, b4 := p.I(), p.I()

	if a1 != b1 || a2 != b2 || a3 != b3 || a4 != b4 {
		t.Fatal("reset does not work")
	}
}

func Test4(t *testing.T) {
	s := []byte(`A cryptographic hash function is a hash function which is considered practically impossible to invert, that is, to recreate the input data from its hash value alone. These one-way hash functions have been called "the workhorses of modern cryptography".[1] The input data is often called the message, and the hash value is often called the message digest or simply the digest.`)
	h := NewHash(3, 11, 1)
	h.Write(s[:len(s)/2]) // 1st half
	p1 := h.Sum()         // also resets h

	h.Write(s) // whole
	p2 := h.Sum()

	h.Write(s[:len(s)/2]) // 1st half
	f := h.Copy()
	if f == h {
		t.Fatal("must be a different Hash")
	}
	r1 := f.Sum()

	h.Write(s[len(s)/2:]) // 2nd half
	r2 := h.Sum()

	if len(p1) != 24 || len(p2) != 24 || !equalb(p1, r1) || !equalb(p2, r2) {
		t.Fatal("Copy() did not work!")
	}
	fmt.Printf("%x %x\n", p1, p2)
}
