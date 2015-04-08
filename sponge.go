//	Author: Serhat Sevki Dincer, jfcgaussGmail

package sponge

import (
	"math"
	"unsafe"
)

// See http://sponge.noekeon.org
type Sponge struct {
	b      [25]uint64
	rn, ns uint32 // { rate (=25-capacity), number of rounds }, namespace
}

/*	Creates a Sponge. cp (capacity) must be in 2..12 (3+ recommended), nr (number of rounds) must be in 2..24 (11+ recommended), otherwise returns nil. Sponge capacity will be 64*cp bits.

	ns (namespace) & nr parameters determine a sponge's type. Different types of sponges will always produce different outputs.
*/
func New(cp, nr, ns uint32) *Sponge {
	s := new(Sponge)
	if s.setpar(cp, nr, ns) {
		return s
	}
	return nil
}

//	Set sponge parameters. Returns true if successful.
func (s *Sponge) setpar(cp, nr, ns uint32) bool {
	if cp < 2 || cp > 12 || nr < 2 || nr > 24 {
		return false
	}
	s.b[24] = uint64(ns) // namespace lane
	s.rn = nr << 5       // bits 5..9 hold number of rounds
	s.rn ^= 25 - cp      // bits 0..4 hold rate
	s.ns = ns
	return true
}

func (s *Sponge) Reset() {
	for i := 0; i < 24; i++ {
		s.b[i] = 0
	}
	s.b[24] = uint64(s.ns) // namespace lane
}

/*	If x (with correct length = 25-cp) is provided: x is absorbed and readable state is returned.

	If x is of incorrect length: nothing is done and nil is returned.

	If x is nil: Sponge is squeezed and readable state is returned.

	Uses a slightly modified Keccak permutation. See http://keccak.noekeon.org
*/
func (s *Sponge) Perm(x []uint64) []uint64 {
	/*	Modified keccak permutation with a different constant applied to a different
		lane in each round. This implementation fully unrolls the round function to
		avoid inner loops, as well as pre-calculating shift offsets. From go.crypto/sha3.
	*/
	var t, r0, r1, r2, r3, r4 uint64
	a := &s.b
	rt := s.rn & 31 // rate

	if x != nil { // absorb ?
		if len(x) != int(rt) {
			return nil
		}
		for i, v := range x {
			a[i] ^= v
		}
	}

	for i, k := s.rn>>5&31, 23; i > 0; i, k = i-1, k-1 { // nr
		// ι step
		a[k] += uint64(i) // start from just next to namespace lane

		// θ step
		r0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]
		r1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]
		r2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]
		r3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]
		r4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]
		t = r4 ^ (r1<<1 ^ r1>>63)
		a[0] ^= t
		a[5] ^= t
		a[10] ^= t
		a[15] ^= t
		a[20] ^= t
		t = r0 ^ (r2<<1 ^ r2>>63)
		a[1] ^= t
		a[6] ^= t
		a[11] ^= t
		a[16] ^= t
		a[21] ^= t
		t = r1 ^ (r3<<1 ^ r3>>63)
		a[2] ^= t
		a[7] ^= t
		a[12] ^= t
		a[17] ^= t
		a[22] ^= t
		t = r2 ^ (r4<<1 ^ r4>>63)
		a[3] ^= t
		a[8] ^= t
		a[13] ^= t
		a[18] ^= t
		a[23] ^= t
		t = r3 ^ (r0<<1 ^ r0>>63)
		a[4] ^= t
		a[9] ^= t
		a[14] ^= t
		a[19] ^= t
		a[24] ^= t

		// ρ and π steps
		t = a[1]
		t, a[10] = a[10], t<<1^t>>(64-1)
		t, a[7] = a[7], t<<3^t>>(64-3)
		t, a[11] = a[11], t<<6^t>>(64-6)
		t, a[17] = a[17], t<<10^t>>(64-10)
		t, a[18] = a[18], t<<15^t>>(64-15)
		t, a[3] = a[3], t<<21^t>>(64-21)
		t, a[5] = a[5], t<<28^t>>(64-28)
		t, a[16] = a[16], t<<36^t>>(64-36)
		t, a[8] = a[8], t<<45^t>>(64-45)
		t, a[21] = a[21], t<<55^t>>(64-55)
		t, a[24] = a[24], t<<2^t>>(64-2)
		t, a[4] = a[4], t<<14^t>>(64-14)
		t, a[15] = a[15], t<<27^t>>(64-27)
		t, a[23] = a[23], t<<41^t>>(64-41)
		t, a[19] = a[19], t<<56^t>>(64-56)
		t, a[13] = a[13], t<<8^t>>(64-8)
		t, a[12] = a[12], t<<25^t>>(64-25)
		t, a[2] = a[2], t<<43^t>>(64-43)
		t, a[20] = a[20], t<<62^t>>(64-62)
		t, a[14] = a[14], t<<18^t>>(64-18)
		t, a[22] = a[22], t<<39^t>>(64-39)
		t, a[9] = a[9], t<<61^t>>(64-61)
		t, a[6] = a[6], t<<20^t>>(64-20)
		a[1] = t<<44 ^ t>>(64-44)

		// χ step
		r0 = a[0]
		r1 = a[1]
		r2 = a[2]
		r3 = a[3]
		r4 = a[4]
		a[0] ^= r2 &^ r1
		a[1] ^= r3 &^ r2
		a[2] ^= r4 &^ r3
		a[3] ^= r0 &^ r4
		a[4] ^= r1 &^ r0
		r0 = a[5]
		r1 = a[6]
		r2 = a[7]
		r3 = a[8]
		r4 = a[9]
		a[5] ^= r2 &^ r1
		a[6] ^= r3 &^ r2
		a[7] ^= r4 &^ r3
		a[8] ^= r0 &^ r4
		a[9] ^= r1 &^ r0
		r0 = a[10]
		r1 = a[11]
		r2 = a[12]
		r3 = a[13]
		r4 = a[14]
		a[10] ^= r2 &^ r1
		a[11] ^= r3 &^ r2
		a[12] ^= r4 &^ r3
		a[13] ^= r0 &^ r4
		a[14] ^= r1 &^ r0
		r0 = a[15]
		r1 = a[16]
		r2 = a[17]
		r3 = a[18]
		r4 = a[19]
		a[15] ^= r2 &^ r1
		a[16] ^= r3 &^ r2
		a[17] ^= r4 &^ r3
		a[18] ^= r0 &^ r4
		a[19] ^= r1 &^ r0
		r0 = a[20]
		r1 = a[21]
		r2 = a[22]
		r3 = a[23]
		r4 = a[24]
		a[20] ^= r2 &^ r1
		a[21] ^= r3 &^ r2
		a[22] ^= r4 &^ r3
		a[23] ^= r0 &^ r4
		a[24] ^= r1 &^ r0
	}
	return a[:rt]
}

//	Sponge-based hashes
type Hash struct {
	s Sponge
	x []byte
}

//	Same parameters with New() sponge. Hash output will be 8*cp bytes.
func NewHash(cp, nr, ns uint32) *Hash {
	h := new(Hash)
	if h.s.setpar(cp, nr, ns) {
		h.x = make([]byte, 0, h.s.rn&31<<3) // buffer for extra chunks & last block, buffer size = 8*rate bytes
		return h
	}
	return nil
}

type slice struct { // not worth importing reflect
	Data     uintptr
	Len, Cap int
}

func setslc(y *[]uint64, x *[]byte) { // set y=x
	s := (*slice)(unsafe.Pointer(y))
	t := (*slice)(unsafe.Pointer(x))
	s.Data = t.Data
	s.Len = t.Len >> 3
	s.Cap = s.Len
}

//	Writes x into the hash. Can be called multiple times with subsequent parts of the whole input. Works best with x whose length is a multiple of block length (8*(25-cp) bytes).
func (h *Hash) Write(x []byte) {
	x = append(h.x, x...) // start with any remaining chunk
	var y []uint64
	setslc(&y, &x)

	rt := cap(h.x) >> 3 // rate
	for ; len(y) >= rt; y = y[rt:] {
		h.s.Perm(y[:rt]) // consume x
	}

	rt = cap(h.x)        // 8*rate
	x = x[len(x)/rt*rt:] // remaining chunk of x

	copy(h.x[:rt], x)
	h.x = h.x[:len(x)] // copy it into h.x
}

//	Calculate & return the hash sum (8*cp bytes), and reset the hash state.
func (h *Hash) Sum() []byte {
	lh := len(h.x)      // length of data remaining in h.x
	x := h.x[:cap(h.x)] // whole h.x buffer
	var y []uint64
	setslc(&y, &x)

	t := (lh + 7) >> 3 // 10*1 pad h.x start
	for i := t; i < len(y); i++ {
		y[i] = 0 // quick-zero h.x beyond remaining data
	}
	x[lh] = 1 // 1st 1
	t <<= 3
	for i := lh + 1; i < t; i++ {
		x[i] = 0 // zero remaining bytes
	}
	x[len(x)-1] |= 128 // last 1 & pad end

	h.s.Perm(y) // absorb last block

	t = 8*25 - cap(x) // 8*capacity
	r := make([]byte, t, t)
	setslc(&y, &r)
	copy(y, h.s.b[:]) // copy result to r

	h.s.Reset()
	h.x = h.x[:0]
	return r
}

//	Pseudo Random Number Generator
type Prng Sponge

//	Same parameters with New() sponge.
func NewPrng(cp, nr, ns uint32) *Prng {
	p := new(Prng)
	if (*Sponge)(p).setpar(cp, nr, ns) {
		return p
	}
	return nil
}

//	Seeds Prng with x. First 25-cp elements of x at most are used for seeding.
func (p *Prng) Seed(x []uint64) {
	rt := p.rn & 31 // rate
	n := int(rt)
	if len(x) < n {
		n = len(x)
	}
	for i := 0; i < n; i++ {
		p.b[i] ^= x[i]
	}
	// bits 10..14 of Prng.rn hold number of available limbs in buffer, initially zero
	(*Sponge)(p).Perm(nil)
	p.rn = p.rn&(1<<10-1) ^ rt<<10
}

//	Returns a random uint64
func (p *Prng) I() uint64 {
	n := p.rn >> 10 // number of available limbs in buffer
	if n == 0 {
		(*Sponge)(p).Perm(nil)
		n = p.rn & 31 // rate
	}
	n--
	p.rn = p.rn&(1<<10-1) ^ n<<10
	return p.b[n]
}

//	Returns a uniformly distributed float from [0,1)
func (p *Prng) U() float64 {
	i := p.I()&^(3<<62) | (1<<10-1)<<52 // set sign=exponent=0 so it'll be a double from [1,2)
	d := *(*float64)(unsafe.Pointer(&i))
	return d - 1
}

//	Returns a uniformly distributed float from (-1,1)
func (p *Prng) U2() float64 {
	i := p.I()&^(1<<62) | (1<<10-1)<<52 // set exponent=0 so it'll be a double from +/-[1,2)
	d := *(*float64)(unsafe.Pointer(&i))
	if d > 0 {
		return d - 1
	}
	return d + 1
}

//	Returns two independent normally distributed floats with zero mean and unit variance
func (p *Prng) G() (float64, float64) {
	a, b, s := .0, .0, .0
	for s == 0 || s >= 1 {
		a = p.U2()
		b = p.U2()
		s = a*a + b*b
	}
	s = math.Sqrt(-2 * math.Log(s) / s)
	return s * a, s * b
}
