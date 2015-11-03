//	Multiple-goroutine-safe Random Number Generator
package rng

import (
	"github.com/jfcg/sixb"
	"github.com/jfcg/sponge"
	"os"
	"time"
	"unsafe"
)

var ch = make(chan [2]uint64, 3)

//	Any number of goroutines can safely read cryptographic-strength random numbers from this channel. Rng is initialized with time & other machine specific data, hence will produce different sequence each time an app starts. The app needs to call this once.
func Ch() <-chan [2]uint64 {
	return ch
}

func init() {
	go func() {
		h := sixb.Txt2int("sponge/rng")
		ns := uint32(h) + uint32(h>>32)
		p := sponge.NewPrng(4, 13, ns)
		initrng(p, ns)
		for {
			ch <- [2]uint64{p.I(), p.I()}
		}
	}()
}

func initrng(p *sponge.Prng, ns uint32) {
	nw := time.Now() // initialize with as much entropy as possible
	s, i := nw.Zone()
	p.Seed(
		uint64(nw.UnixNano()), // time
		sixb.Txt2int(s),
		uint64(i+1),
		uint64(os.Getuid()+1), // ids
		uint64(os.Getgid()+1),
		uint64(os.Getpid()),
		uint64(os.Getppid()),
	)

	t, _ := os.Getwd()
	u, _ := os.Hostname()
	env := append(os.Environ(), t, u) // env vars, wd, host, args
	env = append(env, os.Args...)
	h := sponge.NewHash(12, 12, ns+1)
	eb := []byte{0}

	for _, v := range env {
		h.Write(eb)
		h.Write([]byte(v))
	}
	sd := h.Sum()
	sy := sixb.Bs2is(sd)
	p.Seed(sy...)
}

//	Creates a random session id
func CreateSession() string {
	rn := <-ch
	db := (*[16]byte)(unsafe.Pointer(&rn[0]))
	var br [21]byte

	for i, k := 0, 0; i < 15; i, k = i+3, k+4 {
		br[k] = sixb.Sb2an(db[i] & 63)
		br[k+1] = sixb.Sb2an(db[i]>>6 ^ db[i+1]&15<<2)
		br[k+2] = sixb.Sb2an(db[i+1]>>4 ^ db[i+2]&3<<4)
		br[k+3] = sixb.Sb2an(db[i+2] >> 2)
	}
	br[20] = sixb.Sb2an(db[15] & 63)
	return string(br[:])
}

//	Returns true if sn is a valid session id
func ValidSession(sn string) bool {
	if len(sn) != 21 {
		return false
	}
	for i := 0; i < len(sn); i++ {
		c := sn[i]
		if c < '0' || c > ':' && c < '@' || c > 'Z' && c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}
