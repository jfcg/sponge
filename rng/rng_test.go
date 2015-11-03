package rng

import (
	"fmt"
	"testing"
)

var sy = make(chan int, 2)

func gr(t *testing.T, n int) {
	for k := 0; k < 7; k++ {
		l := ""
		for i := 0; i < 6; i++ {
			sn := CreateSession()
			if !ValidSession(sn) {
				t.Fatal("bad session id")
			}
			l += sn + " "
		}
		fmt.Println(n, l)
	}
	sy <- 1
}

func Test1(t *testing.T) {
	for k := 0; k < 7; k++ {
		go gr(t, k)
	}
	for k := 0; k < 7; k++ {
		<-sy
	}
}
