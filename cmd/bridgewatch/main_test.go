package main

import "testing"

func TestValidAddr(t *testing.T) {
	if !validAddr("127.0.0.1:19081") || validAddr("0.0.0.0:1") {
		t.Fatal("address validation")
	}
}
