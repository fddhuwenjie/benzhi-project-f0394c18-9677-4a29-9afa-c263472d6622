package main

import (
	"os"
	"strings"
)

const defaultAddress = "127.0.0.1:19081"

func configuredAddress() string {
	if port := os.Getenv("PORT"); port != "" {
		return "127.0.0.1:" + port
	}
	return defaultAddress
}

func validAddr(addr string) bool {
	return strings.HasPrefix(addr, "127.0.0.1:") || strings.HasPrefix(addr, "localhost:")
}
