package main

import (
	"crypto/ed25519"
	"time"

	jwt "github.com/mertakinstd/jwtgenerator"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	token, err := jwt.GenerateEdDSA("test-subject", priv, 24*time.Hour)
	if err != nil {
		panic(err)
	}
	println("Generated Token:", token)

	err = jwt.ValidateEdDSA(token, pub)
	if err != nil {
		panic(err)
	}
	println("Token is valid")
}
