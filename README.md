# JWT Generator

[![Go Report Card](https://goreportcard.com/badge/github.com/mertakinstd/jwtgenerator)](https://goreportcard.com/report/github.com/mertakinstd/jwtgenerator)

A lightweight and simple JWT (JSON Web Token) generator and validator library for Go.

## Features

- HS256 token generation and validation
- EdDSA (Ed25519) token generation and validation
- Token payload extraction
- Expiration checking
- HMAC-SHA256 and Ed25519 signing
- Clean and intuitive API

## Installation

```bash
go get github.com/mertakinstd/jwtgenerator
```

## Usage

```go
package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "fmt"
    "time"
    jwt "github.com/mertakinstd/jwtgenerator"
)

func main() {
    hs256Key := "12345678901234567890123456789012"

    // Generate HS256 token
    tokenHS256, err := jwt.GenerateHS256("user123", hs256Key, 24*time.Hour)
    if err != nil {
        fmt.Printf("Error while generating token")
    }

    // Validate HS256 token
    err = jwt.ValidateHS256(tokenHS256, hs256Key)
    if err != nil {
        fmt.Printf("Invalid token")
    }

    // Generate EdDSA key pair
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        fmt.Printf("Error while generating keys")
    }

    // Generate EdDSA token
    tokenEdDSA, err := jwt.GenerateEdDSA("user123", privateKey, 24*time.Hour)
    if err != nil {
        fmt.Printf("Error while generating token")
    }

    // Validate EdDSA token
    err = jwt.ValidateEdDSA(tokenEdDSA, publicKey)
    if err != nil {
        fmt.Printf("Invalid token")
    }

    // Extract token payload
    subject, err := jwt.Export(tokenHS256)
    if err != nil {
        fmt.Printf("Error while exporting subject")
    }
    fmt.Printf("Token subject: %s\n", subject)
}
```

## Export Note

`Export` only parses and returns the `sub` claim. It does not verify signature or expiration.
Always call `ValidateHS256` or `ValidateEdDSA` before using `Export` output in security-sensitive logic.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
