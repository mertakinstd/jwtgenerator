# JWT Generator

[![Go Report Card](https://goreportcard.com/badge/github.com/mertakinstd/jwtgenerator)](https://goreportcard.com/report/github.com/mertakinstd/jwtgenerator)

A lightweight and simple JWT (JSON Web Token) generator and validator library for Go.

## Features

- Token generation functionality
- Token validation with configurable strict mode validation (includes header verification)
- Token payload extraction
- Expiration checking
- HMAC-SHA256 signing
- Clean and intuitive API

## Installation

```bash
go get github.com/mertakinstd/jwtgenerator
```

## Usage

```go
package main

import (
    "fmt"
    "time"
    jwt "github.com/mertakinstd/jwtgenerator"
)

func main() {
    // Generate token
    token, err := jwt.Generate("user123", "secret-key", 24*time.Hour)
    if err != nil {
        fmt.Printf("Error while generating token")
    }

    // Validate token with strict mode (validates header claims)
    err = jwt.Validate(token, "secret-key", true)
    if err != nil {
        fmt.Printf("Invalid token")
    }

    // Validate token without strict mode
    err = jwt.Validate(token, "secret-key", false)
    if err != nil {
        fmt.Printf("Invalid token")
    }

    // Extract token payload
    subject, err := jwt.Export(token)
    if err != nil {
        fmt.Printf("Error while exporting subject")
    }
    fmt.Printf("Token subject: %s\n", subject)
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
