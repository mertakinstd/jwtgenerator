package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"sync"
	"time"
)

type tokenPayload struct {
	Subject string `json:"sub"`
	Iat     int64  `json:"iat"`
	Exp     int64  `json:"exp"`
}

const (
	headerStr       = `{"alg":"HS256","typ":"JWT"}`
	headerStrBase64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
)

var (
	hmacPool = sync.Pool{
		New: func() any {
			return hmac.New(sha256.New, nil)
		},
	}

	base64BufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, 0, 256)
			return &buf
		},
	}
)

func Generate(subject string, key string, expire time.Duration) (string, error) {
	issuedAt := time.Now().UTC()
	expiration := issuedAt.Add(expire)

	payload := tokenPayload{
		Subject: subject,
		Iat:     issuedAt.Unix(),
		Exp:     expiration.Unix(),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload")
	}

	payloadBase64 := encodeTo64(payloadJSON)

	signature, err := signToken(key, headerStrBase64, payloadBase64)
	if err != nil {
		return "", err
	}

	token := headerStrBase64 + "." + payloadBase64 + "." + signature

	return token, nil
}

func signToken(key, header, payload string) (string, error) {
	mac := hmacPool.Get().(hash.Hash)
	defer hmacPool.Put(mac)
	mac.Reset()

	data := make([]byte, 0, len(key)+len(header)+len(payload)+1)
	data = append(data, key...)
	data = append(data, header...)
	data = append(data, '.')
	data = append(data, payload...)

	_, err := mac.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to sign token")
	}

	return encodeTo64(mac.Sum(nil)), nil
}

func Validate(token string, key string, strict bool) error {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("token malformed")
	}

	headerBase64 := parts[0]
	payloadBase64 := parts[1]
	signature := parts[2]

	if strict {
		err := validateHeader(headerBase64)
		if err != nil {
			return err
		}
	}

	payloadJSON, err := decodeFrom64(payloadBase64)
	if err != nil {
		return fmt.Errorf("failed to decode payload")
	}

	var payload tokenPayload

	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return fmt.Errorf("failed to unmarshal payload")
	}

	err = validateExpiry(payload)
	if err != nil {
		return fmt.Errorf("token expired ")
	}

	err = validateSignature(key, headerBase64, payloadBase64, signature)
	if err != nil {
		if err.Error() == "invalid" {
			return fmt.Errorf("token signature invalid")
		}
		return err
	}

	return nil
}

func validateHeader(header string) error {
	if header != headerStrBase64 {
		return fmt.Errorf("invalid header")
	}

	return nil
}

func validateExpiry(payload tokenPayload) error {
	if time.Now().Unix() > payload.Exp {
		return fmt.Errorf("expired")
	}

	return nil
}

func validateSignature(key, header, payload, signature string) error {
	referenceSignature, err := signToken(key, header, payload)
	if err != nil {
		return err
	}

	if !hmac.Equal([]byte(signature), []byte(referenceSignature)) {
		return fmt.Errorf("invalid")
	}

	return nil
}

func Export(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("token malformed")
	}

	payloadBase64 := parts[1]

	payloadJSON, err := decodeFrom64(payloadBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode payload")
	}

	var payload tokenPayload

	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal payload")
	}

	return payload.Subject, nil
}

func encodeTo64(data []byte) string {
	bufPtr := base64BufPool.Get().(*[]byte)
	defer base64BufPool.Put(bufPtr)
	buf := *bufPtr

	size := base64.RawURLEncoding.EncodedLen(len(data))

	if size > len(buf) {
		*bufPtr = make([]byte, size)
		buf = *bufPtr
	}

	base64.RawURLEncoding.Encode(buf, data)

	result := make([]byte, size)
	copy(result, buf[:size])

	return string(result)
}

func decodeFrom64(data string) ([]byte, error) {
	bufPtr := base64BufPool.Get().(*[]byte)
	defer base64BufPool.Put(bufPtr)
	buf := *bufPtr

	size := base64.RawURLEncoding.DecodedLen(len(data))
	if size > len(buf) {
		*bufPtr = make([]byte, size)
		buf = *bufPtr
	}

	n, err := base64.RawURLEncoding.Decode(buf, []byte(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	result := make([]byte, n)
	copy(result, buf[:n])

	return result, nil
}
