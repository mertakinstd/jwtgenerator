package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

type (
	tokenPayload struct {
		Subject string `json:"sub"`
		Iat     int64  `json:"iat"`
		Exp     int64  `json:"exp"`
	}

	bufferWrapper struct {
		buf []byte
	}
)

const (
	keySize             = 32
	headerStrBase64     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	headerStrBase64Size = 36
)

var (
	dataPool = sync.Pool{
		New: func() any {
			return &bufferWrapper{
				buf: make([]byte, 0, 256),
			}
		},
	}

	keyPool = sync.Pool{
		New: func() any {
			return &bufferWrapper{
				buf: make([]byte, 0, keySize),
			}
		},
	}

	tokenPool = sync.Pool{
		New: func() any {
			return &bufferWrapper{
				buf: make([]byte, 0, 256),
			}
		},
	}

	encode64Pool = sync.Pool{
		New: func() any {
			return &bufferWrapper{
				buf: make([]byte, 0, 256),
			}
		},
	}

	decode64Pool = sync.Pool{
		New: func() any {
			return &bufferWrapper{
				buf: make([]byte, 0, 256),
			}
		},
	}
)

func Generate(subject string, key string, expire time.Duration) (string, error) {
	err := validateKey(key)
	if err != nil {
		return "", err
	}

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
	keyWrapper := keyPool.Get().(*bufferWrapper)
	defer func() {
		keyWrapper.buf = keyWrapper.buf[:0]
		keyPool.Put(keyWrapper)
	}()

	copy(keyWrapper.buf[:keySize], key)

	mac := hmac.New(sha256.New, keyWrapper.buf[:keySize])

	tokenLength := headerStrBase64Size + 1 + len(payload)

	dataWrapper := dataPool.Get().(*bufferWrapper)
	defer func() {
		dataWrapper.buf = dataWrapper.buf[:0]
		dataPool.Put(dataWrapper)
	}()

	if cap(dataWrapper.buf) < tokenLength {
		dataWrapper.buf = make([]byte, 0, tokenLength)
	} else {
		dataWrapper.buf = dataWrapper.buf[:tokenLength]
	}

	n := copy(dataWrapper.buf, header)
	dataWrapper.buf[n] = '.'
	copy(dataWrapper.buf[n+1:], payload)

	_, err := mac.Write(dataWrapper.buf)
	if err != nil {
		return "", fmt.Errorf("failed to sign token")
	}

	tokenWrapper := tokenPool.Get().(*bufferWrapper)
	defer func() {
		tokenWrapper.buf = tokenWrapper.buf[:0]
		tokenPool.Put(tokenWrapper)
	}()

	if cap(tokenWrapper.buf) < mac.Size() {
		tokenWrapper.buf = make([]byte, 0, mac.Size())
	}

	token := mac.Sum(tokenWrapper.buf[:0])

	return encodeTo64(token), nil
}

func Validate(token string, key string, strict bool) error {
	err := validateKey(key)
	if err != nil {
		return err
	}

	headerBase64, payloadBase64, signature, err := extractTokenParts(token)
	if err != nil {
		return err
	}

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
		return fmt.Errorf("token expired")
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

func extractTokenParts(token string) (string, string, string, error) {
	first := strings.IndexByte(token, '.')
	if first <= 0 {
		return "", "", "", fmt.Errorf("token malformed")
	}

	second := strings.IndexByte(token[first+1:], '.')
	if second <= 0 {
		return "", "", "", fmt.Errorf("token malformed")
	}

	header := token[:first]
	payload := token[first+1 : first+1+second]
	signature := token[first+1+second+1:]

	if len(signature) == 0 {
		return "", "", "", fmt.Errorf("token malformed")
	}

	return header, payload, signature, nil
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
	_, payloadBase64, _, err := extractTokenParts(token)
	if err != nil {
		return "", err
	}

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

func validateKey(key string) error {
	if len(key) != keySize {
		return fmt.Errorf("key length must be %v bytes", keySize)
	}

	return nil
}

func encodeTo64(data []byte) string {
	encode64Wrapper := encode64Pool.Get().(*bufferWrapper)
	defer func() {
		encode64Wrapper.buf = encode64Wrapper.buf[:0]
		encode64Pool.Put(encode64Wrapper)
	}()

	size := base64.RawURLEncoding.EncodedLen(len(data))

	if size > cap(encode64Wrapper.buf) {
		encode64Wrapper.buf = make([]byte, size)
	}

	base64.RawURLEncoding.Encode(encode64Wrapper.buf[:size], data)

	return string(encode64Wrapper.buf[:size])
}

func decodeFrom64(data string) ([]byte, error) {
	decode64Wrapper := decode64Pool.Get().(*bufferWrapper)
	defer func() {
		decode64Wrapper.buf = decode64Wrapper.buf[:0]
		decode64Pool.Put(decode64Wrapper)
	}()

	size := base64.RawURLEncoding.DecodedLen(len(data))

	if size > cap(decode64Wrapper.buf) {
		decode64Wrapper.buf = make([]byte, size)
	}

	base64.RawURLEncoding.Decode(decode64Wrapper.buf[:size], []byte(data))

	result := make([]byte, size)
	copy(result, decode64Wrapper.buf[:size])

	return result, nil
}
