package jwt

import (
	"crypto/ed25519"
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
	keySizeHS256         = 32
	headerStrBase64Size  = 36
	headerStrBase64HS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	headerStrBase64EdDSA = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9"
)

var (
	bufferPool = sync.Pool{
		New: func() any {
			return &bufferWrapper{
				buf: make([]byte, 0, 256),
			}
		},
	}

	encodeBufferPool = sync.Pool{
		New: func() any {
			return &bufferWrapper{
				buf: make([]byte, 0, 256),
			}
		},
	}

	decodeBufferPool = sync.Pool{
		New: func() any {
			return &bufferWrapper{
				buf: make([]byte, 0, 256),
			}
		},
	}
)

func GenerateHS256(subject string, key string, expire time.Duration) (string, error) {
	if len(key) != keySizeHS256 {
		return "", fmt.Errorf("key length must be %v bytes", keySizeHS256)
	}

	if expire <= 0 {
		return "", fmt.Errorf("expire duration must be greater than zero")
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
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	payloadBase64 := encodeTo64(payloadJSON)

	signature, err := signTokenHS256(key, headerStrBase64HS256, payloadBase64)
	if err != nil {
		return "", err
	}

	token := headerStrBase64HS256 + "." + payloadBase64 + "." + signature

	return token, nil
}

func signTokenHS256(key string, header string, payload string) (string, error) {
	bufferW := bufferPool.Get().(*bufferWrapper)
	defer func() {
		clear(bufferW.buf)
		bufferW.buf = bufferW.buf[:0]
		bufferPool.Put(bufferW)
	}()

	bufferW.buf = bufferW.buf[:len(key)]
	copy(bufferW.buf, key)

	mac := hmac.New(sha256.New, bufferW.buf)

	tokenLength := headerStrBase64Size + 1 + len(payload)

	if cap(bufferW.buf) < tokenLength {
		bufferW.buf = make([]byte, 0, tokenLength)
	} else {
		bufferW.buf = bufferW.buf[:tokenLength]
	}

	n := copy(bufferW.buf, header)
	bufferW.buf[n] = '.'
	copy(bufferW.buf[n+1:], payload)

	_, err := mac.Write(bufferW.buf)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	if cap(bufferW.buf) < mac.Size() {
		bufferW.buf = make([]byte, 0, mac.Size())
	}

	token := mac.Sum(bufferW.buf[:0])

	return encodeTo64(token), nil
}

func ValidateHS256(token string, key string) error {
	if len(key) != keySizeHS256 {
		return fmt.Errorf("key length must be %v bytes", keySizeHS256)
	}

	headerBase64, payloadBase64, signature, err := extractTokenParts(token)
	if err != nil {
		return err
	}

	if headerBase64 != headerStrBase64HS256 {
		return fmt.Errorf("invalid header")
	}

	referenceSignature, err := signTokenHS256(key, headerStrBase64HS256, payloadBase64)
	if err != nil {
		return err
	}

	if !hmac.Equal([]byte(signature), []byte(referenceSignature)) {
		return fmt.Errorf("invalid signature")
	}

	payloadJSON, err := decodeFrom64(payloadBase64)
	if err != nil {
		return err
	}

	var payload tokenPayload

	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	err = validateExpiry(payload)
	if err != nil {
		return err
	}

	return nil
}

func GenerateEdDSA(subject string, privateKey ed25519.PrivateKey, expire time.Duration) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("private key length must be %v bytes", ed25519.PrivateKeySize)
	}

	if expire <= 0 {
		return "", fmt.Errorf("expire duration must be greater than zero")
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
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	payloadBase64 := encodeTo64(payloadJSON)

	signature := ed25519.Sign(privateKey, []byte(headerStrBase64EdDSA+"."+payloadBase64))

	token := headerStrBase64EdDSA + "." + payloadBase64 + "." + encodeTo64(signature)

	return token, nil
}

func ValidateEdDSA(token string, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("public key length must be %v bytes", ed25519.PublicKeySize)
	}

	headerBase64, payloadBase64, signatureBase64, err := extractTokenParts(token)
	if err != nil {
		return err
	}

	if headerBase64 != headerStrBase64EdDSA {
		return fmt.Errorf("invalid header")
	}

	signature, err := decodeFrom64(signatureBase64)
	if err != nil {
		return err
	}

	if !ed25519.Verify(publicKey, []byte(headerStrBase64EdDSA+"."+payloadBase64), signature) {
		return fmt.Errorf("invalid signature")
	}

	payloadJSON, err := decodeFrom64(payloadBase64)
	if err != nil {
		return err
	}

	var payload tokenPayload

	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	err = validateExpiry(payload)
	if err != nil {
		return err
	}

	return nil
}

func extractTokenParts(token string) (string, string, string, error) {
	if strings.Count(token, ".") != 2 {
		return "", "", "", fmt.Errorf("token malformed")
	}

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

func validateExpiry(payload tokenPayload) error {
	if time.Now().Unix() >= payload.Exp {
		return fmt.Errorf("token expired")
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
		return "", err
	}

	var payload tokenPayload

	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return payload.Subject, nil
}

func encodeTo64(data []byte) string {
	encode64Wrapper := encodeBufferPool.Get().(*bufferWrapper)
	defer func() {
		encode64Wrapper.buf = encode64Wrapper.buf[:0]
		encodeBufferPool.Put(encode64Wrapper)
	}()

	size := base64.RawURLEncoding.EncodedLen(len(data))

	if size > cap(encode64Wrapper.buf) {
		encode64Wrapper.buf = make([]byte, size)
	}

	base64.RawURLEncoding.Encode(encode64Wrapper.buf[:size], data)

	return string(encode64Wrapper.buf[:size])
}

func decodeFrom64(data string) ([]byte, error) {
	decode64Wrapper := decodeBufferPool.Get().(*bufferWrapper)
	defer func() {
		decode64Wrapper.buf = decode64Wrapper.buf[:0]
		decodeBufferPool.Put(decode64Wrapper)
	}()

	size := base64.RawURLEncoding.DecodedLen(len(data))

	if size > cap(decode64Wrapper.buf) {
		decode64Wrapper.buf = make([]byte, size)
	}

	n, err := base64.RawURLEncoding.Decode(decode64Wrapper.buf[:size], []byte(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %w", err)
	}

	result := make([]byte, n)
	copy(result, decode64Wrapper.buf[:n])

	return result, nil
}
