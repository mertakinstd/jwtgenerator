package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func Generate(subject string, key string, expire time.Duration) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header")
	}

	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	issuedAt := time.Now().UTC()
	expiration := issuedAt.Add(expire)

	payload := map[string]any{
		"sub": subject,
		"iat": issuedAt.Unix(),
		"exp": expiration.Unix(),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload")
	}

	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signature, err := signToken(key, headerBase64, payloadBase64)
	if err != nil {
		return "", err
	}

	token := headerBase64 + "." + payloadBase64 + "." + signature

	return token, nil
}

func signToken(key, header, payload string) (string, error) {
	mac := hmac.New(sha256.New, []byte(key))

	_, err := mac.Write([]byte(header + "." + payload))
	if err != nil {
		return "", fmt.Errorf("failed to sign token")
	}

	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signature, nil
}

func Validate(token string, key string, strict bool) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token malformed")
	}

	headerBase64 := parts[0]
	payloadBase64 := parts[1]
	signature := parts[2]

	if strict {
		headerJSON, err := base64.RawURLEncoding.DecodeString(headerBase64)
		if err != nil {
			return fmt.Errorf("failed to decode header")
		}

		var header map[string]string

		err = json.Unmarshal(headerJSON, &header)
		if err != nil {
			return fmt.Errorf("failed to unmarshal header")
		}

		err = validateHeader(header)
		if err != nil {
			return err
		}
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return fmt.Errorf("failed to decode payload")
	}

	var payload map[string]any

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

func validateHeader(header map[string]string) error {
	algorithm := header["alg"]
	if algorithm != "HS256" {
		return fmt.Errorf("unsupported algorithm")
	}

	tokenType := header["typ"]
	if tokenType != "JWT" {
		return fmt.Errorf("unsupported token type")
	}

	return nil
}

func validateExpiry(payload map[string]any) error {
	exp := int64(payload["exp"].(float64))

	if time.Now().Unix() > exp {
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
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token malformed")
	}

	payloadBase64 := parts[1]

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode payload")
	}

	var payload map[string]any

	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal payload")
	}

	return payload["sub"].(string), nil
}
