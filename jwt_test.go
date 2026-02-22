package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

//go:generate go test -v -race -bench=. -benchmem -cpu=1,2,4,8 -count=1
func TestMain(m *testing.M) {
	m.Run()
}

func TestGenerateHS256(t *testing.T) {
	key := "12345678901234567890123456789012"
	subject := "test-subject"
	expire := 24 * time.Hour

	token, err := GenerateHS256(subject, key, expire)
	if err != nil {
		t.Fatalf("GenerateHS256() error = %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("GenerateHS256() token should have 3 parts, got %d", len(parts))
	}
}

func TestGenerateHS256InvalidInput(t *testing.T) {
	_, err := GenerateHS256("test-subject", "short-key", 24*time.Hour)
	if err == nil {
		t.Fatalf("expected key length error, got nil")
	}

	_, err = GenerateHS256("test-subject", "12345678901234567890123456789012", 0)
	if err == nil {
		t.Fatalf("expected expire duration error, got nil")
	}
}

func TestValidateHS256(t *testing.T) {
	key := "12345678901234567890123456789012"
	validToken := mustGenerateHS256Token(t, "test", key, 24*time.Hour)

	invalidHeaderToken := replaceTokenPart(t, validToken, 0, headerStrBase64EdDSA)
	invalidSignatureToken := tamperTokenPart(t, validToken, 2)
	invalidPayloadBase64Token := mustGenerateHS256WithRawPayload(t, key, "%%%")

	tests := []struct {
		name       string
		token      string
		key        string
		wantErr    bool
		errContain string
	}{
		{
			name:    "valid token",
			token:   validToken,
			key:     key,
			wantErr: false,
		},
		{
			name:       "invalid signature",
			token:      validToken,
			key:        "12345678901234567890123456789013",
			wantErr:    true,
			errContain: "invalid signature",
		},
		{
			name:       "malformed token",
			token:      "invalid.token",
			key:        key,
			wantErr:    true,
			errContain: "token malformed",
		},
		{
			name:       "invalid header",
			token:      invalidHeaderToken,
			key:        key,
			wantErr:    true,
			errContain: "invalid header",
		},
		{
			name:       "invalid payload base64",
			token:      invalidPayloadBase64Token,
			key:        key,
			wantErr:    true,
			errContain: "decode",
		},
		{
			name:       "tampered signature section",
			token:      invalidSignatureToken,
			key:        key,
			wantErr:    true,
			errContain: "invalid signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHS256(tt.token, tt.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateHS256() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && tt.errContain != "" && (err == nil || !strings.Contains(err.Error(), tt.errContain)) {
				t.Fatalf("ValidateHS256() error = %v, expected to contain %q", err, tt.errContain)
			}
		})
	}
}

func TestValidateHS256ExpiredToken(t *testing.T) {
	key := "12345678901234567890123456789012"
	token := mustBuildExpiredHS256Token(t, key)

	err := ValidateHS256(token, key)
	if err == nil {
		t.Fatalf("expected expired error, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestGenerateEdDSA(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	token, err := GenerateEdDSA("test-subject", privateKey, 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateEdDSA() error = %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("GenerateEdDSA() token should have 3 parts, got %d", len(parts))
	}
}

func TestGenerateEdDSAInvalidInput(t *testing.T) {
	_, err := GenerateEdDSA("test-subject", ed25519.PrivateKey("short"), 24*time.Hour)
	if err == nil {
		t.Fatalf("expected private key length error, got nil")
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	_, err = GenerateEdDSA("test-subject", privateKey, 0)
	if err == nil {
		t.Fatalf("expected expire duration error, got nil")
	}
}

func TestValidateEdDSA(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	validToken := mustGenerateEdDSAToken(t, "test", privateKey, 24*time.Hour)
	invalidHeaderToken := replaceTokenPart(t, validToken, 0, headerStrBase64HS256)
	invalidSignatureToken := tamperTokenPart(t, validToken, 2)
	expiredToken := mustBuildExpiredEdDSAToken(t, privateKey)
	invalidSignatureBase64Token := replaceTokenPart(t, validToken, 2, "%%%")

	tests := []struct {
		name       string
		token      string
		key        ed25519.PublicKey
		wantErr    bool
		errContain string
	}{
		{
			name:    "valid token",
			token:   validToken,
			key:     publicKey,
			wantErr: false,
		},
		{
			name:       "invalid public key",
			token:      validToken,
			key:        otherPublicKey,
			wantErr:    true,
			errContain: "invalid signature",
		},
		{
			name:       "malformed token",
			token:      "invalid.token",
			key:        publicKey,
			wantErr:    true,
			errContain: "token malformed",
		},
		{
			name:       "invalid header",
			token:      invalidHeaderToken,
			key:        publicKey,
			wantErr:    true,
			errContain: "invalid header",
		},
		{
			name:       "tampered signature",
			token:      invalidSignatureToken,
			key:        publicKey,
			wantErr:    true,
			errContain: "invalid signature",
		},
		{
			name:       "invalid signature base64",
			token:      invalidSignatureBase64Token,
			key:        publicKey,
			wantErr:    true,
			errContain: "decode",
		},
		{
			name:       "expired token",
			token:      expiredToken,
			key:        publicKey,
			wantErr:    true,
			errContain: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEdDSA(tt.token, tt.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateEdDSA() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && tt.errContain != "" && (err == nil || !strings.Contains(err.Error(), tt.errContain)) {
				t.Fatalf("ValidateEdDSA() error = %v, expected to contain %q", err, tt.errContain)
			}
		})
	}
}

func TestValidateEdDSAInvalidPublicKey(t *testing.T) {
	err := ValidateEdDSA("a.b.c", ed25519.PublicKey("short"))
	if err == nil {
		t.Fatalf("expected public key length error, got nil")
	}
}

func TestExport(t *testing.T) {
	subject := "test-subject"
	hsToken := mustGenerateHS256Token(t, subject, "12345678901234567890123456789012", 24*time.Hour)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	_ = edPub
	edToken := mustGenerateEdDSAToken(t, subject, edPriv, 24*time.Hour)

	gotHS, err := Export(hsToken)
	if err != nil {
		t.Fatalf("Export(HS256) error = %v", err)
	}
	if gotHS != subject {
		t.Fatalf("Export(HS256) = %v, want %v", gotHS, subject)
	}

	gotEd, err := Export(edToken)
	if err != nil {
		t.Fatalf("Export(EdDSA) error = %v", err)
	}
	if gotEd != subject {
		t.Fatalf("Export(EdDSA) = %v, want %v", gotEd, subject)
	}
}

func TestDecodeFrom64Invalid(t *testing.T) {
	_, err := decodeFrom64("%%%")
	if err == nil {
		t.Fatalf("expected decode error, got nil")
	}
}

func BenchmarkGenerateHS256(b *testing.B) {
	key := "12345678901234567890123456789012"
	subject := "test-subject"
	expire := 24 * time.Hour

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateHS256(subject, key, expire)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateHS256Parallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := GenerateHS256("test", "12345678901234567890123456789012", time.Hour)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkValidateHS256(b *testing.B) {
	key := "12345678901234567890123456789012"
	token, _ := GenerateHS256("test-subject", key, 24*time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := ValidateHS256(token, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateHS256Parallel(b *testing.B) {
	key := "12345678901234567890123456789012"
	token, _ := GenerateHS256("test-subject", key, 24*time.Hour)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := ValidateHS256(token, key)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkGenerateEdDSA(b *testing.B) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateEdDSA("test-subject", privateKey, 24*time.Hour)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateEdDSA(b *testing.B) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	token, err := GenerateEdDSA("test-subject", privateKey, 24*time.Hour)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := ValidateEdDSA(token, publicKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateEdDSAParallel(b *testing.B) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	token, err := GenerateEdDSA("test-subject", privateKey, 24*time.Hour)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := ValidateEdDSA(token, publicKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkExport(b *testing.B) {
	token, _ := GenerateHS256("test-subject", "12345678901234567890123456789012", 24*time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Export(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExportParallel(b *testing.B) {
	token, _ := GenerateHS256("test-subject", "12345678901234567890123456789012", 24*time.Hour)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := Export(token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func mustGenerateHS256Token(t *testing.T, subject string, key string, expire time.Duration) string {
	t.Helper()

	token, err := GenerateHS256(subject, key, expire)
	if err != nil {
		t.Fatalf("GenerateHS256() error = %v", err)
	}

	return token
}

func mustGenerateEdDSAToken(t *testing.T, subject string, privateKey ed25519.PrivateKey, expire time.Duration) string {
	t.Helper()

	token, err := GenerateEdDSA(subject, privateKey, expire)
	if err != nil {
		t.Fatalf("GenerateEdDSA() error = %v", err)
	}

	return token
}

func mustGenerateHS256WithRawPayload(t *testing.T, key string, rawPayloadBase64 string) string {
	t.Helper()

	signature, err := signTokenHS256(key, headerStrBase64HS256, rawPayloadBase64)
	if err != nil {
		t.Fatalf("signTokenHS256() error = %v", err)
	}

	return headerStrBase64HS256 + "." + rawPayloadBase64 + "." + signature
}

func mustBuildExpiredHS256Token(t *testing.T, key string) string {
	t.Helper()

	now := time.Now().UTC().Unix()
	payload := tokenPayload{
		Subject: "expired-hs256",
		Iat:     now - 120,
		Exp:     now - 60,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	payloadBase64 := encodeTo64(payloadJSON)
	signature, err := signTokenHS256(key, headerStrBase64HS256, payloadBase64)
	if err != nil {
		t.Fatalf("signTokenHS256() error = %v", err)
	}

	return fmt.Sprintf("%s.%s.%s", headerStrBase64HS256, payloadBase64, signature)
}

func mustBuildExpiredEdDSAToken(t *testing.T, privateKey ed25519.PrivateKey) string {
	t.Helper()

	now := time.Now().UTC().Unix()
	payload := tokenPayload{
		Subject: "expired-eddsa",
		Iat:     now - 120,
		Exp:     now - 60,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	payloadBase64 := encodeTo64(payloadJSON)
	signature := ed25519.Sign(privateKey, []byte(headerStrBase64EdDSA+"."+payloadBase64))

	return fmt.Sprintf("%s.%s.%s", headerStrBase64EdDSA, payloadBase64, encodeTo64(signature))
}

func replaceTokenPart(t *testing.T, token string, index int, value string) string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token must have 3 parts, got %d", len(parts))
	}
	if index < 0 || index > 2 {
		t.Fatalf("invalid token part index %d", index)
	}

	parts[index] = value
	return strings.Join(parts, ".")
}

func tamperTokenPart(t *testing.T, token string, index int) string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token must have 3 parts, got %d", len(parts))
	}
	if index < 0 || index > 2 {
		t.Fatalf("invalid token part index %d", index)
	}
	if len(parts[index]) == 0 {
		t.Fatalf("token part %d is empty", index)
	}

	part := []byte(parts[index])
	if part[0] == 'A' {
		part[0] = 'B'
	} else {
		part[0] = 'A'
	}

	parts[index] = string(part)
	return strings.Join(parts, ".")
}
