package jwt_test

import (
	"strings"
	"testing"
	"time"

	jwt "github.com/mertakinstd/jwtgenerator"
)

func TestGenerate(t *testing.T) {
	key := "test-key"
	subject := "test-subject"
	expire := 24 * time.Hour

	token, err := jwt.Generate(subject, key, expire)
	if err != nil {
		t.Errorf("Generate() error = %v", err)
		return
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("Generate() token should have 3 parts, got %d", len(parts))
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		key     string
		strict  bool
		wantErr bool
	}{
		{
			name:    "valid token with strict mode",
			key:     "test-key",
			strict:  true,
			wantErr: false,
		},
		{
			name:    "valid token without strict mode",
			key:     "test-key",
			strict:  false,
			wantErr: false,
		},
		{
			name:    "invalid signature",
			key:     "wrong-key",
			strict:  true,
			wantErr: true,
		},
		{
			name:    "malformed token",
			token:   "invalid.token",
			key:     "test-key",
			strict:  true,
			wantErr: true,
		},
	}

	validToken, _ := jwt.Generate("test", "test-key", 24*time.Hour)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenToValidate := tt.token
			if tokenToValidate == "" {
				tokenToValidate = validToken
			}

			err := jwt.Validate(tokenToValidate, tt.key, tt.strict)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExport(t *testing.T) {
	subject := "test-subject"
	token, _ := jwt.Generate(subject, "test-key", 24*time.Hour)

	got, err := jwt.Export(token)
	if err != nil {
		t.Errorf("Export() error = %v", err)
		return
	}

	if got != subject {
		t.Errorf("Export() = %v, want %v", got, subject)
	}
}

func TestExpiredToken(t *testing.T) {
	key := "test-key"
	token, _ := jwt.Generate("test", key, 1*time.Second)

	// Simulate token expiration by waiting for 2 seconds
	time.Sleep(2 * time.Second)

	if err := jwt.Validate(token, key, false); err != nil {
		if !strings.Contains(err.Error(), "expired") {
			t.Errorf("Expected expired error, got %v", err)
		}
	}
}
