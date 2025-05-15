package jwt

import (
	"strings"
	"testing"
	"time"
)

//go:generate go test -v -race -bench=. -benchmem -cpu=1,2,4,8 -count=1
func TestMain(m *testing.M) {
	m.Run()
}

func TestGenerate(t *testing.T) {
	key := "12345678901234567890123456789012"
	subject := "test-subject"
	expire := 24 * time.Hour

	token, err := Generate(subject, key, expire)
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
			key:     "12345678901234567890123456789012",
			strict:  true,
			wantErr: false,
		},
		{
			name:    "valid token without strict mode",
			key:     "12345678901234567890123456789012",
			strict:  false,
			wantErr: false,
		},
		{
			name:    "invalid signature",
			key:     "12345678901234567890123456789013",
			strict:  true,
			wantErr: true,
		},
		{
			name:    "malformed token",
			token:   "invalid.token",
			key:     "12345678901234567890123456789012",
			strict:  true,
			wantErr: true,
		},
	}

	validToken, _ := Generate("test", "12345678901234567890123456789012", 24*time.Hour)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenToValidate := tt.token
			if tokenToValidate == "" {
				tokenToValidate = validToken
			}

			err := Validate(tokenToValidate, tt.key, tt.strict)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExport(t *testing.T) {
	subject := "test-subject"
	token, _ := Generate(subject, "12345678901234567890123456789012", 24*time.Hour)

	got, err := Export(token)
	if err != nil {
		t.Errorf("Export() error = %v", err)
		return
	}

	if got != subject {
		t.Errorf("Export() = %v, want %v", got, subject)
	}
}

func TestExpiredToken(t *testing.T) {
	key := "12345678901234567890123456789012"
	token, _ := Generate("test", key, 1*time.Second)

	// Simulate token expiration by waiting for 2 seconds
	time.Sleep(2 * time.Second)

	if err := Validate(token, key, false); err != nil {
		if !strings.Contains(err.Error(), "expired") {
			t.Errorf("Expected expired error, got %v", err)
		}
	}
}

func BenchmarkGenerate(b *testing.B) {
	key := "12345678901234567890123456789012"
	subject := "test-subject"
	expire := 24 * time.Hour

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Generate(subject, key, expire)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := Generate("test", "12345678901234567890123456789012", time.Hour)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkValidate(b *testing.B) {
	key := "12345678901234567890123456789012"
	token, _ := Generate("test-subject", key, 24*time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := Validate(token, key, true)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateParallel(b *testing.B) {
	key := "12345678901234567890123456789012"
	token, _ := Generate("test-subject", key, 24*time.Hour)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := Validate(token, key, true)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkExport(b *testing.B) {
	token, _ := Generate("test-subject", "12345678901234567890123456789012", 24*time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Export(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExportParallel(b *testing.B) {
	token, _ := Generate("test-subject", "12345678901234567890123456789012", 24*time.Hour)

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
