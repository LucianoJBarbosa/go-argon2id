package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// secureRandomInt gera um número aleatório seguro entre 0 e max-1
func secureRandomInt(max int) int {
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	n := binary.LittleEndian.Uint64(b[:])
	return int(n % uint64(max))
}

func TestArgon2idHashCreation(t *testing.T) {
	password := "minha_senha_segura123"
	saltBytes := make([]byte, DefaultParams.SaltLength)
	_, err := rand.Read(saltBytes)
	if err != nil {
		t.Fatalf("Erro ao gerar salt: %v", err)
	}
	salt := base64.RawStdEncoding.EncodeToString(saltBytes)

	hash, err := CreateHash(password, salt, DefaultParams)
	if err != nil {
		t.Fatalf("Erro ao criar hash: %v", err)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("Formato do hash inválido. Esperado 6 partes, obtido %d. Hash: %s", len(parts), hash)
	}

	if parts[1] != "argon2id" {
		t.Errorf("Variante incorreta. Esperado 'argon2id', obtido '%s'", parts[1])
	}

	t.Logf("Hash gerado: %s", hash)

	params, decodedSalt, _, err := DecodeHash(hash)
	if err != nil {
		t.Fatalf("Erro ao decodificar hash: %v", err)
	}

	if params.Memory != DefaultParams.Memory {
		t.Errorf("Memória incorreta. Esperado %d, obtido %d", DefaultParams.Memory, params.Memory)
	}
	if params.Iterations != DefaultParams.Iterations {
		t.Errorf("Iterações incorretas. Esperado %d, obtido %d", DefaultParams.Iterations, params.Iterations)
	}
	if params.Parallelism != DefaultParams.Parallelism {
		t.Errorf("Paralelismo incorreto. Esperado %d, obtido %d", DefaultParams.Parallelism, params.Parallelism)
	}

	if string(decodedSalt) != string(saltBytes) {
		t.Error("Salt não foi preservado corretamente")
	}

	match, err := ComparePasswordAndHash(password, hash)
	if err != nil {
		t.Fatalf("Erro ao verificar senha: %v", err)
	}
	if !match {
		t.Error("A verificação da senha falhou")
	}
	match, err = ComparePasswordAndHash("senha_errada", hash)
	if err != nil {
		t.Fatalf("Erro ao verificar senha incorreta: %v", err)
	}
	if match {
		t.Error("A verificação deveria falhar com senha incorreta")
	}
}

func TestArgon2idWithDifferentParameters(t *testing.T) {
	tests := []struct {
		name          string
		params        *Params
		shouldSucceed bool
	}{
		{
			name: "Parâmetros padrão",
			params: &Params{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: uint8(4),
				SaltLength:  16,
				KeyLength:   32,
			},
			shouldSucceed: true,
		},
		{
			name: "Parâmetros mais seguros",
			params: &Params{
				Memory:      256 * 1024,
				Iterations:  3,
				Parallelism: uint8(4),
				SaltLength:  32,
				KeyLength:   64,
			},
			shouldSucceed: true,
		},
		{
			name: "Memória muito baixa",
			params: &Params{
				Memory:      1024,
				Iterations:  1,
				Parallelism: uint8(4),
				SaltLength:  16,
				KeyLength:   32,
			},
			shouldSucceed: true,
		},
		{
			name: "Salt muito pequeno",
			params: &Params{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: uint8(4),
				SaltLength:  8,
				KeyLength:   32,
			},
			shouldSucceed: true,
		},
		{
			name: "Muitas iterações",
			params: &Params{
				Memory:      64 * 1024,
				Iterations:  10,
				Parallelism: uint8(4),
				SaltLength:  16,
				KeyLength:   32,
			},
			shouldSucceed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password := "teste123"
			saltBytes := make([]byte, tt.params.SaltLength)
			_, err := rand.Read(saltBytes)
			if err != nil {
				t.Fatalf("Erro ao gerar salt: %v", err)
			}
			salt := base64.RawStdEncoding.EncodeToString(saltBytes)

			hash, err := CreateHash(password, salt, tt.params)
			if err != nil {
				if tt.shouldSucceed {
					t.Errorf("CreateHash falhou: %v", err)
				}
				return
			}

			// Testar verificação
			match, err := ComparePasswordAndHash(password, hash)
			if err != nil {
				t.Errorf("ComparePasswordAndHash falhou: %v", err)
				return
			}
			if !match {
				t.Error("A senha válida não foi reconhecida")
			}
		})
	}
}

func TestConcurrentHashing(t *testing.T) {
	numGoroutines := 10
	done := make(chan bool)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			password := fmt.Sprintf("senha_teste_%d", id)
			saltBytes := make([]byte, DefaultParams.SaltLength)
			_, err := rand.Read(saltBytes)
			if err != nil {
				t.Errorf("Goroutine %d: Erro ao gerar salt: %v", id, err)
				done <- false
				return
			}
			salt := base64.RawStdEncoding.EncodeToString(saltBytes)

			hash, err := CreateHash(password, salt, DefaultParams)
			if err != nil {
				t.Errorf("Goroutine %d: Erro ao criar hash: %v", id, err)
				done <- false
				return
			}

			match, err := ComparePasswordAndHash(password, hash)
			if err != nil {
				t.Errorf("Goroutine %d: Erro ao verificar senha: %v", id, err)
				done <- false
				return
			}
			if !match {
				t.Errorf("Goroutine %d: A senha válida não foi reconhecida", id)
				done <- false
				return
			}
			done <- true
		}(i)
	}

	// Aguardar todas as goroutines terminarem
	for i := 0; i < numGoroutines; i++ {
		if !<-done {
			t.Error("Pelo menos uma goroutine falhou")
		}
	}
}

func TestExtremeParameters(t *testing.T) {
	tests := []struct {
		name          string
		params        *Params
		shouldSucceed bool
	}{
		{
			name: "Memória mínima",
			params: &Params{
				Memory:      8,
				Iterations:  1,
				Parallelism: 1,
				SaltLength:  16,
				KeyLength:   32,
			},
			shouldSucceed: false,
		},
		{
			name: "Memória muito alta",
			params: &Params{
				Memory:      1024 * 1024,
				Iterations:  1,
				Parallelism: 1,
				SaltLength:  16,
				KeyLength:   32,
			},
			shouldSucceed: true,
		},
		{
			name: "Muitas iterações",
			params: &Params{
				Memory:      64 * 1024,
				Iterations:  100,
				Parallelism: 1,
				SaltLength:  16,
				KeyLength:   32,
			},
			shouldSucceed: true,
		},
		{
			name: "Paralelismo alto",
			params: &Params{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 32,
				SaltLength:  16,
				KeyLength:   32,
			},
			shouldSucceed: true,
		},
		{
			name: "Salt grande",
			params: &Params{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 4,
				SaltLength:  64, // Salt grande
				KeyLength:   32,
			},
			shouldSucceed: true,
		},
		{
			name: "Chave grande",
			params: &Params{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 4,
				SaltLength:  16,
				KeyLength:   128, // Chave grande
			},
			shouldSucceed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password := "teste123"
			saltBytes := make([]byte, tt.params.SaltLength)
			_, err := rand.Read(saltBytes)
			if err != nil {
				t.Fatalf("Erro ao gerar salt: %v", err)
			}
			salt := base64.RawStdEncoding.EncodeToString(saltBytes)

			hash, err := CreateHash(password, salt, tt.params)
			if (err != nil) != !tt.shouldSucceed {
				t.Errorf("CreateHash() error = %v, shouldSucceed %v", err, tt.shouldSucceed)
				return
			}

			if tt.shouldSucceed {
				// Verificar se o hash pode ser validado
				match, err := ComparePasswordAndHash(password, hash)
				if err != nil {
					t.Errorf("ComparePasswordAndHash falhou: %v", err)
					return
				}
				if !match {
					t.Error("A senha válida não foi reconhecida")
				}
			}
		})
	}
}

func TestRandomPasswordInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("Pulando teste de fuzz em modo curto")
	}

	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?")
	for i := 0; i < 100; i++ {
		passwordLen := secureRandomInt(100) + 1 // Senhas de 1 a 100 caracteres
		password := make([]rune, passwordLen)
		for j := range password {
			password[j] = chars[secureRandomInt(len(chars))]
		}

		// Gerar salt
		saltBytes := make([]byte, DefaultParams.SaltLength)
		_, err := rand.Read(saltBytes)
		if err != nil {
			t.Fatalf("Erro ao gerar salt: %v", err)
		}
		salt := base64.RawStdEncoding.EncodeToString(saltBytes)

		hash, err := CreateHash(string(password), salt, DefaultParams)
		if err != nil {
			t.Errorf("CreateHash falhou com senha de tamanho %d: %v", passwordLen, err)
			continue
		}

		match, err := ComparePasswordAndHash(string(password), hash)
		if err != nil {
			t.Errorf("ComparePasswordAndHash falhou: %v", err)
			continue
		}
		if !match {
			t.Error("A senha válida não foi reconhecida")
		}
	}
}
