package crypto

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("argon2id: hash is not in the correct format")
	ErrIncompatibleVariant = errors.New("argon2id: incompatible variant of argon2")
	ErrIncompatibleVersion = errors.New("argon2id: incompatible version of argon2")
)

// DefaultParams define os parâmetros padrão para o Argon2id
// Esses parâmetros podem ser ajustados conforme necessário para aumentar a segurança ou o desempenho.
// Eles são utilizados para gerar o hash da senha e devem ser consistentes em toda a aplicação.
// É importante manter esses parâmetros consistentes para garantir que os hashes possam ser verificados corretamente.
// Os parâmetros são:
// - Memory: a quantidade de memória a ser usada (em KB)
// - Iterations: o número de iterações a serem realizadas
// - Parallelism: o número de threads a serem usadas
// - SaltLength: o tamanho do salt a ser gerado
// - KeyLength: o tamanho da chave resultante do hash
var DefaultParams = &Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  1,
	Parallelism: uint8(runtime.NumCPU()),
	SaltLength:  16,
	KeyLength:   32,
}

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func CreateHash(password, salt string, p *Params) (string, error) {
	saltBytes, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return "", fmt.Errorf("erro ao decodificar o salt: %v", err)
	}

	hash := argon2.IDKey([]byte(password), saltBytes, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(saltBytes)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

// DecodeHash decodifica o hash Argon2id e retorna os parâmetros, salt e chave.
func DecodeHash(encodedHash string) (p *Params, salt, key []byte, err error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return nil, nil, nil, ErrIncompatibleVariant
	}

	var version int
	_, err = fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &Params{}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.SaltLength = uint32(len(salt))

	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.KeyLength = uint32(len(key))

	return p, salt, key, nil
}

// CheckHash verifica se uma hash gerada com os mesmos parâmetros e salt corresponde ao hash fornecido.
func CheckHash(password, encodedHash string) (match bool, p *Params, err error) {
	p, salt, hash, err := DecodeHash(encodedHash)
	if err != nil {
		return false, nil, err
	}

	generatedHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	hashLegth := int32(len(hash))
	generatedHashLength := int32(len(generatedHash))

	if subtle.ConstantTimeCompare(hash, generatedHash) == 0 {
		return false, p, nil
	}

	if subtle.ConstantTimeCompare(hash[:hashLegth], generatedHash[:generatedHashLength]) == 1 {
		return true, p, nil
	}

	return false, p, nil
}

// ComparePasswordAndHash compara uma senha com um hash codificado.
func ComparePasswordAndHash(password, encodedHash string) (bool, error) {
	match, _, err := CheckHash(password, encodedHash)
	if err != nil {
		return false, fmt.Errorf("erro ao verificar a senha: %v", err)
	}
	return match, nil
}
