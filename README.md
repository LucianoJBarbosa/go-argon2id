# go-argon2id

Projeto de estudo implementando o algoritmo de hash de senha Argon2id em Go. 
Este é um projeto educacional que demonstra:
- Como implementar hashing seguro de senhas
- Boas práticas de programação em Go
- Implementação de testes unitários
- Uso do algoritmo Argon2id (vencedor da Password Hashing Competition)

## Características

- Implementação segura do Argon2id
- Parâmetros configuráveis
- Geração e verificação de hashes
- Suporte a salt personalizado
- Testes unitários abrangentes

## Instalação

```bash
# Clone o repositório
git clone https://github.com/LucianoJBarbosa/go-argon2id.git

# Entre no diretório
cd go-argon2id

# Execute os testes
go test -v
```

## Uso

```go
package main

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "github.com/LucianoJBarbosa/go-argon2id"
) 

func main() {
    // Gerar um salt aleatório
    saltBytes := make([]byte, crypto.DefaultParams.SaltLength)
    _, err := rand.Read(saltBytes)
    if err != nil {
        panic(err)
    }
    salt := base64.RawStdEncoding.EncodeToString(saltBytes)

    // Criar hash de senha
    hash, err := crypto.CreateHash("minha_senha", salt, crypto.DefaultParams)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Hash gerado: %s\n", hash)

    // Verificar senha
    match, err := crypto.ComparePasswordAndHash("minha_senha", hash)
    if err != nil {
        panic(err)
    }
    if match {
        fmt.Println("Senha correta!")
    } else {
        fmt.Println("Senha incorreta!")
    }
}
```

## Parâmetros

Os parâmetros padrão são:

- Memory: 64MB
- Iterations: 1
- Parallelism: Número de CPUs disponíveis
- SaltLength: 16 bytes
- KeyLength: 32 bytes

Você pode personalizar esses parâmetros criando uma nova instância de `Params`:

```go
customParams := &crypto.Params{
    Memory:      128 * 1024, // 128MB
    Iterations:  2,
    Parallelism: 4,
    SaltLength:  16,
    KeyLength:   32,
}
```

## Segurança

Este pacote implementa o algoritmo Argon2id, que é o vencedor da competição Password Hashing Competition e é recomendado para a maioria dos casos de uso por combinar proteção contra ataques de canal lateral e ataques baseados em GPU.

## Exemplos Práticos

### Hash de Senha com Parâmetros Personalizados

```go
params := &crypto.Params{
    Memory:      128 * 1024, // 128MB - Aumentado para maior segurança
    Iterations:  3,          // Mais iterações = mais seguro, mas mais lento
    Parallelism: 4,
    SaltLength:  16,
    KeyLength:   32,
}

hash, err := crypto.CreateHash("senha_secreta", salt, params)
```

### Verificação de Hash em Sistema de Login

```go
func Login(username, password, storedHash string) (bool, error) {
    // Verificar se a senha fornecida corresponde ao hash armazenado
    match, err := crypto.ComparePasswordAndHash(password, storedHash)
    if err != nil {
        return false, fmt.Errorf("erro ao verificar senha: %v", err)
    }
    return match, nil
}
```

## Contribuição

Contribuições são bem-vindas! Por favor, sinta-se à vontade para enviar um Pull Request. Para mudanças importantes, abra primeiro uma issue para discutir o que você gostaria de mudar.

Certifique-se de atualizar os testes conforme apropriado.

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.
