# Sistema de Assinatura Digital e Verificação Segura de Arquivos

## Parte I — Geração e Gerenciamento de Chaves RSA

### 1. Geração dos números primos

Os números primos `p` e `q` são gerados pela classe `MillerRabinNode`, utilizando o teste probabilístico de primalidade 
Miller-Rabin.

Cada primo possui 1024 bits, com o intuito de gerar um `n` de 2048 bits. Durante a geração, o bit mais significativo é 
forçado para `1`, garantindo que o número possua exatamente 1024 bits, e o bit menos significativo é forçado para `1`, 
garantindo que o candidato seja ímpar.

O teste de Miller-Rabin é executado 40 vezes, com bases aleatórias, e caso um candidato seja considerado composto em 
alguma das rodadas, ele é descartado e um novo candidato é gerado.

### 2. Construção da chave RSA

Após a geração de `p` e `q`, são calculados os parâmetros da chave RSA:

$$
n = p \cdot q
$$

e

$$
\phi(n) = (p-1)(q-1)
$$

O expoente público utilizado é:

$$
e = 65537
$$

O expoente privado `d` é calculado como o inverso multiplicativo de `e` módulo `\phi(n)`:

$$
d \equiv e^{-1} \pmod{\phi(n)}
$$

Dessa forma, é satisfeita a relação:

$$
e \cdot d \equiv 1 \pmod{\phi(n)}
$$

O programa principal (`main.py`) exibe o valor abaixo para conferência dessa relação, que deve ser igual a `1`:

$$
(e \cdot d) \bmod \phi(n) = 1
$$



### 3. Armazenamento das chaves

O grupo definiu **JSON** como formato para armazenamento das chaves por ser simples, estruturado e facilmente processável em Python.

São utilizados dois arquivos distintos:

```text
public_key.json
private_key.json
```

**Chave pública:**

```json
{
    "n": <módulo RSA>,
    "e": 65537
}
```

**Chave privada:**

```json
{
    "n": <módulo RSA>,
    "d": <expoente privado>
}
```

### 4. Exportação e importação

A classe `ChaveRSANode` implementa funções para exportar e importar as chaves.

A exportação transforma os parâmetros da chave em um arquivo JSON, conforme explicitado no tópico anterior:

```text
chave em memória
      ↓
  exportação
      ↓
public_key.json / private_key.json
```

A importação realiza o processo inverso:

```text
public_key.json / private_key.json
      ↓
    importação
      ↓
chave disponível no programa
```

Esse mecanismo permite que uma chave gerada em uma execução do programa seja armazenada e reutilizada posteriormente, 
sem a necessidade de gerar novamente `p` e `q`.

### 5. Como executar

```text
python main.py
```

O programa gera o par de chaves, exibe os parâmetros e cria os arquivos `public_key.json` e `private_key.json` na pasta 
atual.

## Organização do Projeto

```text
MillerRabinNode
    └── geração e teste de números primos

ChaveRSANode
    ├── cálculo dos parâmetros RSA
    ├── construção das chaves
    ├── exportação das chaves
    └── importação das chaves

PrimitivasRSANode (Parte II)
    └── I2OSP, OS2IP, RSAEP e RSADP

MGF1Node (Parte II)
    └── função de geração de máscara MGF1 com SHA3-256

CifragemOAEPNode (Parte II)
    └── codificação EME-OAEP, cifragem e decifragem RSA-OAEP

GerenciadorChavesNode (Parte II)
    └── geração de chave e carregamento validado dos arquivos JSON
```

O arquivo principal (`main.py`) coordena a execução da Parte I, gera os primos, constrói o par de chaves, exibe os 
parâmetros e testa a exportação e a importação. A interface da Parte II fica em `main_oaep.py`.

## Parte II — RSA-OAEP

Cifragem e decifragem RSAES-OAEP conforme a RFC 8017 (PKCS #1 v2.2), seção 7.1, usando **SHA3-256** como função de hash 
(`hLen = 32` bytes) e **MGF1** (apêndice B.2.1) como função de geração de máscara. As operações RSA, o OAEP e a MGF1 
foram implementados sem bibliotecas criptográficas; a biblioteca padrão é usada apenas para o SHA3-256 
(`hashlib.sha3_256`), para os bytes aleatórios do seed (`secrets`), Base64, JSON e argparse. A exponenciação modular 
usa a função nativa `pow()` do Python, a mesma utilizada na Parte I.

A Parte II reutiliza a Parte I sem modificá-la: `MillerRabinNode` e `ChaveRSANode` geram as chaves, e os arquivos 
`public_key.json` / `private_key.json` são lidos no formato definido na seção 3.

### Arquivos

| Arquivo | Conteúdo |
|---|---|
| `PrimitivasRSANode.py` | `I2OSP`, `OS2IP` (RFC 8017, seção 4), `RSAEP`, `RSADP` (seção 5.1) e `key_size_bytes(n)` |
| `MGF1Node.py` | `MGF1` com SHA3-256 (apêndice B.2.1) |
| `CifragemOAEPNode.py` | Codificação/decodificação EME-OAEP e `encrypt` / `decrypt` (seção 7.1) |
| `GerenciadorChavesNode.py` | Geração de chave com as garantias do `main.py` e carregamento validado dos arquivos JSON |
| `main_oaep.py` | Interface de linha de comando |

Assim como na Parte I, cada arquivo contém uma classe de mesmo nome, e os métodos são chamados diretamente pela 
classe:

```python
from GerenciadorChavesNode import GerenciadorChavesNode
from CifragemOAEPNode import CifragemOAEPNode

public_key = GerenciadorChavesNode.load_public_key("public_key.json")     # (n, e)
private_key = GerenciadorChavesNode.load_private_key("private_key.json")  # (n, d)

C = CifragemOAEPNode.encrypt(public_key, "Mensagem secreta".encode("utf-8"))
M = CifragemOAEPNode.decrypt(private_key, C).decode("utf-8")
```

### Como executar

Requer Python 3.8 ou superior, sem dependências externas. Todos os comandos são executados na raiz do projeto.

```text
python main_oaep.py gerar-chaves
python main_oaep.py cifrar   --chave public_key.json  --mensagem "Mensagem secreta" --saida cifrado.b64
python main_oaep.py decifrar --chave private_key.json --arquivo-cifrado cifrado.b64
```

O primeiro comando gera as chaves, o segundo salva o ciphertext em Base64 no arquivo `cifrado.b64` e o terceiro lê esse 
arquivo e mostra a mensagem original.

Sem `--saida`, o comando `cifrar` mostra o Base64 no terminal. Nesse caso, copie o valor e passe-o entre aspas para o 
`decifrar`, substituindo `COLE_AQUI_O_BASE64`:

```text
python main_oaep.py cifrar   --chave public_key.json  --mensagem "Mensagem secreta"
python main_oaep.py decifrar --chave private_key.json --ciphertext "COLE_AQUI_O_BASE64"
```

Outras opções:

```text
python main_oaep.py cifrar   --chave public_key.json  --arquivo mensagem.txt --saida cifrado.b64
python main_oaep.py decifrar --chave private_key.json --arquivo-cifrado cifrado.b64 --saida decifrado.txt
python main_oaep.py cifrar   --chave public_key.json  --mensagem "texto" --label "contexto" --saida cifrado.b64
python main_oaep.py decifrar --chave private_key.json --arquivo-cifrado cifrado.b64 --label "contexto"
```

O `--label` é o rótulo `L` do OAEP (padrão: vazio) e precisa ser o mesmo na cifragem e na decifragem.

Entradas inválidas (Base64 malformado, arquivo de chave ausente ou corrompido, chave do tipo errado, mensagem longa 
demais) geram uma mensagem de erro clara, sem stack trace. Qualquer falha na decifragem (ciphertext adulterado, chave 
errada, label diferente) gera sempre a mesma mensagem:

```text
Erro: falha na decifragem (ciphertext inválido ou adulterado)
```

### Formato do ciphertext

O ciphertext é uma string de exatamente `k` bytes, onde `k` é o tamanho de `n` em bytes (256 para uma chave de 
2048 bits), codificada em **Base64** (344 caracteres para `k = 256`).

### Limite de tamanho da mensagem

$$
mLen \le k - 2 \cdot hLen - 2
$$

Para uma chave de 2048 bits com SHA3-256: `256 - 2·32 - 2 = 190` bytes. Textos com acentos ocupam mais de um byte por 
caractere em UTF-8. Mensagens maiores são rejeitadas pela interface com a mensagem:

```text
Erro: mensagem longa demais (191 bytes; o máximo para esta chave é 190 bytes).
```

No código, o método `CifragemOAEPNode.encrypt` lança a exceção `MessageTooLongError` (`message too long`).

