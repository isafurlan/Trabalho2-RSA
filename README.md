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

O expoente privado `d` é calculado como o inverso multiplicativo de `e` módulo $\phi(n)$:

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

main_oaep.py (Parte II)
    └── linha de comando para gerar chaves, cifrar e decifrar
```

O arquivo principal (`main.py`) coordena a execução da Parte I, gera os primos, constrói o par de chaves, exibe os 
parâmetros e testa a exportação e a importação. A interface da Parte II fica em `main_oaep.py`.

## Parte II — RSA-OAEP

Cifragem e decifragem RSA-OAEP (RFC 8017) com SHA3-256 e MGF1, feitas sem bibliotecas de criptografia. Da biblioteca 
padrão são usados só o SHA3-256 (`hashlib`), os bytes aleatórios (`secrets`), Base64, JSON e argparse. A exponenciação 
modular usa o `pow()` do Python, como na Parte I. As chaves são as da Parte I, nos mesmos arquivos JSON.

### Funcionalidades

- `PrimitivasRSANode`: I2OSP, OS2IP, RSAEP e RSADP.
- `MGF1Node`: MGF1 com SHA3-256.
- `CifragemOAEPNode`: codificação OAEP, `encrypt` e `decrypt`.
- `GerenciadorChavesNode`: gera chaves com a Parte I e carrega os arquivos JSON validando os campos.
- `main_oaep.py`: linha de comando para gerar chaves, cifrar e decifrar.

**Detalhes:**

- Label opcional (`--label`), que precisa ser o mesmo na cifragem e na decifragem.
- A mesma mensagem cifrada duas vezes gera ciphertexts diferentes.

### Como executar

Python 3.8 ou superior, sem dependências externas. Na raiz do projeto:

```text
python main_oaep.py gerar-chaves
python main_oaep.py cifrar   --chave public_key.json  --mensagem "Mensagem secreta" --saida cifrado.b64
python main_oaep.py decifrar --chave private_key.json --arquivo-cifrado cifrado.b64
```

Passando o ciphertext direto pelo terminal:

```text
python main_oaep.py cifrar   --chave public_key.json  --mensagem "Mensagem secreta"
python main_oaep.py decifrar --chave private_key.json --ciphertext "BASE64_GERADO_NO_COMANDO_ANTERIOR"
```

Mensagem lida de arquivo e resultado salvo em arquivo:

```text
python main_oaep.py cifrar   --chave public_key.json  --arquivo mensagem.txt --saida cifrado.b64
python main_oaep.py decifrar --chave private_key.json --arquivo-cifrado cifrado.b64 --saida decifrado.txt
```

Com label:

```text
python main_oaep.py cifrar   --chave public_key.json  --mensagem "texto" --label "contexto" --saida cifrado.b64
python main_oaep.py decifrar --chave private_key.json --arquivo-cifrado cifrado.b64 --label "contexto"
```

Entradas inválidas (Base64 malformado, arquivo de chave ausente ou corrompido, chave do tipo errado, mensagem longa 
demais) mostram uma mensagem de erro curta, sem stack trace. Qualquer falha na decifragem (ciphertext adulterado, chave 
errada, label diferente) mostra sempre o mesmo erro:

```text
Erro: falha na decifragem (ciphertext inválido ou adulterado)
```

### Formato do ciphertext

O ciphertext tem `k` bytes, o tamanho de `n` em bytes: 256 bytes com chave de 2048 bits. Ele é mostrado e salvo em 
**Base64**, com 344 caracteres.

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
