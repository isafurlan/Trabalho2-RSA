# Sistema de Assinatura Digital e Verificação Segura de Arquivos

## Parte I — Geração e Gerenciamento de Chaves RSA

### 1. Geração dos números primos

Os números primos `p` e `q` são gerados pela classe `MillerRabinNode`, utilizando o teste probabilístico de primalidade 
Miller-Rabin.

Cada primo possui 1024 bits, com o intuito de gerar um `n` de 2048 bits. Durante a geração, o bit mais significativo é 
forçado para `1`, garantindo que o número possua exatamente 1024 bits, e o bit menos significativo é forçado para `1`, 
garantindo que o candidato seja ímpar.

O teste de Miller-Rabin é executado múltiplas vezes. e caso um candidato seja considerado composto em alguma 
das rodadas, ele é descartado e um novo candidato é gerado.

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

A implementação verifica essa relação durante os testes da geração das chaves.

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

## Organização do Projeto

```text
MillerRabinNode
    └── geração e teste de números primos

ChaveRSANode
    ├── cálculo dos parâmetros RSA
    ├── construção das chaves
    ├── exportação das chaves
    └── importação das chaves
```

O arquivo principal (`main.py`) coordena a execução, gera os primos, constrói o par de chaves, exibe os parâmetros e testa 
a exportação e a importação.

