# 🔐 Sistema de Assinatura Digital e Verificação Segura de Arquivos

CIC0201 — Segurança Computacional — 2026/2 — Trabalho de Implementação 2.

Implementação em Python de RSA com OAEP (cifragem) e PSS (assinatura), conforme a RFC 8017, sem bibliotecas
criptográficas. Da biblioteca padrão são usados apenas o SHA3-256 (`hashlib`), bytes aleatórios (`secrets`/`random.SystemRandom`),
Base64, JSON e argparse. A exponenciação modular usa o `pow()` do Python.

**Requisitos:** Python 3.8 ou superior, sem dependências externas. Todos os comandos são executados na raiz do projeto.

## 📁 Organização

| Arquivo | Parte | Conteúdo |
|---|---|---|
| `MillerRabinNode.py` | I | Teste de Miller-Rabin e geração de primos de 1024 bits |
| `ChaveRSANode.py` | I | Cálculo dos parâmetros RSA e exportação/importação das chaves |
| `main.py` | I | Demonstração da geração, exportação e importação das chaves |
| `PrimitivasRSANode.py` | II | I2OSP, OS2IP, RSAEP e RSADP |
| `MGF1Node.py` | II | MGF1 com SHA3-256 |
| `CifragemOAEPNode.py` | II | Codificação EME-OAEP, cifragem e decifragem |
| `GerenciadorChavesNode.py` | II | Geração de chaves e carregamento validado dos arquivos JSON |
| `main_oaep.py` | II | Linha de comando para gerar chaves, cifrar e decifrar |
| `AssinaturaPSSNode.py` | III | Cálculo do digest SHA3-256, codificação probabilística PSS e geração da assinatura em Base64 |
| `VerificacaoPSSNode.py` | IV | Parsing do formato Base64, recuperação do hash original via chave pública e verificação de integridade |
| `main_pss.py` | III e IV | Linha de comando para orquestrar a assinatura e a verificação de arquivos |
| `tests/` | — | Casos de teste |

## 🔑 Parte I — Geração e Gerenciamento de Chaves RSA

- Os primos `p` e `q` têm 1024 bits (bit mais significativo e bit menos significativo forçados em `1`) e são aceitos após
  40 rodadas de Miller-Rabin com bases aleatórias.
- `n = p·q` tem 2048 bits, `φ(n) = (p−1)(q−1)`, `e = 65537` e `d = e⁻¹ mod φ(n)`, de modo que `e·d ≡ 1 (mod φ(n))`.
- As chaves são armazenadas em **JSON**, em dois arquivos:

```text
public_key.json   {"n": <módulo>, "e": 65537}
private_key.json  {"n": <módulo>, "d": <expoente privado>}
```

```text
python main.py
```

Gera o par de chaves, exibe os parâmetros e cria `public_key.json` e `private_key.json` na pasta atual.

## 🔒 Parte II — Cifragem e Decifragem RSA-OAEP

- OAEP com SHA3-256 e MGF1, com label opcional (`--label`), que deve ser o mesmo na cifragem e na decifragem.
- A cifragem é probabilística: a mesma mensagem gera ciphertexts diferentes.
- Tamanho máximo da mensagem: `k − 2·hLen − 2` = `256 − 2·32 − 2` = **190 bytes** para chave de 2048 bits.
- O ciphertext tem 256 bytes e é representado em **Base64** (344 caracteres).
- Qualquer falha na decifragem (ciphertext adulterado, chave errada, label diferente, padding inválido) gera sempre o
  mesmo erro, sem indicar qual verificação falhou:
  `Erro: falha na decifragem (ciphertext inválido ou adulterado)`.
- Entradas inválidas (Base64 malformado, arquivo de chave ausente, corrompido ou do tipo errado, mensagem longa demais)
  geram uma mensagem de erro curta, sem stack trace.

```text
python main_oaep.py gerar-chaves
python main_oaep.py cifrar   --chave public_key.json  --mensagem "Mensagem secreta" --saida cifrado.b64
python main_oaep.py decifrar --chave private_key.json --arquivo-cifrado cifrado.b64
```

Outras opções: `--arquivo` (mensagem lida de arquivo), `--ciphertext` (Base64 direto no terminal), `--saida` (grava o
resultado em arquivo) e `--label`. Use `python main_oaep.py <comando> --help` para detalhes.

## ✍️ Parte III e IV — Assinatura Digital e Verificação RSA-PSS
- Assinatura de arquivos baseada no cálculo de digest com SHA3-256 e função de máscara MGF1.
- A codificação é probabilística (EMSA-PSS-ENCODE): a aplicação de um salt aleatório garante que o mesmo arquivo gera assinaturas diferentes a cada execução, distanciando-se da abordagem simplificada de apenas cifrar o hash.
- O resultado da assinatura tem tamanho idêntico ao do módulo (256 bytes para uma chave de 2048 bits) e é exportado em **Base64**.
- A etapa de verificação recupera os campos, valida o padding inverso e informa claramente se o arquivo é íntegro. Qualquer adulteração de exatamente um byte (no arquivo, na assinatura ou na chave pública) resulta na rejeição imediata da validação.

```text
python main_pss.py assinar --chave private_key.json --arquivo documento.txt --saida assinatura.b64
python main_pss.py verificar --chave public_key.json --arquivo documento.txt --assinatura assinatura.b64
```

## 🧪 Testes

```text
python -m unittest discover -s tests -v
```

Executa todos os testes (alguns segundos, pois gera chaves de 2048 bits).

| Arquivo | O que verifica |
|---|---|
| `tests/test_parte1.py` | Miller-Rabin com primos, compostos e números de Carmichael; primos de 1024 bits; parâmetros da chave (`n = p·q`, 2048 bits, `gcd(e, φ) = 1`, `e·d ≡ 1`); exportação/importação; arquivo de chave inválido |
| `tests/test_parte2.py` | Cifrar e decifrar (mensagem vazia, UTF-8, 190 bytes); rejeição acima de 190 bytes; cifragem probabilística; MGF1; detecção de ciphertext adulterado, chave errada e label diferente; erro único para todas as falhas de padding; entradas inválidas na linha de comando |
| `tests/test_parte3.py` | Geração do digest com tamanho exato de 32 bytes; tratamento de exceções para leitura de arquivos inexistentes |
| `tests/test_parte4.py` | Comportamento de rejeição da verificação ao corromper propositalmente exatamente um byte do arquivo original, um byte da assinatura ou os parâmetros da chave pública |


## 👩‍💻 Desenvolvido por

- Érica Feitosa
- Isabela Furlan
- Laíssa Soares

Estudantes do CiC - UnB
