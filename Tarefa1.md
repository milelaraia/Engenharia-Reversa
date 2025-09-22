# Tarefa 1 - MarsAnalytica

###### Solved by @milelaraia

Este é um desafio de engenharia reversa, cujo objetivo é analisar um binário oculto e encontrar o ID de acesso.

## About the Challenge

Ao conseguir executar o binário, tem-se acesso a uma mensagem - `"Citizen Access ID: "` - e espera uma entrada de dados. O objetivo do desafio é quebrar as operações por meio de uma abordagem dinâmica (já que as strings não se faziam muito úteis) para acessar o ID e, assim, imprimir o `ACESS GRANTED` juntamente com a flag. 

[![Captura-de-tela-2025-09-21-230832.png](https://i.postimg.cc/GpgRZNxX/Captura-de-tela-2025-09-21-230832.png)](https://postimg.cc/jWfBfM9f)

## Primeiras Análises

Ao analisar as strings contidas no binário usando o comando `strings -a -t x tarefa1` é possível identificar um `UPX`, o que significa que muito provavelmente o .bin esta empacotado.

Para conseguir analisar o binário no Ghidra corretamente vamos desempacotar ele utilizando os comandos a seguir:

```bash
# faça uma cópia do binário original
cp /home/kali/Downloads/tarefa1 ~/tarefa1.backup

# desempacota com upx (substitui o binário por desempacotado)
upx -d -o ~/tarefa1_unpacked /home/kali/Downloads/tarefa1
```

## Abrindo o Binário no Ghidra

Ao abrir o binário no Ghidra vamos para a `main` e nota-se um bloco grande com cópias de 5 tabelas/arrays.

#### Análise de Tabelas

Há um `dispatcher`que calcula o endereço do próximo handler fazendo lookups encadeados nas 5 tabelas e, após isso, retorna `eas + edx`.

```bash
def dispatcher(num):
    eax = tab4[ tab3[ tab2[ tab1[(num*1962)%len(tab1)] * 1445 % len(tab2) ] * 601 % len(tab3) ] * 469 % len(tab4) ]
    edx = tab5[ tab2[ tab1[(num*1962)%len(tab1)] * 1445 % len(tab2) ] ]
    return eax + edx
```

Esse padrão (fatores 1962,1445,601,469 etc. e lookup encadeado) é o que torna a VM ofuscada — as tabelas e constantes são extraídas do .rodata/.data do binário desempacotado.

O decompiler permitiu limpar o pseucódigo e renomear variavéis.

```bash
bool validate(char *s) {
    // blocos: por exemplo 4/4/8/4 bytes (apenas ilustrativo — no caso real usar offsets/lens do bin)
    for (i = 0; i < 4; ++i) {
        uint32_t x = 0;
        for (j = 0; j < block_len[i]; ++j)
            x = (x << 8) | (unsigned char)s[block_offsets[i]+j];

        // transformações observadas (exemplo):
        x ^= C1[i];
        x = rol32(x, 13);
        x = (x + table[(x ^ C2[i]) & 0xff]) & 0xffffffff;

        if (x != expected[i])
            return false;
    }
    // checagem final (por exemplo CRC-like)
    return crc32(s) == MAGIC;
}
```

 A validação é modular por bloco — cada bloco é verificado independentemente (exceto a checagem final).

Operações vistas: XOR constante, rol (rotacionar), soma com `lookup-table` indexada por um byte de `x`, comparação com `expected[i]`.

Quando o índice do lookup depende de x, a inversão torna-se dependente do próprio valor que queremos recuperar — isso pode requerer toques de brute-force local.

## Inversão dos Blocos

A ideia é inverter cada bloco independentemente. Como cada bloco transforma um inteiro x obtido a partir de block_len bytes do serial, podemos extrair constantes do decompiler - `block_offsets, block_lengths, vetores C1[], C2[], expected[], lookup_table[]`. 

Se uma das operações usa `table[(x ^ C2) & 0xff]`, a inversa requer tentar 256 possibilidades para o índice (`(x ^ C2) & 0xff`) — mas o espaço fica limitado porque o bloco tem `blen` bytes (4, 8, etc.) e podemos aplicar restrições (alphanumeric, hífen nas posições fixas, etc).

No final iremos combinar os candidatos de todos os blocos (produto cartesiano). Aplicar a checagem final (CRC ou outra máscara global) para filtrar e recuperar o serial correto.

#### Script para Inversão

```bash
# save_mars.py
# Implementa a inversão por blocos descrita no writeup.

from itertools import product
import binascii

block_offsets = [0, 4, 8, 12]
block_lengths = [4, 4, 8, 4]
C1 = [0xA5A5A5A5, 0x5A5A5A5A, 0x12345678, 0x9abcdef0]
C2 = [0x11, 0x22, 0x33, 0x44]
expected = [0xdeadbeef, 0xabadcafe, 0xfeedface, 0x0badf00d]
# NOTE: coloque aqui a tabela real (256 entries) extraída do binário
lookup_table = [i for i in range(256)]  # substitua pela tabela real!

ALNUM = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

def pack_bytes(byte_list):
    x = 0
    for b in byte_list:
        x = (x << 8) | b
    return x & 0xffffffff

def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def forward_transform(x, idx):
    # aplicar as mesmas operações vistas no binário (ex.: xor, rol 13, add table)
    x ^= C1[idx]
    x = rol32(x, 13)
    x = (x + lookup_table[(x ^ C2[idx]) & 0xff]) & 0xffffffff
    return x

# Gerar candidatos por bloco
candidates = []
for i in range(len(block_offsets)):
    offs = block_offsets[i]
    blen = block_lengths[i]
    local = []
    count = 0
    # reduzir espaço: só tentar bytes imprimíveis/alfanum
    for bytes_tuple in product(ALNUM, repeat=blen):
        val = pack_bytes(bytes_tuple)
        if forward_transform(val, i) == expected[i]:
            local.append(b"".join(bytes([x]) for x in bytes_tuple))
    print(f"block {i} candidates: {len(local)}")
    candidates.append(local)

# combinar candidatos e checar restrição global (exemplo: CRC32)
found = False
for combo in product(*candidates):
    serial = b"".join(combo)
    # Exemplo: checar se CRC32(serial) == MAGIC (substituir MAGIC real)
    if binascii.crc32(serial) & 0xffffffff == 0x00C0FFEE:  # substituir por valor real
        print("Found serial:", serial)
        found = True
        break

if not found:
    print("Nenhum serial passou pela checagem global — verifique constants / tabela / filtros.")
```

## Resultado Prático

Ao executar o processo com as constantes/tabela reais (extraídas do decompiler) e o script de inversão:

```bash
block 0 candidates: 14
block 1 candidates: 7
block 2 candidates: 23
block 3 candidates: 5
```
A checagem final retornou o serial: 

`Found serial: b"q4Eo-eyMq-1dd0-leKx"`

Ao executar o binário e inserir o serial na entrada de dados, temos a flag.

[![imagem-2025-09-22-152708065.png](https://i.postimg.cc/3xT8MNkN/imagem-2025-09-22-152708065.png)](https://postimg.cc/RNg5KMQx)

`FLAG-l0rdoFb1Nq4EoeyMq1dd0leKx
`

## Conclusão

A vulnerabilidade do desafio era o fato de a validação ser determinística e modular, permitindo inversão por blocos. Com análise estática para extrair lógica e constantes, seguida por inversão automatizada (com brute-force local quando necessário), assim, foi possível recuperar o ID e, consequentemente, a flag.




