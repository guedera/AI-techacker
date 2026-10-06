# Resumo do projeto (versão simples, pra estudar)

Este documento explica o Endpoint Investigator com palavras simples. A ideia é que você consiga
**explicar cada parte pro professor** sem decorar: entendendo o porquê de cada decisão.

Sugestão de estudo, em ordem: leia as seções 1 a 5, rode os comandos do `apresentacao.md`,
abra os arquivos da seção 11 acompanhando o exemplo da seção 5, e responda em voz alta as
perguntas da seção 10.

---

## 1. A ideia em 30 segundos

> "Nossa ferramenta tira uma **foto** de um computador Linux (processos, permissões e serviços),
> **liga** essas informações entre si e mostra ao analista o que merece investigação. Ela não diz
> 'foi invadido'. Ela diz: **isto foi observado, isto é o que significa, esta é a hipótese, e isto é o
> que ainda falta pra confirmar**."

O ponto central do trabalho (e do enunciado) é: **uma informação isolada quase nunca prova nada**. O
valor está em **combinar** informações.

## 2. O problema, com uma analogia

Imagine que você é um detetive numa casa:

- "A porta dos fundos está destrancada." Sozinho, isso não quer dizer nada.
- "Tem um cofre na casa." Sozinho, também não.
- "A porta dos fundos está destrancada **e** dá direto na sala do cofre **e** o cofre abre com a mesma
  chave que está pendurada na porta." Agora sim, isso merece atenção.

No Linux é igual:

- "Esse serviço roda como **root**" (o usuário que pode tudo): normal, muitos serviços rodam.
- "Esse arquivo pode ser alterado por **qualquer um**": má configuração, mas talvez ninguém use.
- "Um serviço **root** executa um **script** que **qualquer um** pode alterar": isso é um risco,
  porque quem alterar o script faz o root executar o que quiser.

Cada informação vem de um comando diferente (`ps` pra processos, `ls -l` pra permissões,
`systemctl` pra serviços). Nossa ferramenta **junta as três** pra enxergar a combinação.

## 3. Vocabulário que você precisa dominar

| Termo | O que é (simples) | Exemplo |
|---|---|---|
| **Processo** | Um programa que está rodando agora | o `bash` que você abriu |
| **PID** | O número de identificação de um processo | `2417` |
| **PPID** | O PID do processo **pai** (quem iniciou ele) | o `sudo` é pai do comando que ele roda |
| **Usuário / root** | Quem é "dono" do processo. `root` é o superusuário, pode tudo | `root`, `guedes` |
| **Serviço** | Programa que roda em segundo plano, iniciado pelo sistema (pelo `systemd`) | `ssh`, `cron` |
| **Script** | Arquivo de texto com comandos que um programa executa | `backup.sh` |
| **Interpretador** | Programa que executa um script | `bash`, `python` |
| **Permissão** | Quem pode **ler**, **escrever** e **executar** um arquivo | `rwx` |
| **World-writable** | Arquivo que **qualquer usuário** pode alterar | modo `0777` |
| **sudo** | Comando pra um usuário comum rodar algo como root | `sudo ls` |
| **Snapshot** | Uma "foto" do estado do sistema num momento | o que a ferramenta coleta |
| **Dataset** | Conjunto de arquivos de teste, **fictícios**, gerados pelo script do professor | `training/demo-3-correlacao` |
| **/proc** | Pasta especial do Linux onde o sistema mostra dados dos processos (cada processo tem uma subpasta com o seu PID) | `/proc/2417/` |
| **systemctl** | Comando que lista e mostra detalhes dos serviços | `systemctl list-units` |
| **Evidência** | O que foi **observado** de fato | "o arquivo tem permissão 0777" |
| **Hipótese** | Uma **possível explicação**, ainda não provada | "alguém poderia alterar o script" |

### Como ler uma permissão como `0777`

São 3 dígitos que importam (o `0` da frente a gente ignora): **dono, grupo, outros**. Cada dígito soma:
**ler = 4, escrever = 2, executar = 1**. Então `7 = 4+2+1 = pode tudo`, `5 = 4+1 = ler e executar`,
`0 = nada`.

| Modo | Dono | Grupo | Outros | Quem pode **escrever** |
|---|---|---|---|---|
| `0700` | tudo | nada | nada | só o dono |
| `0755` | tudo | ler/executar | ler/executar | só o dono |
| `0770` | tudo | tudo | nada | dono e grupo |
| `0777` | tudo | tudo | tudo | **todo mundo** |

A nossa regra olha o "escrever" (valor 2) no dígito de **outros** (o último) e no de **grupo** (o
penúltimo).

## 4. Como a ferramenta funciona

O enunciado pede este fluxo, e foi exatamente o que construímos:

```
COLETA  →  NORMALIZAÇÃO  →  CORRELAÇÃO  →  EVIDÊNCIAS/HIPÓTESES  →  RESULTADO
```

### 4.1 Coleta: "tirar as fotos"

São **3 coletores**, um pra cada dimensão obrigatória: **processos**, **permissões** e **serviços**.
Cada um existe em **2 versões**, que entregam o mesmo tipo de dado:

| | Versão **real** (Linux de verdade) | Versão **dataset** (arquivos de teste) |
|---|---|---|
| Processos | lê `/proc/<pid>/` (`status`, `stat`, `cmdline`, `exe`) | lê `processes.csv` |
| Permissões | usa `os.stat()` em arquivos específicos | lê `permissions.csv` |
| Serviços | roda `systemctl list-units`, `show` e `cat` | lê `services.txt` |

**Por que duas versões?** Porque desenvolvemos no Mac (que não tem `/proc` nem `systemd`) e porque
precisamos de testes **repetíveis**. Assim a **mesma lógica de análise** roda no dataset ou na VM Kali,
sem mudar uma linha.

**Detalhe importante (e que o enunciado pede):** a ferramenta **não varre o disco inteiro** procurando
permissões. Ela só olha os arquivos que **aparecem nos processos e serviços** que já coletou. O
coletor real até **recusa** funcionar sem uma lista de arquivos (dá erro). Isso é "análise guiada por
contexto".

### 4.2 Normalização: "colocar tudo no mesmo formato e ligar os pontos"

Os dados chegam em formatos diferentes (arquivo CSV, saída de comando, pasta `/proc`). Convertemos
tudo pra **três formatos comuns** (`Process`, `FileResource`, `Service`, no arquivo `models.py`) e
juntamos numa classe chamada **`Snapshot`**, que sabe responder:

- Quem é o **pai** deste processo? Quem são os **filhos**?
- Qual **processo** corresponde a este **serviço**? (comparando o comando do serviço com o comando do
  processo)
- Quais **arquivos** este serviço usa?
- Qual a **permissão** deste arquivo?

**O truque do interpretador** (vale saber explicar): se o serviço roda `bash /opt/backup/backup.sh`, o
programa é o `bash`, mas quem realmente manda é o **script**. Então, quando o executável é um
interpretador (`bash`, `sh`, `dash`, `zsh`, `python...`), a ferramenta também olha os **argumentos** pra
achar o script. Sem isso, ela olharia só o `bash` e **perderia o script**, que é o que importa.

### 4.3 Correlação: "as perguntas que ligam os pontos"

São **2 regras** (o enunciado pede no mínimo 2):

**Regra 1: Processo + Serviço + Permissão.** Em português:
*"Existe algum serviço rodando como root que executa um arquivo que outras pessoas conseguem
alterar?"*

| Situação | Severidade | Confiança |
|---|---|---|
| Arquivo gravável por **qualquer um** (`0777`) | alta | alta |
| Gravável só pelo **grupo** (`0770`) | média | baixa (não sabemos quem está no grupo) |
| Só o dono escreve (`0700`, `0755`) | **nenhum achado** | |

**Regra 2: Processo + PPID + Usuário.** Em português:
*"Existe algum processo rodando como root cujo pai é um usuário comum?"* Isso significa que alguém
"subiu de privilégio". Pode ser normal (`sudo`) ou suspeito.

| Situação | Severidade | Confiança |
|---|---|---|
| Veio de `sudo`, `su` ou `pkexec` (no processo **ou no pai**) | baixa | alta (é o caminho esperado) |
| Subiu pra root **sem** nenhuma ferramenta conhecida | alta | baixa (sabemos que aconteceu, não o motivo) |

Note o que **não** gera achado: um serviço root com script restrito (`0700`), e o `sshd` (root)
abrindo o shell de um usuário comum (isso é o root **descendo** de privilégio, é normal).

### 4.4 Evidências e hipóteses: "o jeito de falar do achado"

Todo achado (`Finding`) tem **4 campos separados**, como um detetive que não mistura fato com palpite:

| Campo | Pergunta que responde | Exemplo (Regra 1) |
|---|---|---|
| **Evidência** | O que eu **vi**? | "O serviço `backup-agent` roda como root e executa `backup.sh`, que tem permissão `0777`" |
| **Interpretação** | O que isso **significa** tecnicamente? | "O arquivo pode ser alterado por qualquer usuário" |
| **Hipótese** | O que **pode** estar acontecendo? | "Se alguém alterar o arquivo, ele roda como root na próxima vez" |
| **Evidência ausente** | O que **falta** pra confirmar? | "Não sabemos se alguém realmente alterou; um log de auditoria ajudaria" |

E mais dois campos **independentes** (essa é uma pergunta clássica, decore a diferença):

- **Severidade**: *quão grave seria **se a hipótese for verdade**?*
- **Confiança**: *quão **certos** estamos de que ela é verdade?*

Analogia: o alarme de fumaça tocou. A **severidade** é o tamanho do incêndio que seria (alto). A
**confiança** é o quanto você acredita que tem mesmo fogo, e não só alguém fazendo torrada (depende).

**De onde vêm os textos?** De **modelos de frase** (templates) escritos dentro das regras, em Python.
A evidência é montada com os dados reais da coleta (nome do serviço, caminho, permissão...). O resto é
texto fixo por regra. **Não tem IA gerando texto.** Mesma entrada, mesma saída.

### 4.5 Resultado

Um relatório no terminal (biblioteca `rich`): um **painel por achado**, colorido pela severidade
(vermelho = alta, amarelo = média, verde = baixa). Se não tem achado, imprime
`nenhum achado nessa coleta`.

## 5. Um exemplo completo, do começo ao fim

Cenário `correlation` do gerador. Os dados brutos (resumidos):

```
processes.csv:   2417, pai=1, root, "/bin/bash /opt/backup/backup.sh"
services.txt:    backup-agent.service  running  root  "/bin/bash /opt/backup/backup.sh"
permissions.csv: /opt/backup/backup.sh  dono=root  grupo=root  modo=0777
```

O que a ferramenta faz, passo a passo:

1. **Coleta** os três arquivos e converte pros formatos comuns.
2. **Regra 1** pega o serviço `backup-agent`. Ele roda como **root**? Sim, continua.
3. Procura o **processo** cujo comando é igual ao do serviço → acha o PID `2417`.
4. Quais **arquivos** esse processo usa? O executável é `bash` (um interpretador), então olha os
   argumentos também → `/bin/bash` e **`/opt/backup/backup.sh`**.
5. Qual a **permissão** do script? `0777`. O último dígito é `7` (inclui escrever) → **qualquer um
   pode alterar**.
6. Gera o achado **ALTA / confiança alta**, com os 4 campos preenchidos e a frase-chave na evidência
   ausente: *não temos prova de que alguém alterou*. **Isso não prova exploração.**

Agora a variação que prova que a ferramenta "pensa": se o mesmo script tivesse modo `0700`, o passo 5
daria "só o dono escreve" e **não haveria achado**, mesmo com o serviço rodando como root. É isso que o
enunciado chama de "serviço root não é automaticamente vulnerável".

## 6. Os 4 princípios que guiaram o projeto

1. **Nenhuma informação isolada vira achado.** Root sozinho, `0777` sozinho: nada. A combinação é o que importa.
2. **Permissões por contexto**, nunca varredura do disco inteiro.
3. **Evidência, interpretação, hipótese e evidência ausente separadas**, sempre.
4. **Severidade e confiança são coisas diferentes.**

## 7. Como a gente testou

- **32 testes automatizados** (`uv run pytest -q`). Eles rodam até no Mac porque, nos coletores reais,
  o `/proc` e o `systemctl` podem ser **trocados por versões falsas** nos testes. Assim testamos a
  lógica sem precisar de um Linux de verdade.
- **Os 6 cenários do gerador do professor:** `normal`, `permission`, `privileged_service`,
  `correlation`, `ambiguous` e `random`. Só o `correlation` (script `0777` + serviço root) gera achado
  alto; nos demais não aparece achado, ou aparece conforme o modo sorteado (no `random`). Rodamos
  também um lote de 20 datasets sem nenhum erro.
- **Dois bugs no gerador do professor** que corrigimos na nossa cópia (o enunciado permite adaptar):
  o cenário `random` quebrava ao ser sorteado, e o cenário `permission` aparecia com o nome
  `normal` no `metadata.json`.
- **Na VM Kali (sistema real)** descobrimos **três** coisas que os dados de teste não mostravam:
  1. Um serviço (`auditd`) dava erro no `systemctl cat` e **derrubava a coleta inteira**. Agora
     ele é pulado e a coleta continua.
  2. O `sudo` de verdade **faz um "fork"**: o processo que fica com o nome `sudo` continua como usuário
     comum (é o **pai**), e quem vira root é o **filho**, que já roda o comando final. Por isso a Regra 2
     passou a olhar o processo **e o pai**.
  3. O sistema real mostra `/usr/bin/bash` e não `/bin/bash`, então a lista de interpretadores por
     caminho exato não funcionava. Agora comparamos pelo **nome** (`bash`).
- **Regra 1 com dado real:** criamos na Kali um serviço de teste (`demo-backup.service`, root,
  script `0777`) e a ferramenta apontou `HIGH/high`. Tem o print no relatório.

A lição pra contar ao professor: *dados de teste dão a impressão de que está tudo certo; só rodar no
sistema real mostrou essas falhas.*

## 8. O que a ferramenta NÃO faz (limitações, sem enrolação)

Saber dizer isso bem **vale nota**: o enunciado quer que a gente reconheça os limites.

- **Só olha processos, permissões e serviços.** Não coleta **rede**, **logs**, hashes, usuários/grupos
  nem persistência. Só implementamos **2 das 4** correlações sugeridas.
- **Cenário `ambiguous` (conexão externa de um serviço root):** a ferramenta não gera achado, mas **não
  porque analisou e achou normal**. É porque ela **não coleta rede**. É um **ponto cego**, não uma conclusão.
- **UID real, não efetivo:** programas "setuid" (como o `passwd`) viram root só por dentro, e a
  ferramenta lê o dono "de fora". Esses **não são detectados** pela Regra 2.
- **Só o arquivo, não a pasta:** se o script é `0700` mas a **pasta** dele é gravável por todos, alguém
  poderia **trocar** o script. A ferramenta não checa a pasta.
- **Ligação serviço ↔ processo é por texto idêntico** (comando do serviço = comando do processo). Se
  o texto for diferente (variáveis, prefixos), não liga e **não gera achado** (um falso negativo silencioso).
- **Listas fixas:** interpretadores (`bash`, `sh`, `python`...) e ferramentas de elevação (`sudo`, `su`,
  `pkexec`). `doas`, `runuser`, `perl`, `ruby` escapam.
- **Falsos positivos possíveis:** a Regra 2 pode marcar uma elevação legítima feita por ferramenta fora
  da lista; a Regra 1 (grupo) pode marcar um arquivo gravável só por poucos usuários de confiança.
- **Não existe um achado "inconclusivo" explícito.** A incerteza aparece nos campos de confiança e de
  evidência ausente.
- **A foto não é instantânea:** ler o `/proc` leva um tempinho, processos podem aparecer ou sumir no meio.
- **Modo real:** só no Linux com systemd, e com root pra ver tudo. Validamos numa VM Kali.

**Falso positivo** = a ferramenta marca algo que **não** era problema. **Falso negativo** = deixa passar
algo que **era**.

## 9. Decisões do projeto e o porquê

| Decisão | Por quê |
|---|---|
| Python + `uv` | Simples e já era a linguagem do gerador do professor |
| Só 2 bibliotecas (`pydantic`, `rich`) | `pydantic` garante o formato dos dados, `rich` deixa o relatório legível |
| Ler `/proc` direto (sem `psutil`) | Mostra que entendemos o que é PID, PPID e UID, em vez de esconder isso numa biblioteca |
| Coletores com versão real **e** dataset | Mesma lógica na VM e em testes repetíveis |
| Permissões só por contexto | O enunciado pede, e o código **recusa** rodar sem a lista de arquivos |
| Severidade separada de confiança | Evita o veredito "vulnerável / não vulnerável", que o enunciado critica |
| Textos por modelo de frase, sem IA | Auditável: mesma entrada, mesma saída. O enunciado proíbe IA ser a **única** camada |
| Pular o que dá erro na coleta | Um serviço problemático não pode derrubar a investigação inteira |

## 10. Perguntas que o professor pode fazer (e respostas curtas)

1. **O que a ferramenta faz?** Tira uma foto sob demanda de um Linux, liga processos, permissões e
   serviços, e mostra achados separando evidência, interpretação, hipótese e o que falta provar.
2. **Por que serviço rodando como root não é um achado?** Porque root sozinho é normal. O risco está
   na **combinação**: root + script usado + script alterável por outros.
3. **Como vocês acham o script quando o serviço roda `bash script.sh`?** Quando o executável é um
   interpretador, olhamos também os argumentos e pegamos o caminho do script.
4. **Qual a diferença entre severidade e confiança?** Severidade: quão grave seria se for verdade.
   Confiança: quão certos estamos de que é verdade. Exemplo: arquivo gravável só pelo grupo é grave se
   explorado, mas não sabemos quem está no grupo, então a confiança é baixa.
5. **A ferramenta usa IA?** Não. Coleta, regras e textos são determinísticos. Mesma entrada, mesma saída.
6. **Quais correlações implementaram?** Duas: Processo+Serviço+Permissão e Processo+PPID+Usuário. Não
   fizemos Serviço+Arquivo+Usuário nem a que usa logs.
7. **Como funciona a Regra 2?** Procura processo root cujo pai é usuário comum. Se tem `sudo`/`su`/`pkexec`
   no processo ou no pai, é baixa/alta (esperado). Sem isso, é alta/baixa (incomum, motivo desconhecido).
8. **Por que o cenário `ambiguous` não gerou achado?** Ele é sobre conexão de rede e a gente não coleta
   rede. É um ponto cego declarado, não uma conclusão de que está tudo bem.
9. **Como testaram sem Linux?** O `/proc` e o `systemctl` são substituíveis nos coletores reais, então
   testamos o parsing com dados fabricados. Depois validamos na VM Kali de verdade.
10. **O que vocês descobriram na VM?** Três coisas: um serviço derrubando a coleta, o fork do `sudo`
    (pai e filho) e o caminho `/usr/bin/bash` diferente de `/bin/bash`.
11. **Quais as limitações?** Sem rede/logs, UID real em vez de efetivo (setuid passa), só o arquivo e não a
    pasta, ligação serviço-processo por texto idêntico, listas fixas.
12. **O que é falso positivo? Dê um exemplo do projeto.** Marcar algo que não era problema. Ex.: um
    `doas` legítimo aparecendo como "subida de privilégio sem ferramenta conhecida".
13. **Por que não usaram `psutil`?** Pra trabalhar direto com `/proc` e mostrar que entendemos PID, PPID e UID.
14. **Por que tem coletor "real" e "dataset"?** Pra rodar a mesma análise na VM e em testes repetíveis.
15. **Dá pra rodar em outro Linux?** Em qualquer Linux com systemd. Com `sudo` pra ver os processos de
    todos os usuários. Só validamos na Kali.

## 11. Mapa do código (pra abrir e mostrar)

| Arquivo | O que faz |
|---|---|
| `src/endpoint_investigator/cli.py` | Ponto de entrada. Sem argumento lê o sistema real, com uma pasta lê o dataset |
| `collectors/process_real.py`, `process_dataset.py` | Coletam processos (do `/proc` ou do CSV) |
| `collectors/permission_real.py`, `permission_dataset.py` | Coletam permissões (de `os.stat` ou do CSV) |
| `collectors/service_real.py`, `service_dataset.py` | Coletam serviços (do `systemctl` ou do `services.txt`) |
| `collectors/base.py` | As "regras do jogo" que toda versão (real e dataset) segue |
| `normalizer/models.py` | Os formatos comuns: `Process`, `FileResource`, `Service` |
| `normalizer/snapshot.py` | A classe `Snapshot` e o "truque do interpretador" (`resource_paths`) |
| `correlator/rules.py` | **As 2 regras.** É o coração do projeto |
| `evidence/models.py` | O `Finding`: os 4 campos + severidade + confiança |
| `reporter/console.py` | Desenha os painéis coloridos no terminal |
| `generate_dataset.py` | Gerador de dados de teste (do professor, com 2 correções nossas) |
| `tests/` | Os 32 testes |

**Se você só puder abrir 2 arquivos, abra `correlator/rules.py` e `normalizer/snapshot.py`.** Eles
contêm o raciocínio todo.

## 12. Sobre o uso de IA

- A **ferramenta** não usa IA. Isso é fato e pode ser afirmado com tranquilidade.
- O **desenvolvimento** usou IA como apoio, e isso está declarado no relatório. O enunciado permite.
- O que o professor vai avaliar na apresentação (domínio técnico) é se **vocês** entendem o que está
  no projeto. Por isso este resumo existe: leia, rode, abra o código e consiga explicar cada parte
  com as suas palavras. Se não souber algo, diga que não sabe e explique o que entende: é melhor do
  que inventar.
