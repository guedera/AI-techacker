# Endpoint Investigator

Ferramenta de investigação de segurança para endpoints GNU/Linux, desenvolvida para a Avaliação
Intermediária de **Tecnologias Hackers** (Insper, Prof. Rodolfo Avelino).

Ela tira um snapshot sob demanda do estado de uma máquina (processos, permissões e serviços),
**relaciona** essas evidências e entrega ao analista achados que separam o que foi **observado** do
que é **interpretação** e do que ainda é só **hipótese** — sem tratar nenhuma evidência isolada
(como "o serviço roda como root") como prova de incidente.

**Autores**

- Guilherme Galvão Guedes — guilhermegg5@al.insper.edu.br
- Luiz Miguel Moraes Berredo — luizmmb1@al.insper.edu.br

## Arquitetura (como funciona)

```
COLETA → NORMALIZAÇÃO → CORRELAÇÃO → EVIDÊNCIAS/HIPÓTESES → RESULTADO
```

| Etapa | Pasta | O que faz |
|---|---|---|
| Coleta | `collectors/` | Lê processos, permissões, serviços e logs, do sistema Linux real ou de um dataset sintético, atrás da mesma interface |
| Normalização | `normalizer/` | Modelos comuns (`Process`, `FileResource`, `Service`, `LogEvent`) e o `Snapshot`, que liga processo ↔ pai, serviço ↔ processo ↔ arquivo, arquivo ↔ permissão e serviço/processo ↔ logs |
| Correlação | `correlator/` | Regras que cruzam as fontes (inclusive os logs, para montar uma linha do tempo) e geram achados |
| Evidências/hipóteses | `evidence/` | Modelo `Finding`: evidência, interpretação, hipótese, evidência ausente, severidade e confiança |
| Resultado | `reporter/` | Relatório no terminal (`rich`), um painel por achado, colorido por severidade |

Mais detalhes de arquitetura e decisões em [ARCHITECTURE.md](organization/ARCHITECTURE.md).

## Dependências e requisitos

- **Python 3.12 ou superior** (`python3 --version` mostra qual você tem).
- **Dependências de execução**, listadas em `requirements.txt`: `pydantic` (modelos de dados) e `rich`
  (relatório colorido no terminal), mais as dependências delas. Para rodar os testes, `pytest`.
- O gerador de datasets (`generate_dataset.py`) usa só a biblioteca padrão do Python.
- O [uv](https://docs.astral.sh/uv/) é **opcional**: o projeto traz `pyproject.toml` e `uv.lock` para quem
  usa uv, mas tudo roda só com `pip` (Opção B abaixo).
- **Modo sistema real:** Linux com systemd (validado numa VM Kali). Para enxergar processos de
  outros usuários é preciso rodar com `sudo`.
- **Modo dataset:** roda em qualquer sistema (desenvolvido e testado em macOS e Linux).

## Instalação

Dentro da pasta do projeto, escolha uma das opções.

**Opção A: com uv**

```bash
uv sync
```

**Opção B: sem uv** (só Python 3.12+ e pip)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Execução

Os exemplos abaixo usam `uv`. Quem instalou pela Opção B (com o ambiente virtual ativado) usa os
comandos da coluna da direita. O `PYTHONPATH=src` é necessário porque o código fica na pasta `src/`.

| O que fazer | Com `uv` | Sem `uv` |
|---|---|---|
| Analisar um dataset | `uv run python -m endpoint_investigator.cli <pasta>` | `PYTHONPATH=src python -m endpoint_investigator.cli <pasta>` |
| Gerar um dataset | `uv run python generate_dataset.py ...` | `python generate_dataset.py ...` |
| Rodar os testes | `uv run pytest -q` | `pip install pytest` e depois `python -m pytest -q` |
| Analisar o sistema real (Linux) | `sudo $(which uv) run python -m endpoint_investigator.cli` | `sudo env PYTHONPATH=src .venv/bin/python -m endpoint_investigator.cli` |

### Sobre um dataset

```bash
uv run python -m endpoint_investigator.cli training/meu-dataset
```

A pasta precisa ter `processes.csv`, `permissions.csv` e `services.txt` (formato do
`generate_dataset.py`). O `journal.log`, se existir, também é lido; sem ele a análise roda igual,
só sem os logs.

### Gerando datasets de teste

```bash
uv run python generate_dataset.py --level challenge --output training/correlacao --seed 1
uv run python -m endpoint_investigator.cli training/correlacao
```

Combinações de `--level` e `--seed` já verificadas (com o `generate_dataset.py` deste repositório,
que tem duas correções em relação ao original, ver abaixo):

| `--level` | `--seed` | Cenário | Resultado esperado |
|---|---|---|---|
| `basic` | `1` | `normal` | nenhum achado |
| `intermediate` | `1` | `privileged_service` | nenhum achado (serviço root com script `0700`) |
| `intermediate` | `2` | `permission` | nenhum achado (arquivo `0777` que nenhum serviço usa) |
| `challenge` | `1` | `correlation` | 1 achado `HIGH` / confiança `high` |
| `challenge` | `7` | `ambiguous` | nenhum achado (ver limitações) |

### Sobre o sistema real (Linux)

```bash
sudo $(which uv) run python -m endpoint_investigator.cli
```

Sem argumento, a ferramenta coleta o sistema onde está rodando. O `$(which uv)` é necessário porque
o `sudo` usa um `PATH` próprio e não encontra o `uv` instalado na home do usuário.

### Testes

```bash
uv run pytest -q
```

São 47 testes e eles rodam sem Linux: o `/proc`, o `systemctl` e o `journalctl` são injetáveis nos collectors reais,
então o parsing é testado com dados fabricados.

## Fontes de informação

| Dimensão | Modo sistema real | Modo dataset |
|---|---|---|
| Processos | `/proc/<pid>/status`, `stat`, `cmdline` e `exe` (PID, PPID, UID/GID, usuário, estado, comando, executável) | `processes.csv` |
| Permissões | `os.stat()` apenas nos caminhos relevantes (dono, grupo, modo, mtime) | `permissions.csv` |
| Serviços | `systemctl list-units`, `show` e `cat` (nome, estado, usuário, `ExecStart`) | `services.txt` |
| Logs | `journalctl -b -o short-iso` (últimos 20000 eventos do boot atual: horário, programa, PID, mensagem) | `journal.log` |

As permissões nunca vêm de uma varredura do filesystem: só são lidas para os arquivos que aparecem
nos processos e serviços coletados (o executável e, quando o executável é um interpretador como
`bash`, `sh` ou `python`, o script passado como argumento). O collector real recusa ser chamado sem
a lista de caminhos. Os logs só reforçam a evidência: se não houver `journalctl`, a coleta segue sem eles.

## Correlações implementadas

### 1. Processo + Serviço + Permissão → hipótese de risco

Regra `servico_privilegiado_arquivo_gravavel`. Para cada serviço que roda como root, encontra o
processo correspondente, os arquivos que ele usa e a permissão de cada um.

| Condição | Severidade | Confiança |
|---|---|---|
| Arquivo gravável por qualquer usuário (*world-writable*) | `high` | `high` |
| Gravável só pelo grupo dono | `medium` | `low` (não sabemos quem está no grupo) |
| Restrito ao dono | sem achado | — |

**Linha do tempo com logs:** a evidência cruza a data de modificação do arquivo (`mtime`) com os logs do
serviço (achados pelo nome da unit, pelo programa ou pelo PID) e diz se o serviço teve atividade depois
da última alteração. Isso muda o texto da evidência e da evidência ausente, não a gravidade.

### 2. Processo + PPID + Usuário → contexto de execução

Regra `processo_root_com_pai_nao_privilegiado`. Aponta processos root cujo pai roda como usuário comum.

| Condição | Severidade | Confiança |
|---|---|---|
| `sudo`, `su` ou `pkexec` no processo ou no pai | `low` | `high` (caminho esperado) |
| Sem mecanismo de elevação conhecido | `high` | `low` (sabemos que aconteceu, não o motivo) |

A queda normal de privilégio (por exemplo `sshd` root abrindo o shell de um usuário) não gera achado.

**Logs na evidência:** o achado anexa até 3 logs do processo e do pai (por exemplo o registro do `sudo`
no journal), o que ajuda a confirmar a elevação sem prová-la.

## Formato dos achados

Todo achado traz quatro campos separados, mais severidade e confiança (que são independentes:
severidade é quão grave seria se a hipótese fosse verdadeira, confiança é quão certos estamos de que
ela é). Saída resumida do cenário `correlation`:

```
HIGH servico_privilegiado_arquivo_gravavel (confianca: high)
  evidencia: Servico backup-agent.service roda como root e executa /opt/backup/backup.sh,
             que tem permissao 0777 (dono root:root). Logs do servico: 4 registro(s), o
             ultimo em 14/09/2026 09:02:05 (backup-agent: backup completed with status=OK).
             O arquivo foi modificado pela ultima vez em 13/09/2026 08:59:00, antes desse
             ultimo registro: o servico teve atividade depois da alteracao.
  interpretacao: O arquivo usado pelo servico privilegiado pode ser alterado por qualquer
                 usuario do sistema.
  hipotese: Se algum desses usuarios alterar o arquivo, o conteudo passa a rodar com
            privilegio de root na proxima vez que o servico executar.
  evidencia ausente: Os logs mostram atividade do servico depois da ultima alteracao, mas
                     nao mostram quem alterou o arquivo nem o que mudou. Precisaria de
                     auditoria de escrita (ex: auditd), historico de hash, ou a lista de
                     membros do grupo root pra saber quem realmente tem acesso.
```

Os textos são gerados por templates determinísticos nas regras (`correlator/rules.py`): a evidência
é montada com os dados da coleta e o restante é texto fixo por regra. **A ferramenta não usa nenhum
modelo de linguagem.**

## Estrutura do projeto

```
src/endpoint_investigator/
  cli.py                  # ponto de entrada (modo dataset e modo sistema real)
  collectors/
    base.py               # interfaces dos collectors
    process_real.py       # /proc
    process_dataset.py    # processes.csv
    permission_real.py    # os.stat
    permission_dataset.py # permissions.csv
    service_real.py       # systemctl
    service_dataset.py    # services.txt
    log_real.py           # journalctl
    log_dataset.py        # journal.log
    log_line.py           # parsing de linha de log (usado pelos dois)
  normalizer/
    models.py             # Process, FileResource, Service, LogEvent
    snapshot.py           # relações entre as entidades
  correlator/rules.py     # regras de correlação
  evidence/models.py      # Finding
  reporter/console.py     # saída no terminal
tests/                    # 47 testes automatizados
generate_dataset.py       # gerador de datasets (fornecido, com duas correções)
training/                 # datasets gerados localmente (ignorado pelo git)
```

## Uso de IA no aplicativo

O aplicativo **não tem IA integrada**. Nenhuma etapa usa modelo de linguagem: a coleta, a normalização,
a correlação e a geração dos textos dos achados são determinísticas (regras em Python e modelos de frase
fixos em `correlator/rules.py`). Não há chave de API nem chamada de rede, as únicas dependências de
execução são `pydantic` e `rich`, e a mesma entrada gera sempre a mesma saída.

## Limitações

Resumo; a lista completa está no [relatorio_final.md](relatorio_final.md).

- Cobre processos, permissões, serviços e logs. Sem conexões de rede, hashes, usuários/grupos ou
  persistência, e só 2 regras de correlação (o cruzamento com logs entra como reforço de evidência
  dentro delas, não como regra própria).
- Os logs mostram quando o serviço rodou, **não quem editou o arquivo**: eventos de edição só existiriam
  com auditoria de escrita (`auditd`), que não coletamos. O `journal.log` do gerador também não os tem.
- No cenário `ambiguous` (conexão externa feita por serviço root) a ferramenta não gera achado, mas
  **porque não coleta rede**, não porque analisou a conexão: é um ponto cego, não uma conclusão.
- Usa o UID real do processo; binários setuid (que mudam só o UID efetivo) não são detectados.
- Verifica a permissão do script, não a do diretório que o contém.
- Associa serviço a processo por igualdade exata entre `ExecStart` e a linha de comando; quando não
  casa, o serviço fica sem achados (falso negativo silencioso).
- Listas fixas de interpretadores (`bash`, `sh`, `python`) e de ferramentas de elevação (`sudo`,
  `su`, `pkexec`).
- Não existe um achado explícito de "inconclusivo": a incerteza aparece nos campos de confiança e de
  evidência ausente dos achados que existem.
- Modo real validado apenas numa VM Kali.

## Sobre o `generate_dataset.py`

O enunciado permite adaptar o script fornecido. Corrigimos dois bugs nele:

1. O cenário `random_noise` quebrava sempre que era sorteado (`intermediate` e `challenge`).
2. O cenário `scenario_permission` aparecia rotulado como `normal` no `metadata.json`.

## Mais documentação

- [relatorio_final.md](relatorio_final.md): documento técnico (problema, estratégia, arquitetura, correlações, decisões técnicas, validação, limitações).
- [ARCHITECTURE.md](organization/ARCHITECTURE.md): camadas, escopo e decisões de arquitetura.
