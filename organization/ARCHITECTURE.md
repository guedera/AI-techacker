# Endpoint Investigator — Arquitetura

## Stack

- Python 3.12, gerenciado via `uv` (`pyproject.toml` + `uv.lock`).
- Dependências: `pydantic` (modelos), `rich` (relatório); `pytest` só em desenvolvimento.
- Sem framework web: execução via CLI, sob demanda (snapshot), conforme o enunciado.

## Camadas

Espelham o fluxo de referência do enunciado:

```
COLETA → NORMALIZAÇÃO → CORRELAÇÃO → EVIDÊNCIAS/HIPÓTESES → RESULTADO
```

```
src/endpoint_investigator/
  collectors/    # lê processos, permissões e serviços: sistema real OU dataset sintético
  normalizer/    # modelos comuns (Process, FileResource, Service) e o Snapshot (relações)
  correlator/    # regras que cruzam processos + permissões + serviços e geram Findings
  evidence/      # modelo Finding: evidência / interpretação / hipótese / evidência ausente
  reporter/      # saída no terminal (rich)
  cli.py         # ponto de entrada
```

- `tests/`: 47 testes unitários por camada.
- `training/`: datasets sintéticos gerados localmente (ignorado pelo git; reprodutíveis via `--seed`).

## Fonte de dados intercambiável

Cada dimensão tem uma interface (`ProcessCollector.collect()`, `PermissionCollector.collect(paths)`,
`ServiceCollector.collect()`, `LogCollector.collect()`) com duas implementações, que já devolvem os modelos comuns:

- **Real**: `/proc/<pid>/{status,stat,cmdline,exe}`, `os.stat()`, `systemctl list-units/show/cat` e `journalctl`.
- **Dataset**: `processes.csv`, `permissions.csv`, `services.txt` e `journal.log` do `generate_dataset.py`.

A mesma investigação roda na VM Kali e sobre datasets reprodutíveis
(`basic`/`intermediate`/`challenge`). A fonte real tem pontos de injeção (`proc_root` no
`ProcCollector`, `runner` no `SystemdCollector` e no `JournalCollector`) para testar o parsing sem Linux.

## Escopo (v1)

**Implementado**
- Processos: PID, PPID, usuário, UID/GID, estado, comando, argumentos, executável.
- Permissões, orientadas por contexto: só dos caminhos que aparecem em processos e serviços
  (executável e, quando o executável é um interpretador, o script nos argumentos). O collector real
  levanta `ValueError` se chamado sem a lista de caminhos.
- Serviços: nome, estado, usuário e `ExecStart`.
- Logs: horário, programa, PID e mensagem (journal do boot atual). Servem de reforço: se o
  `journalctl` não existir ou falhar, a coleta segue sem eles.

**Fora do escopo (decisão consciente, entra como limitação no documento técnico)**
- Conexões de rede, usuários e grupos, hashes de arquivos, persistência e auditoria de escrita
  (`auditd`): por isso os logs mostram quando o serviço rodou, mas não quem editou o arquivo.

## Correlações

Implementadas (mínimo exigido: 2):

1. **Processo + Serviço + Permissão → hipótese de risco** (`servico_privilegiado_arquivo_gravavel`):
   serviço root que executa arquivo gravável por outros usuários.
2. **Processo + PPID + Usuário → contexto de execução** (`processo_root_com_pai_nao_privilegiado`):
   processo root cujo pai roda como usuário comum.

Os logs entram como reforço de evidência dentro dessas duas regras: na 1, cruzam o `mtime` do arquivo
com os logs do serviço (linha do tempo); na 2, anexam os logs do processo e do pai (ex.: registro do
`sudo`). Não implementada: Serviço + Arquivo + Usuário (relação de privilégio).

## Regra de saída

Todo achado (`Finding`) carrega `evidence` (dado observado), `interpretation` (significado
técnico), `hypothesis` (explicação possível) e `missing_evidence` (o que falta para confirmar ou
rejeitar), mais `severity` e `confidence`, que são eixos independentes: severidade é quão grave
seria se a hipótese for verdadeira, confiança é quão certos estamos de que ela é. Nunca um veredito
binário "vulnerável"/"não vulnerável".

Os textos são templates determinísticos nas regras: a evidência é montada com os dados da coleta e
interpretação, hipótese e evidência ausente são texto fixo por regra (com poucas variáveis).

## Decisões técnicas relevantes

- `/proc` lido direto (stdlib), sem `psutil`, para trabalhar os conceitos de processo em vez de
  delegá-los a uma biblioteca.
- `resource_paths()` trata interpretadores (`bash`, `sh`, `python`): o recurso relevante é o script
  passado como argumento, não o interpretador.
- A regra de elevação de privilégio olha o processo **e** o pai, porque o `sudo` real faz fork (descoberto
  na validação na VM Kali).
- Processos que somem durante a coleta e units que o `systemctl` não detalha são ignorados, sem
  derrubar a coleta.

## IA

A solução não usa modelo de linguagem em nenhuma etapa. Decisão do grupo: não incluir uma camada de
IA nesta versão. Se entrar no futuro, só poderá entrar depois da correlação, explicando achados já
estruturados, nunca recebendo dados brutos para "analisar a máquina".
