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

- `tests/`: 29 testes unitários por camada.
- `training/`: datasets sintéticos gerados localmente (ignorado pelo git; reprodutíveis via `--seed`).

## Fonte de dados intercambiável

Cada dimensão tem uma interface (`ProcessCollector.collect()`, `PermissionCollector.collect(paths)`,
`ServiceCollector.collect()`) com duas implementações, que já devolvem os modelos comuns:

- **Real**: `/proc/<pid>/{status,stat,cmdline,exe}`, `os.stat()` e `systemctl list-units/show/cat`.
- **Dataset**: `processes.csv`, `permissions.csv` e `services.txt` do `generate_dataset.py`.

A mesma investigação roda na VM Kali e sobre datasets reprodutíveis
(`basic`/`intermediate`/`challenge`). A fonte real tem pontos de injeção (`proc_root` no
`ProcCollector`, `runner` no `SystemdCollector`) para testar o parsing sem Linux.

## Escopo (v1)

**Implementado**
- Processos: PID, PPID, usuário, UID/GID, estado, comando, argumentos, executável.
- Permissões, orientadas por contexto: só dos caminhos que aparecem em processos e serviços
  (executável e, quando o executável é um interpretador, o script nos argumentos). O collector real
  levanta `ValueError` se chamado sem a lista de caminhos.
- Serviços: nome, estado, usuário e `ExecStart`.

**Fora do escopo (decisão consciente, entra como limitação no documento técnico)**
- Logs/journal, conexões de rede, usuários e grupos, hashes de arquivos, persistência.

## Correlações

Implementadas (mínimo exigido: 2):

1. **Processo + Serviço + Permissão → hipótese de risco** (`servico_privilegiado_arquivo_gravavel`):
   serviço root que executa arquivo gravável por outros usuários.
2. **Processo + PPID + Usuário → contexto de execução** (`processo_root_com_pai_nao_privilegiado`):
   processo root cujo pai roda como usuário comum.

Não implementadas: Serviço + Arquivo + Usuário (relação de privilégio) e Processo + Serviço + Log
(reconstrução temporal, exigiria um collector de logs).

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
