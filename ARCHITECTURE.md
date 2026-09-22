# Endpoint Investigator — Arquitetura (Sprint 0)

## Stack

- Python 3.12, gerenciado via `uv` (`pyproject.toml` + `uv.lock`).
- Sem framework web — execução via CLI, sob demanda (snapshot), conforme enunciado.

## Camadas

Espelham o fluxo de referência do enunciado:

```
COLETA → NORMALIZAÇÃO → CORRELAÇÃO → EVIDÊNCIAS/HIPÓTESES → RESULTADO
```

```
src/endpoint_investigator/
  collectors/    # le dados brutos: sistema real (/proc, systemctl) OU dataset sintetico
  normalizer/    # converte saida bruta de cada collector em modelos de dados comuns
  correlator/    # regras que cruzam processos + permissoes + servicos (+ opcionais)
  evidence/      # classifica achados em Evidencia / Interpretacao / Hipotese / Ausente
  reporter/      # gera a saida final para o analista (texto/JSON/HTML)
```

- `tests/` — testes unitários por camada, validados contra os datasets do `generate_dataset.py`.
- `training/` — datasets sintéticos gerados localmente (gitignored; reprodutíveis via `--seed`).

## Decisão: fonte de dados intercambiável

Os collectors implementam uma interface comum (`collect() -> RawX`) com duas implementações:

- **Real**: lê `/proc/<pid>/*`, `systemctl show`, `stat` no sistema real (Linux/VM Kali).
- **Dataset**: faz parsing de `processes.csv`, `permissions.csv`, `services.txt`, `journal.log`
  gerados pelo `generate_dataset.py`.

Isso permite rodar a mesma investigação tanto na demo com a VM Kali quanto sobre datasets
reprodutíveis (`basic`/`intermediate`/`challenge`) para desenvolvimento e testes.

## Escopo adotado (v1)

**Obrigatório (sempre implementado):**
- Processos (PID, PPID, usuário, UID/GID, comando, executável, estado).
- Permissões de arquivos/diretórios referenciados por processos e serviços coletados
  (não é varredura cega do filesystem — é orientada por contexto).
- Serviços (nome, estado, usuário, grupo, executável, scripts, processos associados).

**Opcional, incorporado quando houver tempo (nesta ordem de prioridade):**
1. Logs (`journal.log`) — usados na correlação temporal (Processo + Serviço + Log).
2. Conexões de rede — reforça o cenário `scenario_ambiguous` (conexão externa de serviço root).
3. Usuários e grupos, hashes de arquivos, mecanismos de persistência — ficam fora do escopo v1;
   citados como limitação conhecida no documento técnico caso não sejam implementados.

## Correlações planejadas (mínimo 2 exigidas)

1. Processo + Serviço + Permissão → hipótese de risco.
2. Processo + PPID + Usuário → contexto de execução.
3. (Se houver tempo) Serviço + Arquivo + Usuário → relação de privilégio.
4. (Se houver tempo) Processo + Serviço + Log → reconstrução temporal.

## Regra de saída

Todo achado gerado pelo `correlator` deve carregar explicitamente:
`evidencia` (dado observado) / `interpretacao` (significado técnico) / `hipotese` (explicação
possível) / `evidencia_ausente` (o que falta para confirmar/rejeitar) — nunca um veredito binário
tipo "vulnerável"/"não vulnerável".

## IA (uso futuro, Sprint 5)

Se incorporada, a IA entra **depois** do `correlator`/`evidence`, apenas como camada de explicação
em linguagem natural sobre achados já estruturados — nunca recebe dados brutos para "analisar
a máquina" diretamente.
