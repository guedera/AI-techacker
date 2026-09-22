# Endpoint Investigator — Plano de Sprints

Baseado no enunciado "Avaliação Intermediária — Endpoint Investigator" (Prof. Rodolfo Avelino, Tecnologias Hackers).
**Prazo final: apresentação em aula em 06/10.** Hoje: 22/09 → ~2 semanas de execução.

## Ideia geral

Construir uma ferramenta que faz um **snapshot sob demanda** de um endpoint Linux e conduz uma
investigação de segurança seguindo o fluxo:

```
COLETA → NORMALIZAÇÃO → CORRELAÇÃO → EVIDÊNCIAS → HIPÓTESES → RESULTADO DA INVESTIGAÇÃO
```

Regras de ouro que guiam todas as sprints:
- As **3 dimensões obrigatórias** são processos, permissões e serviços. Tudo mais (logs, rede,
  usuários/grupos, arquivos abertos, systemd, hashes, persistência) é opcional e deve se conectar
  claramente à estratégia de investigação — não é feature por feature.
- Nunca tratar as 3 fontes como listas independentes: o valor está nas **relações**
  (processo ↔ identidade ↔ PPID ↔ arquivo ↔ serviço).
- Toda saída da ferramenta deve rotular claramente **Evidência / Interpretação / Hipótese /
  Evidência ausente** — isso é critério de nota explícito (1,5 pt).
- Nome de processo isolado não é achado. "Serviço roda como root" isolado não é achado. O que
  importa é a combinação (identidade privilegiada + recurso + capacidade de modificação).
- Se usar LLM, ele entra **depois** da coleta/correlação estruturada, nunca como única camada
  (`dados → LLM → "analise isso"` é explicitamente proibido pelo enunciado).

---

## Sprint 0 — Definição de escopo e arquitetura (dia 1–2)

**Objetivo:** alinhar o grupo antes de escrever código de investigação.

- [ ] Definir stack (linguagem/framework) — enunciado é livre, mas priorizar algo com boas libs
  para parsing de `/proc`, CSV e regex (Python é natural aqui, dado o `generate_dataset.py`).
- [ ] Desenhar a arquitetura em camadas, espelhando o fluxo de referência:
  1. **Collectors** (um por fonte: processos, permissões, serviços, +opcionais)
  2. **Normalizer** (converte saída bruta de cada collector em um modelo de dados comum)
  3. **Correlator** (regras que cruzam dados normalizados de fontes diferentes)
  4. **Evidence/Hypothesis engine** (classifica achados em Evidência/Interpretação/Hipótese/Ausente)
  5. **Reporter** (gera saída legível — texto/JSON/HTML — para o analista)
- [ ] Decidir se a ferramenta lê **sistema real** (via `/proc`, `systemctl`, `ps`) e/ou os
  **datasets sintéticos** (CSV/txt/log gerados pelo `generate_dataset.py`) como fonte intercambiável.
  Recomendado: abstrair a fonte de dados (real vs. dataset) por trás da mesma interface de collector,
  assim a demo pode rodar tanto na VM Kali quanto sobre datasets reproduzíveis.
- [ ] Escolher e documentar o **escopo explícito**: quais tipos de achado a ferramenta cobre e quais
  ficam fora (necessário para a seção de limitações do documento técnico).
- [ ] Rodar `generate_dataset.py` para os 3 níveis e inspecionar os artefatos gerados, para entender
  o formato exato de `processes.csv`, `permissions.csv`, `services.txt`, `journal.log`.

**Entrega da sprint:** documento curto (pode ser um `ARCHITECTURE.md`) com diagrama de camadas,
escopo e decisões técnicas.

---

## Sprint 1 — Coleta (Collectors) (dia 3–5)

**Objetivo:** implementar a camada de coleta para as 3 dimensões obrigatórias.

- [ ] **Processos**: coletar PID, PPID, usuário, UID/GID, comando, argumentos, executável, estado
  (via `/proc/<pid>/*` no sistema real, ou parsing de `processes.csv` no modo dataset).
- [ ] **Permissões**: coletar owner, group, modo, mtime de arquivos/diretórios — mas de forma
  **orientada por contexto** (arquivos referenciados por processos/serviços coletados), não varredura
  cega do filesystem.
- [ ] **Serviços**: coletar nome, estado, usuário, grupo, comando de inicialização, executável,
  scripts, processos associados (via `systemctl`/`service` no real, ou `services.txt` no dataset).
- [ ] Implementar a mesma interface de collector para os dois modos (sistema real / dataset) desde
  o início, para não precisar retrabalhar depois.
- [ ] Testes unitários simples de parsing usando os datasets `basic` já gerados.

**Entrega da sprint:** collectors funcionando isoladamente, com output bruto por dimensão.

---

## Sprint 2 — Normalização (dia 5–6)

**Objetivo:** unificar os dados brutos das 3(+) fontes em um modelo comum que permita relacionar
entidades por chave (PID, path, nome de serviço, usuário).

- [ ] Definir modelos de dados (ex: `Process`, `FileResource`, `Service`, `LogEvent`) com campos
  padronizados e IDs cruzáveis entre si (ex: `Service.pid` aponta para `Process.pid`;
  `Process.executable_path` aponta para `FileResource.path`).
- [ ] Construir os grafos/índices de relação: processo→pai, processo→serviço, serviço→arquivo,
  arquivo→permissão.
- [ ] Validar contra os 3 datasets de exemplo (`scenario_normal`, `scenario_permission`,
  `scenario_privileged_service` do gerador) que as relações são montadas corretamente.

**Entrega da sprint:** camada de normalização testada, pronta para alimentar as regras de correlação.

---

## Sprint 3 — Correlação (dia 7–9)

**Objetivo:** implementar **no mínimo 2 tipos de correlação** exigidos (idealmente as 4 sugeridas
pelo enunciado, para maximizar os 2,0 pontos do critério de correlação).

- [ ] Regra 1: **Processo + Serviço + Permissão → hipótese de risco**
  (ex: serviço root usa script que é world-writable ou alterável por usuário não privilegiado).
- [ ] Regra 2: **Processo + PPID + Usuário → contexto de execução**
  (reconstruir árvore de processos e destacar mudanças de usuário/privilégio na cadeia pai→filho).
- [ ] Regra 3 (opcional, soma pontos): **Serviço + Arquivo + Usuário → relação de privilégio**
  (proprietário do recurso vs. usuário que o serviço usa para executar).
- [ ] Regra 4 (opcional): **Processo + Serviço + Log → reconstrução temporal**
  (cruzar timestamps de journal.log com start dos processos/serviços para contar uma linha do tempo).
- [ ] Cada regra deve gerar um "achado candidato" com metadados: quais evidências entraram na
  correlação, não apenas um veredito binário.
- [ ] Testar cada regra contra os cenários do gerador desenhados para acioná-la
  (`scenario_correlation` é o mais direto para a Regra 1; `scenario_ambiguous` testa falso-positivo).

**Entrega da sprint:** motor de correlação com as regras implementadas e testadas contra os datasets.

---

## Sprint 4 — Evidências, Interpretação e Hipóteses (dia 9–11)

**Objetivo:** transformar achados candidatos da correlação em relatórios que respeitam a
distinção exigida pelo enunciado.

- [ ] Para cada achado, estruturar explicitamente 4 campos:
  - **Evidência**: o que foi observado (dados brutos/normalizados que sustentam o achado).
  - **Interpretação**: o significado técnico atribuído (ex: "script alterável por não-root usado
    por serviço root").
  - **Hipótese**: explicação possível para a relação (ex: "possível vetor de escalonamento de
    privilégio, se o script for de fato modificado por esse usuário").
  - **Evidência ausente**: o que seria necessário coletar para confirmar/rejeitar a hipótese (ex:
    "não há confirmação de que o script foi executado após alteração; logs de auditoria de escrita
    ajudariam").
- [ ] Implementar um mecanismo de **severidade/confiança** (não binário sim/não vulnerável) — reflete
  a orientação do enunciado de evitar regras simplistas ("serviço root = vulnerável").
- [ ] Garantir que a ferramenta **explique explicitamente casos inconclusivos** em vez de forçar uma
  conclusão (isso é citado como qualidade esperada da ferramenta).

**Entrega da sprint:** camada de reporting estruturado (JSON interno) pronta para virar saída final.

---

## Sprint 5 — Saída/Relatório e camada de IA opcional (dia 11–13)

**Objetivo:** apresentar o resultado da investigação de forma legível, e (se o grupo optar) usar
LLM apenas como camada de explicação **sobre** as evidências já estruturadas.

- [ ] Construir o formato de saída final (CLI colorida, Markdown, HTML ou JSON — a critério do
  grupo) com seções: Resumo executivo → Achados por correlação → Evidência/Interpretação/Hipótese/
  Ausente → Processos/Permissões/Serviços brutos (apêndice).
- [ ] Se for usar LLM: alimentar o modelo com as evidências e correlações **já calculadas**
  (nunca dados brutos "analise isso"), pedindo apenas explicação em linguagem natural ou geração de
  hipóteses adicionais — sempre marcado como camada de interpretação, não de coleta.
- [ ] Deixar claro no output o que veio do motor determinístico vs. o que veio da camada de IA
  (rastreabilidade — importante para a defesa em banca).

**Entrega da sprint:** ferramenta ponta a ponta funcionando: input (real ou dataset) → relatório final.

---

## Sprint 6 — Testes e validação (dia 13–15)

**Objetivo:** validar a ferramenta contra cenários variados, incluindo os mais ambíguos.

- [ ] Gerar datasets nos 3 níveis (`basic`, `intermediate`, `challenge`) incluindo `--batch` para
  múltiplos cenários e `--seed` para reprodutibilidade.
- [ ] Rodar a ferramenta contra todos os cenários do gerador (`scenario_normal`, `scenario_permission`,
  `scenario_privileged_service`, `scenario_correlation`, `scenario_ambiguous`, `random_noise`) e
  confirmar que:
  - cenários normais não geram falso-positivo de alta severidade;
  - `scenario_correlation` (script world-writable + serviço root) é capturado;
  - `scenario_ambiguous` (conexão externa de serviço root) não é classificado como malware sem
    contexto adicional — deve aparecer como hipótese fraca / evidência insuficiente.
- [ ] Opcional: usar a VM Kali para criar 1–2 situações controladas reais (não apenas dataset) e
  validar a coleta no sistema de verdade — reforça a nota de "domínio técnico" na demo.
- [ ] Registrar quais situações geram falsos positivos conhecidos — vai direto para a seção de
  limitações do documento técnico.

**Entrega da sprint:** bateria de testes documentada, com resultado esperado vs. obtido por cenário.

---

## Sprint 7 — Documentação (dia 15–17)

**Objetivo:** produzir os entregáveis escritos exigidos.

- [ ] **README.md**: arquitetura, dependências, instalação, execução, fontes de informação usadas,
  correlações implementadas, limitações conhecidas.
- [ ] **Documento técnico (máx. 4 páginas)**: problema, estratégia de investigação, arquitetura,
  principais correlações, decisões técnicas, uso de IA (se aplicável), limitações. Manter dentro do
  limite de páginas — ser direto.
- [ ] Revisar se a seção de limitações é honesta: onde a ferramenta pode gerar falso positivo,
  interpretação incompleta ou resultado inconclusivo (isso é valorizado, não penalizado).

**Entrega da sprint:** README.md e documento técnico finalizados.

---

## Sprint 8 — Ensaio da demonstração (dia 17–19, antes do 06/10)

**Objetivo:** preparar a apresentação em aula.

- [ ] Roteirizar a demo: rodar a ferramenta em tempo real (sistema real ou dataset) mostrando o fluxo
  completo COLETA → ... → RESULTADO.
- [ ] Escolher 1 cenário "limpo" (sem achados) e 1–2 cenários "com achado" para mostrar contraste.
  Incluir o cenário ambíguo para demonstrar que a ferramenta reconhece incerteza (isso pontua:
  "capacidade de observar, relacionar, formular hipóteses e justificar conclusões" é o critério
  central da avaliação, não quantidade de vulnerabilidades encontradas).
- [ ] Todos os membros do grupo devem saber explicar qualquer parte do código/arquitetura
  ("domínio técnico do grupo" vale 0,5 pt e pode ser perguntado a qualquer integrante).
- [ ] Ensaiar o tempo da apresentação e testar em máquina limpa (sem dependências pré-instaladas
  do ambiente de dev) para garantir que a demo não falha por ambiente.

**Entrega da sprint:** apresentação pronta, testada, com roteiro e fallback caso algo falhe ao vivo.

---

## Mapeamento com os critérios de avaliação (10,0 pts)

| Critério | Pontos | Sprint(s) responsável(is) |
|---|---|---|
| Funcionamento da solução | 3,0 | 1–6 |
| Aplicação de processos, permissões e serviços | 2,0 | 1–2 |
| Correlação entre evidências | 2,0 | 3 |
| Evidência vs. interpretação vs. hipótese | 1,5 | 4 |
| Arquitetura, código e documentação | 1,0 | 0, 7 |
| Demonstração e domínio técnico | 0,5 | 8 |
