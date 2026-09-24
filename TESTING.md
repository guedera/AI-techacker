# Validação — Sprint 6

## Bugs encontrados no `generate_dataset.py` (script do professor)

O enunciado permite adaptar o script fornecido. Encontramos e corrigimos dois bugs nele
durante a validação — sem eles, boa parte dos cenários nunca conseguia ser testada:

1. **`random_noise` quebrava sempre que era sorteado** (níveis `intermediate`/`challenge`).
   A função reaproveitava `scenario_normal(start)["processes"]`/`["permissions"]` (já convertidos
   em dict pelo `build()`) como se fossem as tuplas cruas de entrada, empilhava uma tupla nova em
   cima e mandava tudo de novo pro `build()`, que quebrava tentando desempacotar um dict de 6
   chaves como tupla de 5 (`ValueError: too many values to unpack`).
2. **`scenario_permission` sempre aparecia como `"normal"` no `metadata.json`.** A função reusa o
   dict pronto de `scenario_normal(start)` (que já tem `kind="normal"`) e nunca atualiza esse campo
   depois de adicionar as permissões extras. O dataset gerado está correto, só o rótulo em
   `metadata.json`/`data["kind"]` estava errado — o que faz parecer que o cenário nunca é sorteado.

Ambos corrigidos localmente em `generate_dataset.py` (ver comentários no código nos pontos alterados).

## Validação contra os 6 cenários nomeados do gerador

Um dataset de cada cenário, gerado após as correções acima:

| Cenário | Esperado | Observado | Resultado |
|---|---|---|---|
| `normal` | nenhum achado | nenhum achado | ✅ |
| `permission` (arquivo `0777` sem ligação a serviço) | nenhum achado — a regra só olha arquivos usados por serviços root | nenhum achado | ✅ |
| `privileged_service` (script restrito, `0700`) | nenhum achado — evita a regra simplista "serviço root = vulnerável" | nenhum achado | ✅ |
| `correlation` (script `0777` usado por serviço root) | achado `HIGH`/confiança `high` | achado `HIGH`/confiança `high` (`servico_privilegiado_arquivo_gravavel`) | ✅ |
| `ambiguous` (conexão externa de serviço root) | nenhum achado de "malware" sem mais contexto | nenhum achado | ✅ (ver limitação abaixo) |
| `random` (modo sorteado entre `0700/0750/0770/0777`) | reagir de acordo com o modo sorteado | ver teste em lote abaixo | ✅ |

## Teste em lote (robustez + reprodutibilidade)

```bash
uv run python generate_dataset.py --batch 20 --level challenge --output training/sprint6/batch --seed 1000
```

20 datasets gerados (`correlation`, `ambiguous`, `random` misturados), todos processados sem
crash. Resultado:

- Todo `correlation` (5/5): achado `HIGH` consistente.
- Todo `ambiguous` (10/10): nenhum achado — nunca um falso positivo.
- `random` (5/5): variou entre nenhum achado, `HIGH` e `MEDIUM`, sempre batendo com o modo real
  gravado em `permissions.csv` daquela rodada (`0777`→`HIGH`, `0700`→nada, `0770`→`MEDIUM`).

## Limitação conhecida (vai para o documento técnico)

O cenário `ambiguous` do gerador é sobre uma **conexão de rede externa** feita por um serviço
root — mas não implementamos um collector de conexões de rede na v1 (decisão de escopo, ver
`ARCHITECTURE.md`). Isso significa que a ferramenta não está "acertando por análise" esse
cenário — ela simplesmente não tem como comentar sobre esse aspecto, porque não coleta esse
dado. O resultado (nenhum achado) é o comportamento correto dado o escopo atual, mas é
diferente de "a ferramenta investigou a conexão e concluiu que não é suspeita". Vale deixar
isso explícito na seção de limitações.

## Pendente (fora do que dá pra rodar no Mac)

Os collectors do "sistema real" (`ProcCollector`, `SystemdCollector`) só foram validados até
aqui contra dados fabricados nos testes automatizados (fixtures fake de `/proc`, runner
injetado no lugar do `systemctl`) — nunca contra um Linux de verdade, porque o
desenvolvimento é no Mac. Falta rodar na VM Kali. Ver instruções no README/conversa do grupo.
