# Roteiro da apresentação (tudo na VM Kali)

Todos os comandos abaixo rodam **na VM Kali**, dentro da pasta do projeto. Um comando por bloco,
é só copiar e colar.

## 0. Antes de tudo (no Mac)

A correção do `snapshot.py` (reconhecer `bash`/`dash`/`python` pelo nome do executável) precisa estar
commitada e enviada, senão a VM roda a versão antiga e a Regra 1 não dispara no serviço de teste.
Commit e `git push` pelo Mac.

## 1. Preparação (na VM, antes da aula)

Entrar na pasta do projeto:

```bash
cd ~/Documents/AI-techacker
```

Trazer o código mais recente:

```bash
git pull
```

Instalar as dependências:

```bash
uv sync
```

Rodar os testes (esperado: `32 passed`):

```bash
uv run pytest -q
```

### 1.1 Gerar os 4 datasets de demonstração

A pasta `training/` não vai pro git, então os datasets precisam ser gerados na VM.

```bash
uv run python generate_dataset.py --level basic --output training/demo-1-normal --seed 1
```

```bash
uv run python generate_dataset.py --level intermediate --output training/demo-2-root-restrito --seed 1
```

```bash
uv run python generate_dataset.py --level challenge --output training/demo-3-correlacao --seed 1
```

```bash
uv run python generate_dataset.py --level challenge --output training/demo-4-ambiguo --seed 7
```

Cenários que cada um gera: `normal`, `privileged_service`, `correlation` e `ambiguous`.

### 1.2 Criar o serviço de teste (situação controlada)

Um serviço systemd que roda como root e executa um script com permissão `0777`. É só pra testar a
lógica da ferramenta, apague depois (seção 4).

```bash
sudo mkdir -p /opt/demo
```

```bash
printf '#!/bin/bash\nwhile true; do sleep 60; done\n' | sudo tee /opt/demo/backup.sh > /dev/null
```

```bash
sudo chmod 777 /opt/demo/backup.sh
```

```bash
printf '[Unit]\nDescription=Servico de teste\n\n[Service]\nExecStart=/bin/bash /opt/demo/backup.sh\n' | sudo tee /etc/systemd/system/demo-backup.service > /dev/null
```

```bash
sudo systemctl daemon-reload
```

```bash
sudo systemctl start demo-backup.service
```

Conferir que subiu (tem que aparecer `active (running)`):

```bash
systemctl status demo-backup.service --no-pager
```

### 1.3 Ensaiar o comando real e tirar um print

Rode exatamente o que será rodado ao vivo:

```bash
sudo $(which uv) run python -m endpoint_investigator.cli
```

Esperado: um painel `HIGH` para `demo-backup.service` (permissão `0777`) e um `LOW` para a própria
sessão `sudo`. **Tire um print da tela**: é o plano B se algo falhar na hora.

Se o `HIGH` não aparecer, não improvise: mande a saída completa pra investigar antes da aula.

## 2. Apresentação (ordem)

Terminal com fonte grande, e `clear` entre os passos.

```bash
clear
```

### Passo 1: problema e ideia (1 min, sem comando)

Uma evidência isolada raramente basta. O fluxo da ferramenta é:
coleta → normalização → correlação → evidências → resultado.

### Passo 2: testes (30 s, opcional)

```bash
uv run pytest -q
```

Fala: "32 testes automatizados; rodam sem precisar de um Linux de verdade".

### Passo 3: cenário normal

```bash
uv run python -m endpoint_investigator.cli training/demo-1-normal
```

Saída: `nenhum achado nessa coleta`.
Fala: a ferramenta fica quieta quando não há o que dizer.

### Passo 4: serviço root não é vulnerável

```bash
uv run python -m endpoint_investigator.cli training/demo-2-root-restrito
```

Saída: `nenhum achado nessa coleta`.
Fala: o `backup-agent` roda como root, mas o script é `0700`, restrito ao dono. Se quiser provar:

```bash
cat training/demo-2-root-restrito/permissions.csv
```

### Passo 5: correlação (momento principal)

```bash
uv run python -m endpoint_investigator.cli training/demo-3-correlacao
```

Saída: painel `HIGH` / confiança `high` (`servico_privilegiado_arquivo_gravavel`).
Leia os 4 campos em voz alta: evidência, interpretação, hipótese e evidência ausente.
Frase-chave: **"isso não prova exploração"**; a evidência ausente diz o que falta para confirmar.

### Passo 6: cenário ambíguo

```bash
uv run python -m endpoint_investigator.cli training/demo-4-ambiguo
```

Saída: `nenhum achado nessa coleta`.
Fala: esse cenário tem uma conexão externa feita por serviço root, mas a ferramenta não coleta
rede. É um ponto cego declarado, não uma conclusão de que está tudo bem.

### Passo 7: sistema real (Kali ao vivo)

Primeiro a prova do lado do sistema, o arquivo aberto pra todo mundo:

```bash
ls -l /opt/demo/backup.sh
```

Agora a ferramenta, sem dataset, lendo o `/proc` e o `systemctl` de verdade:

```bash
sudo $(which uv) run python -m endpoint_investigator.cli
```

Saída: o `HIGH` do `demo-backup.service` e o `LOW` do `sudo`.
Fala: o `LOW` é a própria sessão da ferramenta, classificada como elevação por `sudo`. Aproveitar
para contar o que só apareceu no sistema real: o `sudo` faz fork (o pai fica com `sudo`, o filho já
roda como root) e o `auditd.service`, cujo erro derrubava a coleta inteira.

### Passo 8: fecho (1 min, sem comando)

Limitações: sem rede e logs, UID real em vez de efetivo (setuid não é detectado), só o arquivo e não
o diretório, só 2 das 4 correlações. Próximo passo possível: coleta de rede e de logs.

## 3. Se algo der errado

- **`uv: command not found`:** `source $HOME/.local/bin/env` e tente de novo.
- **`sudo: uv: command not found`:** use sempre `sudo $(which uv) ...`, o `sudo` tem `PATH` próprio.
- **A VM trava ou não sobe:** mostre o print do ensaio e siga com os datasets (passos 3 a 6),
  que só precisam do `uv`.
- **Faltou tempo:** corte os passos 2 e 4.

## 4. Depois da apresentação (limpar a VM)

```bash
sudo systemctl stop demo-backup.service
```

```bash
sudo rm /etc/systemd/system/demo-backup.service
```

```bash
sudo rm -r /opt/demo
```

```bash
sudo systemctl daemon-reload
```
