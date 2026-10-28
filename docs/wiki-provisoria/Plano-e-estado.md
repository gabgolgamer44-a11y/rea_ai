# Plano e estado

## Etapas acordadas

1. Importar o REA original integralmente, preservar histórico, licenças e créditos, registrar o commit realmente usado e medir a linha de base dos testes.
2. Auditar e ampliar as integrações existentes, incluindo Ghidra, IDA Pro, JADX, Frida e TShark.
3. Avaliar e implementar Radare2 e Binary Ninja conforme as capacidades disponíveis.
4. Avaliar a automação real do x64dbg e separar análise offline de PCAP da captura ao vivo.
5. Determinar o que é viável para OllyDbg e Immunity Debugger e documentar as limitações verificadas.
6. Atualizar a documentação em português e a matriz de integrações com resultados e evidências.

O trabalho de implementação está sendo conduzido pelo Antigravity. Cada etapa deve ser revisada em branch e PR.

## Estado atual

- A branch `main` do rea_ai ainda contém apenas um README breve, conforme a inspeção inicial.
- A issue [#1](https://github.com/gabgolgamer44-a11y/rea_ai/issues/1) acompanha as etapas e critérios.
- O PR [#2](https://github.com/gabgolgamer44-a11y/rea_ai/pull/2) prepara modelos e orientações de revisão.
- Esta wiki provisória está sendo proposta por PR separado.
- A importação do upstream e as integrações ainda não foram confirmadas como concluídas.

## Registro de validação

Para cada entrega, atualizar a matriz com:
- commit e arquivos alterados;
- versão da ferramenta, sistema operacional e arquitetura testados;
- comandos executados e resultados;
- testes simulados e execução real relatados separadamente;
- recursos indisponíveis e limitações restantes.

Referências principais: [REA upstream](https://github.com/morluto/rea), [README upstream](https://github.com/morluto/rea#readme), [issue de acompanhamento](https://github.com/gabgolgamer44-a11y/rea_ai/issues/1).
