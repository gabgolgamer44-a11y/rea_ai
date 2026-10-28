# REA AI — Reverse Engineer Anything com agentes de IA

> **Iniciado em 28/10/2026, o REA AI é um projeto novo e experimental, ainda em desenvolvimento.** A previsão de lançamento é **25/11/2026**, em uma versão experimental que ainda poderá apresentar bugs. O projeto está sendo preparado a partir do sistema completo do REA original. As funções e integrações descritas abaixo representam a direção do projeto e o avanço gradual das validações.

O **REA AI** pretende conectar agentes de inteligência artificial a ferramentas de engenharia reversa. A ideia é permitir que você investigue um programa fazendo perguntas em linguagem natural, enquanto o agente usa os fluxos do REA, reúne evidências e explica o que foi observado.

**[Conheça a experiência visual](https://rea-ai-showcase.kathiuscia.chatgpt.site) · [Leia a Wiki](https://github.com/gabgolgamer44-a11y/rea_ai/wiki) · [Acompanhe o plano](https://github.com/gabgolgamer44-a11y/rea_ai/issues/1)**

> O site é uma apresentação visual com demonstrações ilustrativas. Ele não analisa arquivos e não indica que as integrações previstas já estejam prontas.

## O que queremos construir

O REA original oferece um sistema para agentes investigarem binários, aplicativos e comportamento em execução por meio de ferramentas e fluxos de trabalho. O REA AI pretende preservar esse sistema completo e acrescentar adaptações próprias.

O objetivo é que o agente possa:

- entender o tipo de alvo e a pergunta feita;
- escolher uma ferramenta compatível com o alvo e com o ambiente disponível;
- coletar informações que ajudem a responder à pergunta;
- separar observações, inferências e pontos ainda incertos;
- apresentar evidências para que você possa revisar as conclusões.

O REA AI é a integração entre agentes, fluxos do REA e ferramentas locais. Ele não substitui as ferramentas de análise nem garante, por si só, que uma conclusão esteja correta.

## Como uma investigação poderá funcionar

1. Você pede ao agente para explicar um comportamento, recurso ou arquivo.
2. O agente define o escopo e identifica os tipos de análise que podem ajudar.
3. O REA seleciona provedores e operações compatíveis, quando disponíveis.
4. As ferramentas retornam resultados que podem ser relacionados a funções, referências, processos ou tráfego.
5. O agente explica o que as evidências sustentam e quais validações continuam pendentes.

Esse fluxo é uma visão do produto. A seleção e a execução das operações dependerão das integrações efetivamente implementadas e configuradas.

## Integrações no escopo

A tabela mostra o escopo desejado e a situação conhecida no REA original:

| Ferramenta | Área | Situação conhecida na base original | Direção no REA AI |
| --- | --- | --- | --- |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Análise estática e descompilação | Integração existente na base | Preservar e ampliar conforme necessário |
| IDA Pro | Análise estática e descompilação | Integração existente na base | Preservar e ampliar conforme necessário |
| [Radare2](https://github.com/radareorg/radare2) | Análise estática e automação | Suporte a Rizin na base; integração com Radare2 adicionada | Implementada (`src/radare2/`) |
| x64dbg | Depuração dinâmica no Windows | Não identificada na inspeção inicial | Implementada via ponte IPC (`src/x64dbg/`) |
| Binary Ninja | Análise estática e descompilação | Não identificada na inspeção inicial | Implementada com checagem de licença (`src/binaryninja/`) |
| Frida | Instrumentação dinâmica | Integração existente na base | Preservar e ampliar com controles explícitos |
| OllyDbg | Depuração legada de 32 bits no Windows | Não identificada na inspeção inicial | Conector supervisionado (`src/ollydbg/`) |
| JADX | Análise de APK/DEX para Android | Integração existente na base | Preservar e integrar ao fluxo geral |
| Immunity Debugger | Depuração legada no Windows | Não identificada na inspeção inicial | Conector supervisionado com checagem de runtime (`src/immunity/`) |
| Wireshark / TShark | Análise de tráfego e capturas | Suporte com restrições | Leitura offline de PCAP sem Npcap no Windows ampliada (`src/captures/`) |

As integrações só serão anunciadas como prontas quando houver evidência adequada. Encontrar um executável instalado não comprova que o adaptador funciona.

## Como vamos relatar o estado

Cada ferramenta será classificada com base no que foi observado:

- **Planejada:** faz parte do escopo, sem implementação confirmada.
- **Encontrada na base:** há código de integração no upstream importado.
- **Implementada:** operações reais estão conectadas por um adaptador.
- **Testada com simulação:** contratos e respostas foram exercitados com dados controlados.
- **Validada em execução real:** uma operação reproduzível funcionou na ferramenta instalada.
- **Limitada ou pendente:** plataforma, licença, dependência ou ausência da ferramenta impede a validação.

A matriz detalhada ficará na [Wiki do projeto](https://github.com/gabgolgamer44-a11y/rea_ai/wiki).

## Segurança e uso responsável

- Ações que iniciem ou alterem processos exigem autorização explícita.
- Ferramentas comerciais usam instalações e licenças fornecidas pelo próprio usuário.
- Binários proprietários não serão incluídos no repositório.
- Capturas de rede e arquivos de análise devem ser autorizados pelo usuário.
- Resultados precisam indicar limitações e distinguir evidência de interpretação.

Use o REA AI apenas em arquivos, sistemas e redes que você tem autorização para analisar.

## Estado atual

O código do REA AI está organizado com a importação da base e a implementação dos novos adaptadores e testes de conformidade.

Instruções de instalação, configuração, CLI e MCP serão adicionadas depois que os comandos e as ferramentas forem completamente validados.

## Base, créditos e licenças

O projeto toma como referência o REA original. A importação preserva o histórico, os créditos, as licenças, os avisos de terceiros, a documentação, os testes e as funcionalidades da base sob licença MIT.

As licenças e avisos distribuídos com a base e suas dependências devem ser consultados antes de redistribuir o projeto.

## Acompanhe o projeto

- [Wiki do REA AI](https://github.com/gabgolgamer44-a11y/rea_ai/wiki)
- [Plano e critérios de acompanhamento](https://github.com/gabgolgamer44-a11y/rea_ai/issues/1)
- [Experiência visual do projeto](https://rea-ai-showcase.kathiuscia.chatgpt.site)

## Contribuições

Durante o desenvolvimento da base, mudanças devem ser pequenas, revisáveis e compatíveis com os fluxos existentes. Antes de propor uma nova integração, verifique se ela já existe e documente as versões, plataformas, dependências e operações que realmente funcionam.

Use os modelos de issue e pull request do repositório para registrar bugs, melhorias, evidências de validação e limitações.
