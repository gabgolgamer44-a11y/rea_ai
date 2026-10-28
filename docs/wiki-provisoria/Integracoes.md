# Integrações planejadas

A lista registra o escopo pretendido. O estado de cada ferramenta será atualizado com evidências após examinar a base importada e testar as integrações.

| Ferramenta | Papel pretendido | Situação nesta wiki |
| --- | --- | --- |
| Ghidra | Análise e descompilação estática | A verificar na base e ampliar conforme necessário |
| IDA Pro | Análise e descompilação estática | A verificar na base e ampliar conforme necessário |
| Radare2 | Análise estática e automação por linha de comando | A verificar; nova integração planejada |
| x64dbg | Depuração dinâmica no Windows | A verificar; mecanismo de automação precisa de validação |
| Binary Ninja | Análise estática e descompilação | A verificar; dependências e licença precisam de validação |
| Frida | Instrumentação dinâmica de processos | A verificar na base e ampliar conforme necessário |
| OllyDbg | Depuração legada de executáveis Windows 32-bit | Viabilidade e limites de automação a confirmar |
| JADX | Análise de APK/DEX e código Android | A verificar na base e ampliar conforme necessário |
| Immunity Debugger | Depuração legada no Windows | Runtime e mecanismo de scripts a confirmar |
| Wireshark / TShark | Leitura de capturas e análise de pacotes | A verificar na base; separar análise offline de captura ao vivo |

## Como interpretar os estados

- **A verificar na base:** ainda não foi feita a auditoria do código importado.
- **Planejada:** consta no escopo, sem alegação de que exista implementação.
- **Implementada:** código do adaptador existe e trata contratos e erros.
- **Validada com simulação:** testes com respostas controladas passaram.
- **Validada em execução real:** a ferramenta instalada realizou uma operação reproduzível.
- **Pendente/limitada:** dependência, plataforma ou capacidade impede ou restringe a operação.

Detecção do executável, por si só, não demonstra que o conector funciona. Ferramentas comerciais usarão instalações e licenças locais do usuário; binários proprietários não serão incluídos no repositório.
