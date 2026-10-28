# Matriz de Integração e Conformidade das Ferramentas no REA AI

Este documento estabelece o inventário oficial de capacidades, status de implementação, mecanismos de comunicação e limitações técnicas das ferramentas suportadas pelo **REA AI**.

Conforme as diretrizes de integridade técnica do projeto:
- **Ferramenta Instalada**: Dependência ou executável detectado localmente no sistema host.
- **Integração Implementada**: Adaptador construído com código TypeScript, contratos, schemas e tratamento de erros.
- **Integração Validada (Simulada)**: Testada e aprovada contra suíte de testes com mocks/stubs fiéis aos schemas do REA.
- **Integração Validada (Real)**: Testada com o software real instalado e amostras de teste no ambiente.
- **Limitação Conhecida**: Restrição intrínseca de arquitetura, plataforma ou ausência de interface headless no software original.

---

## 1. Matriz Geral de Status das 10 Ferramentas

| # | Ferramenta | Categoria / Domínio | Status de Integração | Plataformas Suportadas | Mecanismo de Automação / Transporte | Validação |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Ghidra** | Estática / Descompilação | **Existente / Ampliada** | Windows, Linux, macOS | Headless Analyzer (`analyzeHeadless.bat`/`.sh`) + PyGhidra bridge | Validada Real e Simulada |
| **2** | **IDA Pro** | Estática / Descompilação | **Existente / Ampliada** | Windows, Linux, macOS | Protocolo nativo IPC + Headless `idat64`/`idat` | Validada Real (quando licenciado) e Simulada |
| **3** | **JADX** | Estática / Android & Java | **Existente / Ampliada** | Windows, Linux, macOS | CLI JSON headless (`jadx`) + Java bridge | Validada Real e Simulada |
| **4** | **Frida** | Instrumentação Dinâmica | **Existente / Ampliada** | Windows, Linux, macOS | Bindings nativos Frida Core com salvaguardas explícitas | Validada Real e Simulada |
| **5** | **Wireshark / TShark** | Análise de Rede & Tráfego | **Ampliada** *(Offline no Windows)* | Windows, Linux, macOS | CLI `tshark -r <file> -n -T json` (Offline sem Npcap) / Live (`-i`, requer Npcap no Win) | Validada Real e Simulada |
| **6** | **Radare2** | Estática / Disassembly | **Implementada** | Windows, Linux, macOS | CLI assíncrona isolada (`r2 -N -q -e scr.color=0 -c ...`) com parsing JSON | Validada Simulada |
| **7** | **Binary Ninja** | Estática / Descompilação | **Implementada** | Windows, Linux, macOS | API Python (`binaryninja`) / CLI `binja` com checagem de licença do usuário | Validada Simulada |
| **8** | **x64dbg** | Depuração Dinâmica | **Implementada** | Windows (x86/x64) | Ponte de automação IPC (Named Pipe / Script em lote) sobre supervisor de processos | Validada Simulada |
| **9** | **Immunity Debugger** | Depuração Legada / Exploit | **Implementada** | Windows (x86 32-bit apenas) | PyCommands com validação rigorosa de runtime (`python27.dll` e `immlib.py`) | Validada Simulada |
| **10** | **OllyDbg** | Depuração Legada | **Implementada** | Windows (x86 32-bit apenas) | Inicialização supervisionada e scripts de automação (`ODbgScript`) | Validada Simulada |

---

## 2. Detalhamento Técnico e Limitações Conhecidas

### 1. Ghidra (`src/ghidra/`)
* **Operações Suportadas**: `inspect_native_load_image`, `list_procedures`, `search_procedures`, `procedure_assembly`, `decompile_procedure`, `procedure_references`, `list_strings`.
* **Configuração**: Detecta `GHIDRA_INSTALL_DIR`, `GHIDRA_HOME` e diretórios padrão do Windows e Linux.
* **Limitações**: Exige Java JDK 17+ / 21+ instalado. Primeira indexação de binários grandes pode demandar tempo e memória consideráveis.

### 2. IDA Pro (`src/ida/`)
* **Operações Suportadas**: Disassembly, callgraphs, xrefs, funções e descompilação Hex-Rays.
* **Detecção Granular de Licença**: O REA sonda se os plugins Hex-Rays (`hexrays.dll`, `hexx64.dll`, etc.) estão presentes. Se ausentes, o provedor anuncia apenas disassembly e metadados, sem prometer pseudocódigo.
* **Limitações**: Software proprietário comercial do usuário. Requer licença válida; binários não são incluídos no repositório.

### 3. JADX (`src/android/`)
* **Operações Suportadas**: Descompilação completa de arquivos APK, DEX, AAR e JAR para código Java de alto nível.
* **Configuração**: Auto-detecta `jadx` no PATH ou via submódulo `third_party/jadx-headless-mcp`.

### 4. Frida (`src/frida/`)
* **Operações Suportadas**: Instrumentação de processos, leitura de memória, hooks de entrada e saída de funções, enumeração de módulos e threads.
* **Salvaguardas de Segurança**: Ações que alteram estado, injetam código ou pausarem processos exigem autorização explícita (`--allow-process-execution` / política de permissão).

### 5. Wireshark / TShark (`src/captures/`, `src/pcap/`)
* **Desacoplamento Offline vs. Captura ao Vivo**:
  * **Análise Offline de PCAP / PCAPNG**: Opera em espaço de usuário via `tshark -r <file> -n -T json`. **Não requer Npcap** no Windows. Suporta filtros de exibição complexos (`-Y`) e extração estruturada de campos (`-e`).
  * **Captura ao Vivo**: Requer interface física/lógica e exige a presença comprovada do driver Npcap / WinPcap no Windows.

### 6. Radare2 (`src/radare2/`)
* **Operações Suportadas**: Metadados do binário (`ij`), funções (`aflj`), strings (`izj`), imports/exports (`iij`/`isj`), disassembly (`pdfj`) e xrefs (`axtj`).
* **Sondagem Opcional de Descompilação**: Sonda a presença de plugins como `r2ghidra` (`pdg?`) ou `r2dec` (`pdd?`). O recurso de descompilação é anunciado na `CapabilityDescriptor` apenas se o plugin responder afirmativamente.
* **Isolamento**: Sempre executado com `-N` (ignora `~/.radare2rc`) e `-e scr.color=0` para evitar sequências ANSI na serialização JSON.

### 7. Binary Ninja (`src/binaryninja/`)
* **Operações Suportadas**: Funções, strings, tipos, imports, exports e descompilação em Intermediate Language (HLIL/BNIL).
* **Verificação de Licença Headless**: O conector verifica se a instalação do Binary Ninja possui licença com suporte à API headless Python (`import binaryninja`). Instalações Demo ou não licenciadas anunciam recusa limpa.

### 8. x64dbg (`src/x64dbg/`)
* **Operações Suportadas**: Controle de sessão de depuração de binários PE (x86 e x64), registradores, memória e breakpoints.
* **Mecanismo de Conexão**: Ponte local assíncrona (Windows Named Pipe / Scripting bridge) associada ao gerenciamento de processos do REA.
* **Limitações**: Aplicação com interface gráfica desktop; requer sessão interativa no Windows (não é nativamente headless para contêineres sem display).

### 9. Immunity Debugger (`src/immunity/`)
* **Operações Suportadas**: Execução de scripts `immlib` / `PyCommands`, inspeção de registradores e memória de processos PE 32-bit.
* **Verificação Estrita de Dependência**: Requer obrigatoriamente **Python 2.7 32-bit** (`python27.dll`) e o pacote `immlib.py`. Não suporta Python 3.
* **Limitações**: Restrito estritamente a arquitetura x86 32-bit no Windows. Interface GUI sem modo headless puro.

### 10. OllyDbg (`src/ollydbg/`)
* **Operações Suportadas**: Inicialização supervisionada e execução de rotinas automáticas via plugin `ODbgScript` para desempacotamento e inspeção de PE 32-bit.
* **Limitações**: Não possui interface headless CLI moderna ou API JSON nativa. Restrito a alvos de 32 bits no Windows. Não são feitas declarações fictícias de descompilação ou automação avançada.
