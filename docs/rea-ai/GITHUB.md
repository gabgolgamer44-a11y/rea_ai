# Organização do GitHub do REA AI

O REA AI usa o sistema completo de [morluto/rea](https://github.com/morluto/rea) como base, preservando suas funcionalidades, histórico, créditos e licenças. As adaptações são acompanhadas na [issue #1](https://github.com/gabgolgamer44-a11y/rea_ai/issues/1).

## Fluxo de trabalho

1. Importar a base completa e registrar o commit upstream efetivamente utilizado.
2. Entregar a importação em PR de rascunho, com os resultados das verificações originais.
3. Desenvolver as integrações em lotes revisáveis, reutilizando as capacidades existentes.
4. Vincular cada PR à issue de acompanhamento e informar o que foi implementado e validado.
5. Integrar na main após revisão. Não fazer force-push em branches compartilhadas.

A branch de preparação do GitHub é `chore/rea-ai-github`. A implementação do Antigravity fica em sua própria branch. Esses trabalhos não devem sobrescrever alterações um do outro.

## Modelos

- [Modelo de PR do REA AI](../../.github/PULL_REQUEST_TEMPLATE/rea_ai.md)
- [Relato de problema](../../.github/ISSUE_TEMPLATE/rea_ai_bug.md)
- [Proposta de melhoria](../../.github/ISSUE_TEMPLATE/rea_ai_melhoria.md)

O modelo de PR é opcional e específico do REA AI, para coexistir com os modelos do upstream. Selecione-o com o parâmetro `template=rea_ai.md` na página de criação do PR.

## Evidências de entrega

Para cada integração, separar:
- **Ferramenta detectada:** instalação ou dependência localizada.
- **Implementada:** operações conectadas à ferramenta com tratamento de erros.
- **Testada com simulação:** contratos e fluxos verificados com respostas controladas.
- **Validada em execução real:** operação executada na ferramenta instalada, com alvo reproduzível.
- **Pendente ou indisponível:** motivo e requisitos para concluir a validação.

Informar versões, plataformas, comandos executados, resultados e limitações. A abertura de uma janela ou a detecção de um executável não comprova uma integração funcional.

## Automação e configuração

As verificações automáticas devem ser configuradas após a importação, a partir dos scripts, workflows e requisitos reais do REA. A presença destes modelos não comprova build nem testes aprovados.

Credenciais devem permanecer no mecanismo de autenticação do ambiente. Não incluir tokens em arquivos, logs, URLs ou exemplos. Ferramentas comerciais devem usar instalações licenciadas do usuário.

Proteção de branches, permissões e publicação de releases devem ser definidas conforme os checks reais e a estratégia do projeto. Este documento não afirma que tais configurações já foram aplicadas.
