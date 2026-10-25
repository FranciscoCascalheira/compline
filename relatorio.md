# Relatório de SBOM e vulnerabilidades — exemplo-NodeGoat

> Nota: este documento é o resultado de uma prova técnica para medir viabilidade e esforço de uma ferramenta de SBOM e análise de vulnerabilidades. Não constitui parecer jurídico nem substitui aconselhamento jurídico sobre o Cyber Resilience Act ou qualquer outro regulamento.

Data de geração: 2026-10-24
Alvo analisado: exemplo-NodeGoat (clone público do OWASP NodeGoat)
Ferramentas: Syft (geração de SBOM em CycloneDX) e Grype (varrimento de vulnerabilidades)

## 1. Resumo

- Total de componentes identificados no SBOM: 422
- Total de vulnerabilidades reportadas pelo Grype: 105

Vulnerabilidades por severidade:
- Critical: 14
- High: 58
- Medium: 23
- Low: 10
- Negligible: 0
- Unknown: 0

## 2. Vulnerabilidades críticas e altas

| Componente | Versão | CVE | Severidade | Correção disponível | No catálogo KEV (CISA) |
| --- | --- | --- | --- | --- | --- |
| minimist | 0.0.10 | CVE-2021-44906 | Critical | Sim (0.2.4) | Não |
| minimist | 0.0.8 | CVE-2021-44906 | Critical | Sim (0.2.4) | Não |
| minimist | 0.0.8 | CVE-2021-44906 | Critical | Sim (0.2.4) | Não |
| minimist | 1.2.0 | CVE-2021-44906 | Critical | Sim (1.2.6) | Não |
| minimist | 1.2.5 | CVE-2021-44906 | Critical | Sim (1.2.6) | Não |
| underscore | 1.9.1 | CVE-2021-23358 | Critical | Sim (1.12.1) | Não |
| mixin-deep | 1.3.1 | CVE-2019-10746 | Critical | Sim (1.3.2) | Não |
| set-value | 0.4.3 | CVE-2019-10747 | Critical | Sim (2.0.1) | Não |
| set-value | 2.0.0 | CVE-2019-10747 | Critical | Sim (2.0.1) | Não |
| bson | 1.0.9 | CVE-2020-7610 | Critical | Sim (1.1.4) | Não |
| fsevents | 1.2.9 | CVE-2023-45311 | Critical | Sim (1.2.11) | Não |
| tar | 4.4.8 | CVE-2026-59873 | Critical | Sim (7.5.19) | Não |
| proxy-addr | 2.0.4 | CVE-2026-90711 | Critical | Sim (2.0.8) | Não |
| fsevents | 1.2.9 | GHSA-xv2f-5jw4-v95m | Critical | Sim (1.2.11) | Não |
| y18n | 3.2.1 | CVE-2020-7774 | High | Sim (3.2.2) | Não |
| decode-uri-component | 0.2.0 | CVE-2022-38900 | High | Sim (0.2.1) | Não |
| tar | 4.4.8 | CVE-2021-32804 | High | Sim (4.4.14) | Não |
| qs | 6.5.2 | CVE-2022-24999 | High | Sim (6.5.3) | Não |
| tar | 4.4.8 | CVE-2021-32803 | High | Sim (4.4.15) | Não |
| ini | 1.3.5 | CVE-2020-7788 | High | Sim (1.3.6) | Não |
| ini | 1.3.5 | CVE-2020-7788 | High | Sim (1.3.6) | Não |
| tar | 4.4.8 | CVE-2021-37701 | High | Sim (4.4.16) | Não |
| marked | 0.3.5 | CVE-2022-21680 | High | Sim (4.0.10) | Não |
| marked | 0.3.5 | CVE-2022-21681 | High | Sim (4.0.10) | Não |
| semver | 5.6.0 | CVE-2022-25883 | High | Sim (5.7.2) | Não |
| semver | 5.7.0 | CVE-2022-25883 | High | Sim (5.7.2) | Não |
| uglify-js | 2.4.24 | CVE-2015-8858 | High | Sim (2.6.0) | Não |
| kind-of | 6.0.2 | CVE-2019-20149 | High | Sim (6.0.3) | Não |
| minimatch | 3.0.4 | CVE-2022-3517 | High | Sim (3.0.5) | Não |
| minimatch | 3.0.4 | CVE-2022-3517 | High | Sim (3.0.5) | Não |
| set-value | 0.4.3 | CVE-2021-23440 | High | Sim (2.0.1) | Não |
| set-value | 2.0.0 | CVE-2021-23440 | High | Sim (2.0.1) | Não |
| debug | 2.2.0 | CVE-2017-20165 | High | Sim (2.6.9) | Não |
| tar | 4.4.8 | CVE-2021-37712 | High | Sim (4.4.18) | Não |
| nconf | 0.10.0 | CVE-2022-21803 | High | Sim (0.11.4) | Não |
| nconf | 0.6.9 | CVE-2022-21803 | High | Sim (0.11.4) | Não |
| marked | 0.3.5 | CVE-2017-16114 | High | Sim (0.3.9) | Não |
| braces | 2.3.2 | CVE-2024-4068 | High | Sim (3.0.3) | Não |
| tar | 4.4.8 | CVE-2021-37713 | High | Sim (4.4.18) | Não |
| i | 0.3.6 | CVE-2021-3820 | High | Sim (0.3.7) | Não |
| swig | 1.4.2 | CVE-2023-25345 | High | Não | Não |
| underscore | 1.9.1 | CVE-2026-27601 | High | Sim (1.13.8) | Não |
| path-to-regexp | 0.1.7 | CVE-2024-45296 | High | Sim (0.1.10) | Não |
| body-parser | 1.18.3 | CVE-2024-45590 | High | Sim (1.20.3) | Não |
| path-to-regexp | 0.1.7 | CVE-2024-52798 | High | Sim (0.1.12) | Não |
| braces | 2.3.2 | CVE-2026-93687 | High | Não | Não |
| brace-expansion | 1.1.11 | CVE-2026-69152 | High | Sim (1.1.18) | Não |
| brace-expansion | 1.1.11 | CVE-2026-69152 | High | Sim (1.1.18) | Não |
| minimatch | 3.0.4 | CVE-2026-26996 | High | Sim (3.1.3) | Não |
| minimatch | 3.0.4 | CVE-2026-26996 | High | Sim (3.1.3) | Não |
| tar | 4.4.8 | CVE-2026-24842 | High | Sim (7.5.7) | Não |
| brace-expansion | 1.1.11 | CVE-2026-14257 | High | Sim (1.1.17) | Não |
| brace-expansion | 1.1.11 | CVE-2026-14257 | High | Sim (1.1.17) | Não |
| path-to-regexp | 0.1.7 | CVE-2026-4867 | High | Sim (0.1.13) | Não |
| minimatch | 3.0.4 | CVE-2026-27903 | High | Sim (3.1.3) | Não |
| minimatch | 3.0.4 | CVE-2026-27903 | High | Sim (3.1.3) | Não |
| tar | 4.4.8 | CVE-2026-73566 | High | Sim (7.5.21) | Não |
| minimatch | 3.0.4 | CVE-2026-27904 | High | Sim (3.1.4) | Não |
| minimatch | 3.0.4 | CVE-2026-27904 | High | Sim (3.1.4) | Não |
| tar | 4.4.8 | CVE-2026-59874 | High | Sim (7.5.18) | Não |
| tar | 4.4.8 | CVE-2026-29786 | High | Sim (7.5.10) | Não |
| tar | 4.4.8 | CVE-2026-23745 | High | Sim (7.5.3) | Não |
| brace-expansion | 1.1.11 | CVE-2026-102276 | High | Sim (1.1.19) | Não |
| brace-expansion | 1.1.11 | CVE-2026-102276 | High | Sim (1.1.19) | Não |
| brace-expansion | 1.1.11 | CVE-2026-102278 | High | Sim (1.1.20) | Não |
| brace-expansion | 1.1.11 | CVE-2026-102278 | High | Sim (1.1.20) | Não |
| brace-expansion | 1.1.11 | CVE-2026-13149 | High | Sim (1.1.16) | Não |
| brace-expansion | 1.1.11 | CVE-2026-13149 | High | Sim (1.1.16) | Não |
| tar | 4.4.8 | CVE-2026-23950 | High | Sim (7.5.4) | Não |
| tar | 4.4.8 | CVE-2026-26960 | High | Sim (7.5.8) | Não |
| tar | 4.4.8 | CVE-2026-31802 | High | Sim (7.5.11) | Não |
| mongodb | 2.2.36 | GHSA-mh5c-679w-hh4r | High | Sim (3.1.13) | Não |

## 3. Cruzamento com vulnerabilidades ativamente exploradas (KEV da CISA)

Dos 77 CVE únicos encontrados pelo Grype, nenhum consta do catálogo CISA KEV (fonte: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json, catálogo versão 2026.10.23, consultado em 2026-10-24). Cópia local: kev-cisa-2026-10-24.json.

Nota: o JSON produzido pelo Grype nesta instalação não inclui um campo próprio de KEV; o cruzamento acima foi feito diretamente contra o catálogo público da CISA, descarregado nesta execução (ver secção 6, Fontes).

## 3.1 Cruzamento com o EPSS (Exploit Prediction Scoring System) da FIRST

Pontuação EPSS (probabilidade de exploração nos próximos 30 dias) obtida na API pública da FIRST (https://api.first.org/data/v1/epss, consultado em 2026-10-24). Cópia local: epss-first-2026-10-24.json. As 10 CVE com EPSS mais alto entre as 77 consultadas com sucesso:

| CVE | Componente | Severidade (Grype) | EPSS | Percentil | No KEV |
| --- | --- | --- | --- | --- | --- |
| CVE-2020-7774 | y18n | High | 0.69377 | 0.99362 | Não |
| CVE-2022-38900 | decode-uri-component | High | 0.23789 | 0.97826 | Não |
| CVE-2022-24999 | qs | High | 0.15622 | 0.96840 | Não |
| CVE-2021-32804 | tar | High | 0.15067 | 0.96732 | Não |
| CVE-2021-32803 | tar | High | 0.07795 | 0.94661 | Não |
| CVE-2021-44906 | minimist | Critical | 0.04581 | 0.91610 | Não |
| CVE-2021-23358 | underscore | Critical | 0.04200 | 0.90930 | Não |
| CVE-2020-7788 | ini | High | 0.03655 | 0.89583 | Não |
| CVE-2019-10746 | mixin-deep | Critical | 0.03651 | 0.89570 | Não |
| CVE-2021-37701 | tar | High | 0.03286 | 0.88424 | Não |

## 4. Ligação às obrigações do artigo 14.º do Regulamento (UE) 2024/2847 (Cyber Resilience Act)

O artigo 14.º do Cyber Resilience Act estabelece obrigações de notificação para fabricantes de produtos com elementos digitais, em dois eixos: vulnerabilidades ativamente exploradas que afetem o produto, e incidentes graves que tenham impacto na segurança do produto. Estas obrigações aplicam-se desde 11 de setembro de 2026.

No eixo das vulnerabilidades ativamente exploradas, o fabricante deve notificar a ENISA (que depois partilha com o CSIRT designado e, quando relevante, com as autoridades de mercado competentes):

- Um aviso prévio (early warning) no prazo de 24 horas após tomar conhecimento da vulnerabilidade ativamente explorada.
- Uma notificação de vulnerabilidade no prazo de 72 horas, com mais detalhe sobre a natureza e o impacto da vulnerabilidade, e eventuais medidas de mitigação ou correção já disponíveis.
- Um relatório final, no prazo de 14 dias após a disponibilização de uma correção (ou, se não existir correção, no prazo de um ano), com a descrição da vulnerabilidade, a sua gravidade e impacto, e informação sobre a correção disponibilizada ou outras medidas corretivas, quando aplicável.

Relação com os resultados desta prova técnica:

- O SBOM gerado pelo Syft (sbom.cdx.json) é o inventário de componentes que permite identificar quais os componentes de terceiros utilizados pelo produto, pré-condição para conseguir avaliar se uma vulnerabilidade divulgada afeta ou não o produto.
- O resultado do Grype (vulns.json) identifica vulnerabilidades conhecidas (CVE) associadas a esses componentes e indica se existe correção disponível, informação relevante para o conteúdo da notificação em 72 horas e do relatório final.
- O critério decisivo para acionar os prazos do artigo 14.º não é a mera existência de um CVE, mas sim a exploração ativa confirmada dessa vulnerabilidade. Nesta prova, esse critério foi aproximado cruzando os CVE encontrados com o catálogo público CISA KEV; ver secção 3 para o resultado concreto nesta execução. Estar no catálogo KEV é um indício forte de exploração ativa, mas a confirmação final de que uma vulnerabilidade concreta afeta um produto real e de que os prazos do artigo 14.º foram acionados exige análise caso a caso, não apenas o cruzamento automático.
- Esta análise automática não determina por si só se o exemplo-NodeGoat (ou um produto real baseado nele) está dentro do âmbito do Cyber Resilience Act, nem substitui o processo de notificação formal à ENISA. Serve apenas para demonstrar como um fluxo de SBOM mais varrimento de vulnerabilidades pode alimentar esse processo.

## 5. Limitações desta prova técnica

- Esta é uma prova técnica de viabilidade, não um produto nem um parecer jurídico.
- A deteção de "exploração ativa" depende dos dados que o Grype expõe no seu JSON; quando esse campo não existe, o relatório assinala a lacuna em vez de inferir um resultado.
- Não foi feita qualquer validação manual dos CVE listados nem confirmação de que afetam efetivamente o comportamento em runtime do exemplo-NodeGoat.
- A severidade apresentada é a severidade primária reportada pelo Grype (frequentemente proveniente de uma advisory do GitHub), que por vezes difere da severidade atribuída pela NVD ao mesmo CVE.
- O cruzamento com o KEV e com o EPSS depende da disponibilidade das APIs públicas da CISA e da FIRST no momento da execução; se alguma falhar, o relatório assinala a falha em vez de inferir um resultado (ver secções 3 e 3.1).
- O EPSS é uma estimativa estatística de probabilidade de exploração futura, não uma confirmação de exploração ativa; o KEV é que serve de gatilho para as obrigações do artigo 14.º.

## 6. Fontes

- Catálogo CISA KEV (Known Exploited Vulnerabilities): https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json, consultado em 2026-10-24. Cópia local gravada em kev-cisa-2026-10-24.json.
- API pública EPSS da FIRST: https://api.first.org/data/v1/epss, consultado em 2026-10-24. Cópia local gravada em epss-first-2026-10-24.json.
