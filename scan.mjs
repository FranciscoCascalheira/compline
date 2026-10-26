// Compline scan: SBOM (Syft) + vulnerability scan (Grype) + CISA KEV and FIRST EPSS cross-check.
// Resolves syft/grype from PATH (or SYFT_BIN/GRYPE_BIN). No npm dependencies, Node.js built-ins only.
// Writes relatorio.md (report text in Portuguese, the language of the first proof); annex7.py reads it.

import { execFileSync } from 'node:child_process';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const TARGET_DIR = process.env.TARGET_DIR || path.join(ROOT, 'exemplo-NodeGoat');
const SYFT_BIN = process.env.SYFT_BIN || 'syft';
const GRYPE_BIN = process.env.GRYPE_BIN || 'grype';
const SBOM_PATH = path.join(ROOT, 'sbom.cdx.json');
const VULNS_PATH = path.join(ROOT, 'vulns.json');
const REPORT_PATH = path.join(ROOT, 'relatorio.md');

const timings = {};

function run(bin, args, label) {
  const start = Date.now();
  const result = execFileSync(bin, args, {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 200,
    env: {
      ...process.env,
      SYFT_CHECK_FOR_APP_UPDATE: 'false',
      GRYPE_CHECK_FOR_APP_UPDATE: 'false',
      GRYPE_DB_AUTO_UPDATE: 'false',
    },
  });
  timings[label] = Date.now() - start;
  return result;
}

// --- 1) Syft: generate a CycloneDX JSON SBOM ---
console.log('A correr syft sobre exemplo-NodeGoat...');
let sbomJson;
try {
  sbomJson = run(SYFT_BIN, ['scan', `dir:${TARGET_DIR}`, '-o', 'cyclonedx-json'], 'syft');
} catch (errModern) {
  console.log('Sintaxe "syft scan" falhou, a tentar sintaxe legada "syft dir:..."');
  sbomJson = run(SYFT_BIN, [`dir:${TARGET_DIR}`, '-o', 'cyclonedx-json'], 'syft');
}
writeFileSync(SBOM_PATH, sbomJson, 'utf8');
console.log(`SBOM gravado em ${SBOM_PATH} (${timings.syft} ms)`);

// --- 2) Grype: scan the SBOM and write vulns.json ---
console.log('A correr grype sobre o SBOM...');
const vulnsJson = run(GRYPE_BIN, [`sbom:${SBOM_PATH}`, '-o', 'json'], 'grype');
writeFileSync(VULNS_PATH, vulnsJson, 'utf8');
console.log(`Resultados do grype gravados em ${VULNS_PATH} (${timings.grype} ms)`);

// --- 3) Analyse results ---
const sbom = JSON.parse(readFileSync(SBOM_PATH, 'utf8'));
const vulnsReport = JSON.parse(readFileSync(VULNS_PATH, 'utf8'));

const totalComponentes = Array.isArray(sbom.components) ? sbom.components.length : 0;

const matches = Array.isArray(vulnsReport.matches) ? vulnsReport.matches : [];

const severidadeOrdem = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];
const contagemSeveridade = {};
for (const s of severidadeOrdem) contagemSeveridade[s] = 0;

let temCampoKEV = false;

function detectaKEV(match) {
  const v = match.vulnerability || {};
  // Procura qualquer indicio de um campo KEV (Known Exploited Vulnerabilities) no JSON do Grype.
  const candidatos = [v.knownExploited, v.kev, match.knownExploited, match.kev];
  for (const c of candidatos) {
    if (c !== undefined && c !== null) {
      temCampoKEV = true;
      if (Array.isArray(c)) return c.length > 0;
      if (typeof c === 'boolean') return c;
      return Boolean(c);
    }
  }
  return null; // desconhecido, campo nao encontrado
}

function extraiCVE(m) {
  if (/^CVE-/.test(m.vulnerability?.id || '')) return m.vulnerability.id;
  const relacionada = (m.relatedVulnerabilities || []).find((r) => /^CVE-/.test(r.id || ''));
  return relacionada ? relacionada.id : m.vulnerability?.id || '(sem id)';
}

const vulnerabilidades = matches.map((m) => {
  const v = m.vulnerability || {};
  const art = m.artifact || {};
  const severidade = v.severity || 'Unknown';
  if (contagemSeveridade[severidade] === undefined) contagemSeveridade[severidade] = 0;
  contagemSeveridade[severidade] += 1;

  let correcao = 'Desconhecida';
  if (v.fix) {
    if (v.fix.state === 'fixed' && Array.isArray(v.fix.versions) && v.fix.versions.length) {
      correcao = `Sim (${v.fix.versions.join(', ')})`;
    } else if (v.fix.state === 'not-fixed') {
      correcao = 'Não';
    } else if (v.fix.state === 'wont-fix') {
      correcao = 'Não (sem intenção de corrigir)';
    }
  }

  return {
    componente: art.name || '(desconhecido)',
    versao: art.version || '(desconhecida)',
    cve: extraiCVE(m),
    severidade,
    correcao,
    kev: detectaKEV(m),
  };
});

const criticasAltas = vulnerabilidades
  .filter((v) => v.severidade === 'Critical' || v.severidade === 'High')
  .sort((a, b) => severidadeOrdem.indexOf(a.severidade) - severidadeOrdem.indexOf(b.severidade));

const algumaExploradaKEV = vulnerabilidades.some((v) => v.kev === true);

// --- 3b) Cross-check against the public CISA KEV catalogue and FIRST EPSS ---
const dataGeracao = new Date().toISOString().slice(0, 10);
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const KEV_LOCAL_PATH = path.join(ROOT, `kev-cisa-${dataGeracao}.json`);
const EPSS_LOCAL_PATH = path.join(ROOT, `epss-first-${dataGeracao}.json`);

const cvesUnicos = [...new Set(vulnerabilidades.map((v) => v.cve).filter((id) => /^CVE-/.test(id)))];

const kevPorCve = new Map();
let kevCatalogo = null;
let kevErro = null;
try {
  console.log('A descarregar o catálogo CISA KEV...');
  const respKev = await fetch(KEV_URL);
  if (!respKev.ok) throw new Error(`HTTP ${respKev.status}`);
  const kevTexto = await respKev.text();
  writeFileSync(KEV_LOCAL_PATH, kevTexto, 'utf8');
  kevCatalogo = JSON.parse(kevTexto);
  for (const entrada of kevCatalogo.vulnerabilities || []) {
    kevPorCve.set(entrada.cveID, entrada);
  }
  console.log(`KEV descarregado: ${kevCatalogo.count} entradas no total, gravado em ${KEV_LOCAL_PATH}`);
} catch (e) {
  kevErro = e.message;
  console.log(`Falha ao descarregar o KEV da CISA: ${kevErro}`);
}

const epssPorCve = new Map();
let epssErro = null;
if (cvesUnicos.length) {
  try {
    console.log(`A consultar EPSS da FIRST para ${cvesUnicos.length} CVE...`);
    // Em lotes de 100, limite por omissão da API pública do FIRST.
    const respostasEpss = [];
    for (let i = 0; i < cvesUnicos.length; i += 100) {
      const lote = cvesUnicos.slice(i, i + 100);
      const resp = await fetch(`${EPSS_URL}?cve=${lote.join(',')}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      respostasEpss.push(await resp.json());
    }
    writeFileSync(EPSS_LOCAL_PATH, JSON.stringify(respostasEpss, null, 2), 'utf8');
    for (const resposta of respostasEpss) {
      for (const item of resposta.data || []) {
        epssPorCve.set(item.cve, { epss: Number(item.epss), percentile: Number(item.percentile), date: item.date });
      }
    }
    console.log(`EPSS descarregado para ${epssPorCve.size} CVE, gravado em ${EPSS_LOCAL_PATH}`);
  } catch (e) {
    epssErro = e.message;
    console.log(`Falha ao consultar EPSS da FIRST: ${epssErro}`);
  }
}

for (const v of vulnerabilidades) {
  v.noKEV = kevPorCve.has(v.cve);
  v.kevInfo = kevPorCve.get(v.cve) || null;
  v.epssFirst = epssPorCve.get(v.cve) || null;
}

const vulnsPorCveUnico = new Map();
for (const v of vulnerabilidades) {
  if (!vulnsPorCveUnico.has(v.cve)) vulnsPorCveUnico.set(v.cve, v);
}
const vulnsUnicas = [...vulnsPorCveUnico.values()];
const cvesNoKEV = vulnsUnicas
  .filter((v) => v.noKEV)
  .sort((a, b) => (a.kevInfo.dateAdded < b.kevInfo.dateAdded ? 1 : -1));
const top10EPSS = vulnsUnicas
  .filter((v) => v.epssFirst)
  .sort((a, b) => b.epssFirst.epss - a.epssFirst.epss)
  .slice(0, 10);

// --- 4) Write relatorio.md ---

function linhaTabela(v) {
  const kevTexto = v.noKEV ? 'Sim' : 'Não';
  return `| ${v.componente} | ${v.versao} | ${v.cve} | ${v.severidade} | ${v.correcao} | ${kevTexto} |`;
}

const tabelaCriticasAltas = criticasAltas.length
  ? [
      '| Componente | Versão | CVE | Severidade | Correção disponível | No catálogo KEV (CISA) |',
      '| --- | --- | --- | --- | --- | --- |',
      ...criticasAltas.map(linhaTabela),
    ].join('\n')
  : 'Não foram encontradas vulnerabilidades com severidade Critical ou High.';

const resumoSeveridade = severidadeOrdem
  .filter((s) => contagemSeveridade[s] !== undefined)
  .map((s) => `- ${s}: ${contagemSeveridade[s]}`)
  .join('\n');

const tabelaKEV = kevErro
  ? `Não foi possível descarregar o catálogo CISA KEV nesta execução (erro: ${kevErro}). O cruzamento ficou por fazer.`
  : cvesNoKEV.length
    ? [
        `Dos ${cvesUnicos.length} CVE únicos encontrados pelo Grype, ${cvesNoKEV.length} constam do catálogo CISA KEV (fonte: ${KEV_URL}, catálogo versão ${kevCatalogo.catalogVersion}, consultado em ${dataGeracao}). Cópia local: kev-cisa-${dataGeracao}.json.`,
        '',
        '| CVE | Componente | Severidade (Grype) | Vulnerabilidade (nome CISA) | Data de adição ao KEV | Ação exigida pela CISA |',
        '| --- | --- | --- | --- | --- | --- |',
        ...cvesNoKEV.map(
          (v) =>
            `| ${v.cve} | ${v.componente} | ${v.severidade} | ${v.kevInfo.vulnerabilityName} | ${v.kevInfo.dateAdded} | ${v.kevInfo.requiredAction} |`
        ),
      ].join('\n')
    : `Dos ${cvesUnicos.length} CVE únicos encontrados pelo Grype, nenhum consta do catálogo CISA KEV (fonte: ${KEV_URL}, catálogo versão ${kevCatalogo.catalogVersion}, consultado em ${dataGeracao}). Cópia local: kev-cisa-${dataGeracao}.json.`;

const tabelaEPSS = epssErro
  ? `Não foi possível consultar o EPSS da FIRST nesta execução (erro: ${epssErro}). O cruzamento com o EPSS ficou por fazer.`
  : top10EPSS.length
    ? [
        `Pontuação EPSS (probabilidade de exploração nos próximos 30 dias) obtida na API pública da FIRST (${EPSS_URL}, consultado em ${dataGeracao}). Cópia local: epss-first-${dataGeracao}.json. As 10 CVE com EPSS mais alto entre as ${epssPorCve.size} consultadas com sucesso:`,
        '',
        '| CVE | Componente | Severidade (Grype) | EPSS | Percentil | No KEV |',
        '| --- | --- | --- | --- | --- | --- |',
        ...top10EPSS.map(
          (v) =>
            `| ${v.cve} | ${v.componente} | ${v.severidade} | ${v.epssFirst.epss.toFixed(5)} | ${v.epssFirst.percentile.toFixed(5)} | ${v.noKEV ? 'Sim' : 'Não'} |`
        ),
      ].join('\n')
    : 'Não foi possível obter pontuações EPSS para nenhum dos CVE identificados.';

const relatorio = `# Relatório de SBOM e vulnerabilidades — exemplo-NodeGoat

> Nota: este documento é o resultado de uma prova técnica para medir viabilidade e esforço de uma ferramenta de SBOM e análise de vulnerabilidades. Não constitui parecer jurídico nem substitui aconselhamento jurídico sobre o Cyber Resilience Act ou qualquer outro regulamento.

Data de geração: ${dataGeracao}
Alvo analisado: exemplo-NodeGoat (clone público do OWASP NodeGoat)
Ferramentas: Syft (geração de SBOM em CycloneDX) e Grype (varrimento de vulnerabilidades)

## 1. Resumo

- Total de componentes identificados no SBOM: ${totalComponentes}
- Total de vulnerabilidades reportadas pelo Grype: ${matches.length}

Vulnerabilidades por severidade:
${resumoSeveridade}

## 2. Vulnerabilidades críticas e altas

${tabelaCriticasAltas}

## 3. Cruzamento com vulnerabilidades ativamente exploradas (KEV da CISA)

${tabelaKEV}

Nota: o JSON produzido pelo Grype nesta instalação não inclui um campo próprio de KEV; o cruzamento acima foi feito diretamente contra o catálogo público da CISA, descarregado nesta execução (ver secção 6, Fontes).

## 3.1 Cruzamento com o EPSS (Exploit Prediction Scoring System) da FIRST

${tabelaEPSS}

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

- Catálogo CISA KEV (Known Exploited Vulnerabilities): ${KEV_URL}, consultado em ${dataGeracao}. Cópia local gravada em kev-cisa-${dataGeracao}.json.
- API pública EPSS da FIRST: ${EPSS_URL}, consultado em ${dataGeracao}. Cópia local gravada em epss-first-${dataGeracao}.json.
`;

writeFileSync(REPORT_PATH, relatorio, 'utf8');
console.log(`Relatório gravado em ${REPORT_PATH}`);

console.log('--- Tempos de execução (ms) ---');
console.log(JSON.stringify(timings, null, 2));
