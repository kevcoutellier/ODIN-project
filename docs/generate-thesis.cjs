const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat,
  HeadingLevel, BorderStyle, WidthType, ShadingType,
  PageNumber, PageBreak, TableOfContents,
} = require("docx");

// ─── Helpers ───
const ACCENT = "1F4E79";
const ACCENT2 = "2E75B6";
const GRAY = "4A4A4A";
const LIGHT_BG = "E8F0FE";
const TABLE_HEAD = "1F4E79";
const TABLE_HEAD_TEXT = "FFFFFF";
const PAGE_W = 11906; // A4
const PAGE_H = 16838;
const CONTENT_W = 9026; // A4 minus 1" margins

const border = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };

function h1(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 400, after: 200 }, children: [new TextRun({ text, bold: true, size: 32, font: "Calibri", color: ACCENT })] });
}
function h2(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 300, after: 150 }, children: [new TextRun({ text, bold: true, size: 26, font: "Calibri", color: ACCENT2 })] });
}
function h3(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 100 }, children: [new TextRun({ text, bold: true, size: 22, font: "Calibri", color: GRAY })] });
}
function p(text, opts = {}) {
  return new Paragraph({
    spacing: { after: 120, line: 360 },
    alignment: opts.align || AlignmentType.JUSTIFIED,
    children: [new TextRun({ text, size: 22, font: "Calibri", ...opts })],
  });
}
function pRuns(runs, opts = {}) {
  return new Paragraph({
    spacing: { after: 120, line: 360 },
    alignment: opts.align || AlignmentType.JUSTIFIED,
    children: runs.map(r => typeof r === "string" ? new TextRun({ text: r, size: 22, font: "Calibri" }) : new TextRun({ size: 22, font: "Calibri", ...r })),
  });
}
function italic(text) { return { text, italics: true }; }
function bold(text) { return { text, bold: true }; }

function makeTable(headers, rows, colWidths) {
  const totalW = colWidths.reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: totalW, type: WidthType.DXA },
    columnWidths: colWidths,
    rows: [
      new TableRow({
        tableHeader: true,
        children: headers.map((h, i) =>
          new TableCell({
            width: { size: colWidths[i], type: WidthType.DXA },
            borders,
            margins: cellMargins,
            shading: { fill: TABLE_HEAD, type: ShadingType.CLEAR },
            children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, size: 20, font: "Calibri", color: TABLE_HEAD_TEXT })] })],
          })
        ),
      }),
      ...rows.map(row =>
        new TableRow({
          children: row.map((cell, i) =>
            new TableCell({
              width: { size: colWidths[i], type: WidthType.DXA },
              borders,
              margins: cellMargins,
              shading: { fill: "FFFFFF", type: ShadingType.CLEAR },
              children: [new Paragraph({ children: [new TextRun({ text: cell, size: 20, font: "Calibri" })] })],
            })
          ),
        })
      ),
    ],
  });
}

function bulletItem(text, ref) {
  return new Paragraph({
    numbering: { reference: ref, level: 0 },
    spacing: { after: 80, line: 340 },
    children: [new TextRun({ text, size: 22, font: "Calibri" })],
  });
}
function numItem(text, ref) {
  return new Paragraph({
    numbering: { reference: ref, level: 0 },
    spacing: { after: 80, line: 340 },
    children: [new TextRun({ text, size: 22, font: "Calibri" })],
  });
}

// ─── BUILD DOCUMENT ───

const doc = new Document({
  styles: {
    default: {
      document: { run: { font: "Calibri", size: 22 } },
    },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 32, bold: true, font: "Calibri", color: ACCENT }, paragraph: { spacing: { before: 400, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 26, bold: true, font: "Calibri", color: ACCENT2 }, paragraph: { spacing: { before: 300, after: 150 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 22, bold: true, font: "Calibri", color: GRAY }, paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 2 } },
    ],
  },
  numbering: {
    config: [
      { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers2", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers3", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers4", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers5", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets2", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets3", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets4", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets5", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ],
  },
  footnotes: {
    1: { children: [new Paragraph({ children: [new TextRun({ text: "Pearl, J. (2009). Causality: Models, Reasoning, and Inference. Cambridge University Press.", size: 18, font: "Calibri" })] })] },
    2: { children: [new Paragraph({ children: [new TextRun({ text: "Debenedetti, E. et al. (2024). AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents. NeurIPS 2024.", size: 18, font: "Calibri" })] })] },
    3: { children: [new Paragraph({ children: [new TextRun({ text: "Microsoft Research. (2024). CaMeL: CApabilities for Machine Learning \u2014 a dual-LLM security architecture for AI agents.", size: 18, font: "Calibri" })] })] },
    4: { children: [new Paragraph({ children: [new TextRun({ text: "Kocsis, L. & Szepesv\u00e1ri, C. (2006). Bandit based Monte-Carlo Planning. ECML 2006.", size: 18, font: "Calibri" })] })] },
    5: { children: [new Paragraph({ children: [new TextRun({ text: "W3C. (2022). Decentralized Identifiers (DIDs) v1.0. W3C Recommendation.", size: 18, font: "Calibri" })] })] },
    6: { children: [new Paragraph({ children: [new TextRun({ text: "OWASP. (2025). OWASP Agentic Security Initiative (ASI) \u2014 Top 10 Risks for AI Agents.", size: 18, font: "Calibri" })] })] },
    7: { children: [new Paragraph({ children: [new TextRun({ text: "European Parliament. (2024). Regulation (EU) 2024/1689 \u2014 The EU AI Act.", size: 18, font: "Calibri" })] })] },
    8: { children: [new Paragraph({ children: [new TextRun({ text: "Lamport, L. (2002). Specifying Systems: The TLA+ Language and Tools for Hardware and Software Engineers. Addison-Wesley.", size: 18, font: "Calibri" })] })] },
  },
  sections: [
    // ═══ COVER PAGE ═══
    {
      properties: {
        page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } },
      },
      children: [
        new Paragraph({ spacing: { before: 3000 } }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 }, children: [new TextRun({ text: "ODIN", size: 72, bold: true, font: "Calibri", color: ACCENT })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [new TextRun({ text: "by AgentLayers", size: 32, font: "Calibri", color: ACCENT2 })] }),
        new Paragraph({ spacing: { after: 600 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "\u2500".repeat(40), size: 20, color: "CCCCCC" })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 }, children: [new TextRun({ text: "A Zero Trust AI Agent Architecture", size: 28, font: "Calibri", color: GRAY })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [new TextRun({ text: "Secured by Design, Trusted by Network", size: 24, font: "Calibri", italics: true, color: GRAY })] }),
        new Paragraph({ spacing: { before: 1200, after: 200 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "M\u00e9moire de Master 2 \u2014 Recherche en Intelligence Artificielle", size: 24, font: "Calibri" })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [new TextRun({ text: "Kevin COUTELLIER", size: 24, font: "Calibri", bold: true })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 600 }, children: [new TextRun({ text: "Avril 2026", size: 22, font: "Calibri", color: GRAY })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Licence MIT \u2014 Open Source", size: 20, font: "Calibri", color: GRAY })] }),
      ],
    },
    // ═══ TABLE OF CONTENTS ═══
    {
      properties: { page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "Odin \u2014 Zero Trust AI Agent", size: 18, font: "Calibri", italics: true, color: GRAY })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Page ", size: 18, font: "Calibri" }), new TextRun({ children: [PageNumber.CURRENT], size: 18, font: "Calibri" })] })] }) },
      children: [
        h1("Table des mati\u00e8res"),
        new TableOfContents("Table des mati\u00e8res", { hyperlink: true, headingStyleRange: "1-3" }),
        new Paragraph({ children: [new PageBreak()] }),

        // ═══ CHAPTER 1: INTRODUCTION ═══
        h1("1. Introduction"),
        h2("1.1 Contexte et motivation"),
        p("Les agents d\u2019intelligence artificielle (IA) ont connu une croissance exponentielle depuis l\u2019introduction des grands mod\u00e8les de langage (LLM). Ces agents autonomes sont capables d\u2019ex\u00e9cuter des outils, de communiquer avec d\u2019autres agents et de prendre des d\u00e9cisions complexes. Cependant, cette puissance s\u2019accompagne de risques de s\u00e9curit\u00e9 majeurs : injection de prompts, empoisonnement des sorties d\u2019outils, escalade de privil\u00e8ges et usurpation d\u2019identit\u00e9."),
        pRuns([
          "Les architectures d\u2019agents existantes fonctionnent selon un mod\u00e8le de ",
          italic("confiance implicite"),
          " : les r\u00e9sultats d\u2019outils sont consomm\u00e9s directement, les agents pairs sont consid\u00e9r\u00e9s comme honn\u00eates, et l\u2019injection de prompts peut d\u00e9tourner l\u2019ensemble du syst\u00e8me. Ce constat motive le d\u00e9veloppement d\u2019une architecture fond\u00e9e sur le principe du ",
          bold("Zero Trust"),
          " : \u00ab ne jamais faire confiance, toujours v\u00e9rifier \u00bb.",
        ]),

        h2("1.2 Contributions"),
        p("Ce m\u00e9moire pr\u00e9sente Odin, un framework open source (licence MIT) pour agents IA s\u00e9curis\u00e9s, dont les contributions principales sont :"),
        numItem("Un mod\u00e8le de s\u00e9curit\u00e9 Zero Trust complet adapt\u00e9 aux agents IA, int\u00e9grant le contr\u00f4le de flux d\u2019information (IFC), l\u2019isolation par anneaux de sandbox et l\u2019\u00e9valuation de politiques en temps r\u00e9el.", "numbers"),
        numItem("Une architecture cognitive en trois phases combinant m\u00e9moire \u00e9pisodique, raisonnement causal (SCM de Pearl) et planification hi\u00e9rarchique (MCTS).", "numbers"),
        numItem("Un protocole Agent-to-Agent (A2A) avec v\u00e9rification cryptographique par identit\u00e9 d\u00e9centralis\u00e9e (DID) et credentials \u00e9ph\u00e9m\u00e8res.", "numbers"),
        numItem("Un disjoncteur \u00e0 5 \u00e9tats (circuit breaker) innovant avec d\u00e9tection des d\u00e9faillances s\u00e9mantiques.", "numbers"),
        numItem("Une impl\u00e9mentation compl\u00e8te valid\u00e9e par 150 tests automatis\u00e9s couvrant les 7 packages du monorepo.", "numbers"),

        h2("1.3 Organisation du document"),
        p("Ce document est organis\u00e9 comme suit. Le chapitre 2 pr\u00e9sente l\u2019\u00e9tat de l\u2019art en s\u00e9curit\u00e9 des agents IA. Le chapitre 3 d\u00e9taille l\u2019architecture syst\u00e8me d\u2019Odin. Le chapitre 4 d\u00e9crit le mod\u00e8le de s\u00e9curit\u00e9 Zero Trust. Le chapitre 5 pr\u00e9sente l\u2019architecture cognitive. Le chapitre 6 d\u00e9crit le protocole A2A. Le chapitre 7 pr\u00e9sente les r\u00e9sultats exp\u00e9rimentaux. Le chapitre 8 conclut et propose des perspectives."),
        new Paragraph({ children: [new PageBreak()] }),

        // ═══ CHAPTER 2: STATE OF THE ART ═══
        h1("2. \u00c9tat de l\u2019art"),
        h2("2.1 Agents IA et grands mod\u00e8les de langage"),
        pRuns([
          "Les agents IA bas\u00e9s sur les LLM, tels que AutoGPT, LangChain Agents ou Claude Computer Use, d\u00e9montrent des capacit\u00e9s remarquables en planification et ex\u00e9cution d\u2019outils. Cependant, des travaux r\u00e9cents comme AgentDojo",
          { children: [new (require("docx").FootnoteReferenceRun)(2)], size: 22 },
          " montrent que ces syst\u00e8mes sont vuln\u00e9rables aux attaques par injection indirecte de prompts, o\u00f9 des instructions malveillantes sont int\u00e9gr\u00e9es dans les donn\u00e9es retourn\u00e9es par les outils.",
        ]),

        h2("2.2 S\u00e9curit\u00e9 des agents IA"),
        pRuns([
          "Le mod\u00e8le CaMeL (CApabilities for Machine Learning)",
          { children: [new (require("docx").FootnoteReferenceRun)(3)], size: 22 },
          " de Microsoft Research propose une architecture \u00e0 double LLM o\u00f9 les contr\u00f4les de s\u00e9curit\u00e9 sont ex\u00e9cut\u00e9s sur un mod\u00e8le privil\u00e9gi\u00e9 s\u00e9par\u00e9, emp\u00eachant l\u2019injection de prompts de d\u00e9tourner l\u2019ex\u00e9cution d\u2019outils. Odin adapte ce mod\u00e8le dans un contexte Zero Trust.",
        ]),
        p("L\u2019OWASP Agentic Security Initiative (ASI) identifie les 10 principaux risques pour les agents IA, incluant l\u2019ex\u00e9cution non autoris\u00e9e d\u2019outils, la compromission de la cha\u00eene d\u2019approvisionnement et la manipulation de la confiance inter-agents."),

        h2("2.3 Confiance et identit\u00e9 d\u00e9centralis\u00e9e"),
        pRuns([
          "Les Decentralized Identifiers (DID)",
          { children: [new (require("docx").FootnoteReferenceRun)(5)], size: 22 },
          " du W3C fournissent un cadre pour l\u2019identit\u00e9 auto-souveraine des agents. Chaque agent g\u00e9n\u00e8re sa propre paire de cl\u00e9s cryptographiques et publie un DID Document contenant sa cl\u00e9 publique et ses capacit\u00e9s.",
        ]),

        h2("2.4 Raisonnement causal pour les agents"),
        pRuns([
          "Pearl",
          { children: [new (require("docx").FootnoteReferenceRun)(1)], size: 22 },
          " d\u00e9finit trois niveaux de raisonnement causal : l\u2019association (L1), l\u2019intervention via le do-calculus (L2) et le contrefactuel (L3). Ces niveaux sont essentiels pour permettre \u00e0 un agent d\u2019apprendre de ses erreurs et d\u2019am\u00e9liorer ses d\u00e9cisions de mani\u00e8re autonome.",
        ]),
        new Paragraph({ children: [new PageBreak()] }),

        // ═══ CHAPTER 3: SYSTEM ARCHITECTURE ═══
        h1("3. Architecture syst\u00e8me"),
        h2("3.1 Vue d\u2019ensemble"),
        p("Odin est construit comme un monorepo TypeScript organis\u00e9 en 7 packages ind\u00e9pendants, orchestr\u00e9s par un agent central. Chaque package correspond \u00e0 un sous-syst\u00e8me fonctionnel avec des interfaces clairement d\u00e9finies."),
        makeTable(
          ["Package", "R\u00f4le", "Composants principaux"],
          [
            ["@odin/core", "Types, routage LLM, m\u00e9moire", "DualLLMRouter, MemoryStore, MerkleTree"],
            ["@odin/security", "P\u00e9rim\u00e8tre de s\u00e9curit\u00e9", "DIDManager, IFCEngine, PolicyEngine, SandboxManager"],
            ["@odin/trust", "R\u00e9seau de confiance", "AgentLayersClient, TrustScoreManager, CircuitBreaker"],
            ["@odin/cognition", "Architecture cognitive", "EpisodicStore, CIK, MCTS, CausalEngine, Evolution"],
            ["@odin/cli", "Orchestrateur, gateways, A2A", "OdinAgent, TelegramGateway, DiscordGateway, A2AServer"],
            ["@odin/dashboard", "Interface temps r\u00e9el", "DashboardServer (WebSocket)"],
            ["@odin/observability", "Audit et tra\u00e7abilit\u00e9", "AuditLog, DecisionTracer, ComplianceReporter"],
          ],
          [2200, 2800, 4026],
        ),

        h2("3.2 Principes de conception"),
        bulletItem("Identity-First : chaque instance poss\u00e8de un DID unique (Ed25519). Toutes les actions sont sign\u00e9es cryptographiquement.", "bullets"),
        bulletItem("Least Privilege : les outils s\u2019ex\u00e9cutent dans des anneaux de sandbox (Ring 0-2) avec tra\u00e7age de teinte des entr\u00e9es/sorties.", "bullets"),
        bulletItem("Continuous Verification : les scores de confiance sont calcul\u00e9s \u00e0 partir de m\u00e9triques temps r\u00e9el, pas de configurations statiques.", "bullets"),
        bulletItem("Defense in Depth : quatre sous-syst\u00e8mes ind\u00e9pendants (S\u00e9curit\u00e9, Confiance, Cognition, Observabilit\u00e9) fournissent des couches de protection superpos\u00e9es.", "bullets"),

        h2("3.3 Pipeline de traitement des messages"),
        p("Lorsqu\u2019un utilisateur envoie un message, celui-ci traverse un pipeline de 8 \u00e9tapes :"),
        numItem("\u00c9tiquetage IFC : le message est marqu\u00e9 TRUSTED (source de confiance directe).", "numbers2"),
        numItem("Recalcul du mode de confiance \u00e0 partir des m\u00e9triques temps r\u00e9el.", "numbers2"),
        numItem("Gestion de session (r\u00e9initialisation idle/daily).", "numbers2"),
        numItem("Compression de contexte optionnelle (\u00e0 75% de la limite).", "numbers2"),
        numItem("Planification LLM privil\u00e9gi\u00e9 (g\u00e9n\u00e9ration des appels d\u2019outils).", "numbers2"),
        numItem("Pipeline d\u2019ex\u00e9cution d\u2019outils : profil, d\u00e9tection de boucles, approbation, validation IFC, politique Cedar, ex\u00e9cution sandbox.", "numbers2"),
        numItem("Int\u00e9gration cognitive : compression A-MEM, auto-\u00e9volution, cycle d\u2019am\u00e9lioration, v\u00e9rification des invariants.", "numbers2"),
        numItem("R\u00e9ponse et synchronisation du tableau de bord.", "numbers2"),
        new Paragraph({ children: [new PageBreak()] }),

        // ═══ CHAPTER 4: SECURITY MODEL ═══
        h1("4. Mod\u00e8le de s\u00e9curit\u00e9 Zero Trust"),
        h2("4.1 Mod\u00e8le de menaces"),
        p("Odin identifie sept cat\u00e9gories de menaces sp\u00e9cifiques aux agents IA :"),
        makeTable(
          ["Menace", "Vecteur d\u2019attaque", "Mitigation Odin"],
          [
            ["Injection de prompt", "Instructions malveillantes dans les entr\u00e9es ou les sorties d\u2019outils", "Architecture dual-LLM (CaMeL)"],
            ["Empoisonnement des sorties", "Outil compromis retournant des donn\u00e9es malveillantes", "Tra\u00e7age de teinte IFC"],
            ["Escalade de privil\u00e8ges", "Agent obtenant des capacit\u00e9s non autoris\u00e9es", "Sandbox 3 anneaux + politique Cedar"],
            ["Usurpation d\u2019identit\u00e9", "Agent se faisant passer pour un autre", "DID Ed25519 + messages sign\u00e9s"],
            ["Exfiltration de donn\u00e9es", "Fuite de donn\u00e9es sensibles via les appels d\u2019outils", "Treillis de confidentialit\u00e9"],
            ["Attaque supply chain", "Skills ou serveurs MCP malveillants", "Scan AgentLayers + SLSA"],
            ["Attaque par agent pair", "Agents pairs non fiables ou malveillants", "Disjoncteur 5 \u00e9tats + score de confiance"],
          ],
          [2000, 3200, 3826],
        ),

        h2("4.2 Architecture dual-LLM (CaMeL)"),
        pRuns([
          "Odin impl\u00e9mente le mod\u00e8le CaMeL",
          { children: [new (require("docx").FootnoteReferenceRun)(3)], size: 22 },
          " avec deux mod\u00e8les LLM s\u00e9par\u00e9s. Le ",
          bold("mod\u00e8le privil\u00e9gi\u00e9"),
          " voit le contexte complet de la conversation et planifie les appels d\u2019outils. Le ",
          bold("mod\u00e8le en quarantaine"),
          " ne traite que les donn\u00e9es \u00e9tiquet\u00e9es par teinte et ne peut pas invoquer d\u2019outils directement. Cette s\u00e9paration emp\u00eache l\u2019injection de prompts de d\u00e9tourner l\u2019ex\u00e9cution d\u2019outils.",
        ]),

        h2("4.3 Contr\u00f4le de flux d\u2019information (IFC)"),
        h3("4.3.1 Treillis d\u2019int\u00e9grit\u00e9"),
        p("Chaque donn\u00e9e porte une \u00e9tiquette de teinte (TaintLabel) avec un niveau d\u2019int\u00e9grit\u00e9 : TRUSTED > DERIVED > UNTRUSTED. Lors de la combinaison de sources multiples, la sortie h\u00e9rite de l\u2019int\u00e9grit\u00e9 la plus basse, emp\u00eachant les donn\u00e9es teint\u00e9es d\u2019escalader les privil\u00e8ges."),
        h3("4.3.2 Treillis de confidentialit\u00e9"),
        p("De mani\u00e8re sym\u00e9trique, la confidentialit\u00e9 suit le treillis PUBLIC < SENSITIVE < SECRET. La combinaison h\u00e9rite de la confidentialit\u00e9 la plus \u00e9lev\u00e9e."),

        h2("4.4 Anneaux de sandbox"),
        p("Les outils s\u2019ex\u00e9cutent dans l\u2019un des trois anneaux d\u2019isolation :"),
        makeTable(
          ["Anneau", "Acc\u00e8s", "Timeout", "M\u00e9moire", "Teinte de sortie"],
          [
            ["Ring 0", "Lecture seule, pas de r\u00e9seau", "5s", "64 MB", "UNTRUSTED"],
            ["Ring 1", "Lecture/\u00e9criture limit\u00e9e, r\u00e9seau contr\u00f4l\u00e9", "30s", "256 MB", "UNTRUSTED"],
            ["Ring 2", "Acc\u00e8s complet (approbation requise)", "60s", "512 MB", "H\u00e9rit\u00e9 de l\u2019entr\u00e9e"],
          ],
          [1200, 3000, 1200, 1200, 2426],
        ),

        h2("4.5 Moteur de politiques Cedar"),
        p("Le moteur de politiques \u00e9value les d\u00e9cisions de contr\u00f4le d\u2019acc\u00e8s en temps sub-milliseconde. Le contexte de politique inclut : identit\u00e9 de l\u2019agent (DID), action demand\u00e9e, ressource cible, score de confiance, TTL de session, nombre d\u2019appels quotidiens, statut d\u2019approbation humaine, anneau de sandbox et \u00e9tiquette de teinte."),
        p("Quatre politiques par d\u00e9faut sont appliqu\u00e9es : seuil de score de confiance (< 40 = bloqu\u00e9), limite de d\u00e9bit (> 1000 appels/jour = bloqu\u00e9), Ring 2 requiert une approbation humaine, et expiration de session."),

        h2("4.6 Identit\u00e9 d\u00e9centralis\u00e9e (DID)"),
        pRuns([
          "Chaque instance Odin g\u00e9n\u00e8re une identit\u00e9 unique did:odin:<empreinte> bas\u00e9e sur une paire de cl\u00e9s Ed25519. Le DID Document est conforme au standard W3C",
          { children: [new (require("docx").FootnoteReferenceRun)(5)], size: 22 },
          " et contient la m\u00e9thode de v\u00e9rification, les capacit\u00e9s et le score de confiance. Pour la d\u00e9l\u00e9gation de t\u00e2ches (A2A), Odin \u00e9met des ",
          bold("credentials \u00e9ph\u00e9m\u00e8res \u00e0 port\u00e9e d\u2019intention"),
          " (Intent-Scoped Ephemeral Credentials) qui sont sign\u00e9s, limit\u00e9s dans le temps et r\u00e9vocables.",
        ]),
        new Paragraph({ children: [new PageBreak()] }),

        // ═══ CHAPTER 5: COGNITIVE ARCHITECTURE ═══
        h1("5. Architecture cognitive"),
        p("L\u2019architecture cognitive d\u2019Odin est construite en trois phases progressives, chacune ajoutant des capacit\u00e9s de raisonnement et d\u2019autonomie suppl\u00e9mentaires."),

        h2("5.1 Phase 1 : Fondation"),
        h3("5.1.1 M\u00e9moire \u00e9pisodique (graphe)"),
        p("Odin maintient une m\u00e9moire \u00e9pisodique bas\u00e9e sur un graphe stock\u00e9 en SQLite. Les entit\u00e9s repr\u00e9sentent des concepts nomm\u00e9s avec des types, des compteurs d\u2019observation et une d\u00e9croissance temporelle. Les ar\u00eates repr\u00e9sentent des relations typ\u00e9es entre entit\u00e9s avec des poids. Le parcours BFS (Breadth-First Search) du voisinage permet le rappel associatif."),
        p("Innovation cl\u00e9 : la d\u00e9croissance temporelle avec demi-vie configurable. Les entit\u00e9s non renforc\u00e9es par de nouvelles observations s\u2019estompent progressivement, emp\u00eachant la surcharge m\u00e9moire tout en pr\u00e9servant les connaissances fr\u00e9quemment utilis\u00e9es."),

        h3("5.1.2 Taxonomie CIK"),
        p("La taxonomie CIK (Capabilities, Identity, Knowledge) constitue le mod\u00e8le d\u2019auto-conscience de l\u2019agent. Les Capacit\u00e9s d\u00e9finissent ce que l\u2019agent peut faire (avec niveau de confiance et contraintes). L\u2019Identit\u00e9 d\u00e9finit qui est l\u2019agent (DID, tier de confiance, immutabilit\u00e9). La Connaissance d\u00e9finit ce que l\u2019agent sait (faits avec confiance, source, contradictions)."),

        h3("5.1.3 Raisonnement Model-First"),
        p("Le ModelFirstReasoner maintient un mod\u00e8le du monde interne \u2014 un ensemble de croyances sur l\u2019\u00e9tat actuel de l\u2019environnement. Avant chaque action, le raisonneur g\u00e9n\u00e8re des pr\u00e9dictions. Apr\u00e8s l\u2019action, les pr\u00e9dictions sont compar\u00e9es \u00e0 la r\u00e9alit\u00e9 : les \u00e9carts d\u00e9clenchent l\u2019apprentissage."),

        h2("5.2 Phase 2 : Autonomie"),
        h3("5.2.1 Agent de sommeil (SleepAgent)"),
        p("Inspir\u00e9 de la consolidation biologique de la m\u00e9moire, le SleepAgent s\u2019ex\u00e9cute pendant les p\u00e9riodes d\u2019inactivit\u00e9 pour fusionner les entit\u00e9s dupliqu\u00e9es, \u00e9laguer les souvenirs faibles, extraire les patterns r\u00e9currents et r\u00e9soudre les contradictions de connaissance."),

        h3("5.2.2 Sandbox d\u2019\u00e9volution"),
        p("Odin peut modifier son propre comportement \u00e0 travers un m\u00e9canisme d\u2019\u00e9volution contr\u00f4l\u00e9. La progression T1 \u2192 T2 \u2192 T3 \u2192 T4 est prot\u00e9g\u00e9e par un SafetyGate : pas de saut de tier, preuves requises, rollback automatique en cas d\u2019\u00e9chec."),

        h3("5.2.3 Contr\u00f4leur A-MEM"),
        p("Le contr\u00f4leur Augmented Memory convertit l\u2019exp\u00e9rience brute en proc\u00e9dures r\u00e9utilisables. Les trajectoires (s\u00e9quences d\u2019appels d\u2019outils) sont enregistr\u00e9es puis compress\u00e9es en r\u00e9sum\u00e9s proc\u00e9duraux stock\u00e9s pour les t\u00e2ches futures similaires."),

        h2("5.3 Phase 3 : Raisonnement avanc\u00e9"),
        h3("5.3.1 Planificateur hi\u00e9rarchique MCTS"),
        pRuns([
          "Odin utilise le Monte Carlo Tree Search (MCTS)",
          { children: [new (require("docx").FootnoteReferenceRun)(4)], size: 22 },
          " pour la planification multi-\u00e9tapes. L\u2019algorithme suit quatre phases : S\u00e9lection (UCB1), Expansion, Simulation (rollout) et R\u00e9tropropagation. Les objectifs de haut niveau se d\u00e9composent en sous-objectifs, chacun avec son propre arbre MCTS.",
        ]),

        h3("5.3.2 Moteur de raisonnement causal"),
        pRuns([
          "Odin impl\u00e9mente les trois niveaux de la hi\u00e9rarchie causale de Pearl",
          { children: [new (require("docx").FootnoteReferenceRun)(1)], size: 22 },
          " via des Mod\u00e8les Causaux Structurels (SCM) :",
        ]),
        bulletItem("Niveau 1 \u2014 Association : P(Y|X), propagation par tri topologique.", "bullets2"),
        bulletItem("Niveau 2 \u2014 Intervention : P(Y|do(X)), do-calculus par mutilation de graphe.", "bullets2"),
        bulletItem("Niveau 3 \u2014 Contrefactuel : algorithme en 3 \u00e9tapes de Pearl (Abduction, Action, Pr\u00e9diction).", "bullets2"),
        p("Application : apr\u00e8s un \u00e9chec d\u2019outil, le CausalEngine construit un mod\u00e8le de d\u00e9faillance et ex\u00e9cute des requ\u00eates contrefactuelles pour g\u00e9n\u00e9rer des am\u00e9liorations actionnables."),

        h3("5.3.3 Invariants formels TLA+"),
        pRuns([
          "Six invariants inspir\u00e9s de TLA+",
          { children: [new (require("docx").FootnoteReferenceRun)(8)], size: 22 },
          " v\u00e9rifient en continu les propri\u00e9t\u00e9s de s\u00e9curit\u00e9 du CIK :",
        ]),
        makeTable(
          ["Invariant", "S\u00e9v\u00e9rit\u00e9", "V\u00e9rification"],
          [
            ["KNOWLEDGE_CONSISTENCY", "Warning", "Confiance dans [0, 1]"],
            ["CONFIDENCE_BOUNDS", "Error", "Pas de valeurs hors limites"],
            ["TIER_CONFIDENCE_ALIGNMENT", "Warning", "Tiers sup\u00e9rieurs = confiance minimale plus \u00e9lev\u00e9e"],
            ["TEMPORAL_ORDERING", "Error", "Timestamps non dans le futur"],
            ["IDENTITY_IMMUTABILITY", "Critical", "DID inchang\u00e9 depuis l\u2019initialisation"],
            ["KNOWLEDGE_CONTRADICTION_RATIO", "Warning", "Contradictions < 10% des connaissances"],
          ],
          [3200, 1200, 4626],
        ),

        h3("5.3.4 Boucle d\u2019auto-am\u00e9lioration contrefactuelle"),
        p("Le syst\u00e8me d\u2019am\u00e9lioration en boucle ferm\u00e9e apprend continuellement des \u00e9checs. Les cinq sources de d\u00e9faillance (tool_failure, prediction_error, evolution_rejected, plan_failure, invariant_violation) alimentent une analyse causale qui g\u00e9n\u00e8re des insights contrefactuels appliqu\u00e9s au CIK, au mod\u00e8le du monde et au sandbox d\u2019\u00e9volution."),
        new Paragraph({ children: [new PageBreak()] }),

        // ═══ CHAPTER 6: A2A PROTOCOL ═══
        h1("6. Protocole Agent-to-Agent (A2A)"),
        h2("6.1 D\u00e9couverte d\u2019agents"),
        p("Chaque instance Odin expose un AgentCard \u00e0 l\u2019endpoint /.well-known/agent.json, contenant son nom, DID, description, capacit\u00e9s, endpoints (A2A et health), score de confiance et signature Ed25519."),

        h2("6.2 Types de messages"),
        p("Le protocole d\u00e9finit huit types de messages :"),
        makeTable(
          ["Type", "Direction", "Fonction"],
          [
            ["task/send", "\u2192 Peer", "D\u00e9l\u00e9guer une t\u00e2che avec credentials \u00e9ph\u00e9m\u00e8res"],
            ["task/result", "\u2190 Peer", "Retourner le r\u00e9sultat d\u2019ex\u00e9cution"],
            ["task/status", "\u2192 Peer", "Interroger la progression d\u2019une t\u00e2che"],
            ["task/cancel", "\u2192 Peer", "Annuler une t\u00e2che en cours"],
            ["peer/discover", "\u2194", "D\u00e9couverte mutuelle d\u2019agents"],
            ["peer/heartbeat", "\u2192 Peer", "Keep-alive avec score de confiance"],
            ["trust/query", "\u2192 Peer", "Interroger la r\u00e9putation d\u2019un pair"],
            ["trust/report", "\u2192 R\u00e9seau", "Signaler un incident de confiance"],
          ],
          [2200, 1600, 5226],
        ),

        h2("6.3 Propri\u00e9t\u00e9s de s\u00e9curit\u00e9"),
        p("Chaque message A2A est encapsul\u00e9 dans une enveloppe contenant la version du protocole, le type, un identifiant unique, les DID source et destination, un horodatage ISO et une signature Ed25519 du payload. Les propri\u00e9t\u00e9s de s\u00e9curit\u00e9 garanties sont :"),
        numItem("Chaque message est sign\u00e9 avec la cl\u00e9 Ed25519 de l\u2019exp\u00e9diteur.", "numbers3"),
        numItem("Les AgentCards des pairs sont v\u00e9rifi\u00e9s via le Trust Mesh AgentLayers.", "numbers3"),
        numItem("Les disjoncteurs prot\u00e8gent contre les pairs non fiables.", "numbers3"),
        numItem("Les credentials \u00e9ph\u00e9m\u00e8res sont limit\u00e9s \u00e0 la t\u00e2che et au temps.", "numbers3"),
        numItem("Toutes les interactions A2A sont audit\u00e9es.", "numbers3"),

        h2("6.4 Disjoncteur \u00e0 5 \u00e9tats"),
        p("Innovation par rapport aux disjoncteurs classiques \u00e0 3 \u00e9tats, Odin ajoute un \u00e9tat DEGRADED pour une fonctionnalit\u00e9 partielle gracieuse. Les transitions sont : CLOSED \u2192 DEGRADED (seuil de d\u00e9gradation), DEGRADED \u2192 OPEN (seuil de d\u00e9faillance), OPEN \u2192 HALF_OPEN (timeout de r\u00e9cup\u00e9ration), HALF_OPEN \u2192 CLOSED (2 succ\u00e8s cons\u00e9cutifs)."),
        pRuns([
          "Innovation suppl\u00e9mentaire : la ",
          bold("d\u00e9tection de d\u00e9faillances s\u00e9mantiques"),
          ". Une r\u00e9ponse HTTP 200 OK contenant un contenu hallucin\u00e9 est d\u00e9tect\u00e9e via un validateur s\u00e9mantique et compte comme une double d\u00e9faillance.",
        ]),
        new Paragraph({ children: [new PageBreak()] }),

        // ═══ CHAPTER 7: EXPERIMENTAL RESULTS ═══
        h1("7. R\u00e9sultats exp\u00e9rimentaux"),
        h2("7.1 Impl\u00e9mentation"),
        p("Odin est impl\u00e9ment\u00e9 en TypeScript (ECMAScript modules) sous forme de monorepo g\u00e9r\u00e9 par pnpm. Le code source totalise environ 5 000 lignes r\u00e9parties sur 7 packages. L\u2019ensemble du projet est open source sous licence MIT."),

        makeTable(
          ["M\u00e9trique", "Valeur"],
          [
            ["Langage", "TypeScript (ES Modules)"],
            ["Packages", "7 (monorepo pnpm)"],
            ["Tests automatis\u00e9s", "150 tests (14 fichiers)"],
            ["Taux de r\u00e9ussite", "100% (150/150)"],
            ["Temps d\u2019ex\u00e9cution des tests", "~7 secondes"],
            ["Framework de test", "Vitest v3.2"],
            ["Runtime", "Node.js 20+"],
            ["CI/CD", "GitHub Actions (Node 20 + 22)"],
            ["Conteneurisation", "Docker multi-stage"],
          ],
          [4000, 5026],
        ),

        h2("7.2 Couverture des tests"),
        p("La suite de tests couvre les composants critiques de chaque sous-syst\u00e8me :"),
        makeTable(
          ["Fichier de test", "Package", "Tests", "Composants test\u00e9s"],
          [
            ["features.test.ts", "@odin/core", "34", "ModelFallbackChain, SmartRouting, ContextCompressor, LoopDetector, SessionManager"],
            ["memory.test.ts", "@odin/core", "11", "MemoryStore, MerkleTree, FTS5 search, injection sanitization"],
            ["ifc.test.ts", "@odin/security", "8", "IFCEngine: \u00e9tiquetage, propagation, validation"],
            ["policy.test.ts", "@odin/security", "5", "PolicyEngine: deny default, trust score, rate limit, benchmark"],
            ["did.test.ts", "@odin/security", "6", "DIDManager: g\u00e9n\u00e9ration, signature, v\u00e9rification, credentials"],
            ["sandbox.test.ts", "@odin/security", "5", "SandboxManager: rings, erreurs, teinte, timeout"],
            ["circuit-breaker.test.ts", "@odin/trust", "9", "CircuitBreaker: 5 \u00e9tats, s\u00e9mantique, m\u00e9triques"],
            ["episodic.test.ts", "@odin/cognition", "12", "EpisodicStore: entit\u00e9s, ar\u00eates, BFS, \u00e9pisodes, d\u00e9croissance"],
            ["cik.test.ts", "@odin/cognition", "18", "CIK: politiques, capacit\u00e9s, identit\u00e9, connaissance, \u00e9volution"],
            ["reasoning.test.ts", "@odin/cognition", "10", "ModelFirstReasoner: monde, observations, plans, contrefactuels"],
            ["mcts.test.ts", "@odin/cognition", "9", "MCTS: planification, statistiques, profondeur, objectifs"],
            ["causal.test.ts", "@odin/cognition", "10", "CausalEngine: SCM, DAG, L1/L2/L3, mod\u00e8les de d\u00e9faillance"],
            ["invariants.test.ts", "@odin/cognition", "7", "CIKInvariantVerifier: sant\u00e9, DID, temporel, invariants custom"],
            ["evolution.test.ts", "@odin/cognition", "6", "SafetyGate, EvolutionSandbox: blocage, preuves, rollback"],
          ],
          [2400, 1800, 700, 4126],
        ),

        h2("7.3 Performance du moteur de politiques"),
        p("Le moteur de politiques Cedar atteint une \u00e9valuation en temps sub-milliseconde. Un benchmark de 1 000 \u00e9valuations cons\u00e9cutives avec contexte complet (DID, action, ressource, score de confiance, anneau, \u00e9tiquette de teinte) produit un temps moyen inf\u00e9rieur \u00e0 1 ms par \u00e9valuation, valid\u00e9 par le test policy.test.ts."),

        h2("7.4 Conformit\u00e9 r\u00e9glementaire"),
        pRuns([
          "Odin int\u00e8gre un framework de conformit\u00e9 couvrant quatre standards majeurs : EU AI Act",
          { children: [new (require("docx").FootnoteReferenceRun)(7)], size: 22 },
          " (transparence, supervision humaine), OWASP ASI",
          { children: [new (require("docx").FootnoteReferenceRun)(6)], size: 22 },
          " (10 risques pour les agents IA), Singapore Model Governance Framework et SLSA (niveaux 0-4 pour la cha\u00eene d\u2019approvisionnement logicielle).",
        ]),
        new Paragraph({ children: [new PageBreak()] }),

        // ═══ CHAPTER 8: CONCLUSION ═══
        h1("8. Conclusion et perspectives"),
        h2("8.1 Synth\u00e8se"),
        p("Ce m\u00e9moire a pr\u00e9sent\u00e9 Odin, une architecture Zero Trust pour agents IA qui apporte des contributions significatives dans trois domaines : la s\u00e9curit\u00e9 par conception (IFC, sandbox, politique Cedar, DID), l\u2019intelligence cognitive en trois phases (m\u00e9moire \u00e9pisodique, raisonnement causal, planification MCTS), et la communication inter-agents s\u00e9curis\u00e9e (protocole A2A avec v\u00e9rification cryptographique)."),
        p("L\u2019impl\u00e9mentation compl\u00e8te, valid\u00e9e par 150 tests automatis\u00e9s avec un taux de r\u00e9ussite de 100%, d\u00e9montre la faisabilit\u00e9 d\u2019une architecture Zero Trust pour les agents IA sans compromis sur les capacit\u00e9s cognitives."),

        h2("8.2 Perspectives"),
        p("Plusieurs directions de recherche s\u2019ouvrent :"),
        bulletItem("Connecteurs gateway : impl\u00e9mentation compl\u00e8te des gateways Slack et WhatsApp, et int\u00e9gration avec des \u00e9cosyst\u00e8mes d\u2019agents existants.", "bullets3"),
        bulletItem("Client MCP : int\u00e9gration compl\u00e8te du protocole Model Context Protocol pour l\u2019acc\u00e8s \u00e0 des outils externes.", "bullets3"),
        bulletItem("Validation formelle : preuve formelle des propri\u00e9t\u00e9s de s\u00e9curit\u00e9 du CIK via TLA+ Toolbox ou Alloy.", "bullets3"),
        bulletItem("\u00c9valuation adversariale : benchmark syst\u00e9matique avec AgentDojo et d\u2019autres frameworks d\u2019attaque pour les agents IA.", "bullets3"),
        bulletItem("R\u00e9seau de confiance distribu\u00e9 : d\u00e9ploiement multi-agents avec le protocole A2A en conditions r\u00e9elles pour mesurer la r\u00e9silience du Trust Mesh.", "bullets3"),
        bulletItem("Apprentissage causal en ligne : am\u00e9lioration du moteur SCM pour supporter l\u2019apprentissage continu des \u00e9quations causales \u00e0 partir des observations.", "bullets3"),
        new Paragraph({ children: [new PageBreak()] }),

        // ═══ REFERENCES ═══
        h1("R\u00e9f\u00e9rences"),
        p("[1] Pearl, J. (2009). Causality: Models, Reasoning, and Inference. 2nd Edition. Cambridge University Press."),
        p("[2] Debenedetti, E. et al. (2024). AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents. NeurIPS 2024."),
        p("[3] Microsoft Research. (2024). CaMeL: CApabilities for Machine Learning \u2014 a dual-LLM security architecture for AI agents."),
        p("[4] Kocsis, L. & Szepesv\u00e1ri, C. (2006). Bandit based Monte-Carlo Planning. ECML 2006, pp. 282-293."),
        p("[5] W3C. (2022). Decentralized Identifiers (DIDs) v1.0. W3C Recommendation."),
        p("[6] OWASP. (2025). OWASP Agentic Security Initiative (ASI) \u2014 Top 10 Risks for AI Agents."),
        p("[7] European Parliament. (2024). Regulation (EU) 2024/1689 \u2014 The EU AI Act."),
        p("[8] Lamport, L. (2002). Specifying Systems: The TLA+ Language and Tools for Hardware and Software Engineers. Addison-Wesley."),
        p("[9] Bernstein, D.J. et al. (2012). High-speed high-security signatures. Journal of Cryptographic Engineering, 2(2), pp. 77-89. (Ed25519)"),
        p("[10] Google. (2025). Agent2Agent (A2A) Protocol Specification. Open protocol for agent interoperability."),
        p("[11] Amazon Web Services. (2024). Cedar Policy Language \u2014 Authorization policy language and engine."),
        p("[12] SLSA. (2024). Supply-chain Levels for Software Artifacts \u2014 Framework for software supply chain security."),
      ],
    },
  ],
});

// ─── Generate ───
const outputPath = process.argv[2] || "thesis_odin_zero_trust_agent.docx";
Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPath, buffer);
  console.log(`Thesis generated: ${outputPath} (${(buffer.length / 1024).toFixed(0)} KB)`);
});
