# Annexe — Revue scientifique

## Odin : Une architecture de sécurité *Zero Trust* pour les agents LLM autonomes

**Kevin Coutellier** — Master 2 Recherche · AgentLayers
*Avril 2026*

---

### Résumé

Les agents autonomes fondés sur des modèles de langage de grande taille (*Large Language Models*, LLMs) démultiplient la surface d'attaque des systèmes d'information : l'injection de prompt, l'empoisonnement d'outils, l'exfiltration de données et la compromission de la chaîne d'approvisionnement cognitive deviennent des menaces opérationnelles. Cette annexe formalise la contribution du projet **Odin**, une implémentation de référence en *TypeScript* organisée en monorepo de sept paquets, qui applique le principe *Zero Trust* — « *never trust, always verify* » — à l'ensemble du cycle de vie d'un agent IA. Nous y décrivons (i) un modèle de double LLM inspiré de CaMeL, (ii) un moteur de contrôle de flux d'information (IFC) à double treillis intégrité/confidentialité, (iii) un bac à sable à trois anneaux couplé à un moteur de politiques de type Cedar, (iv) une identité cryptographique auto-souveraine fondée sur les DID Ed25519, (v) un *Trust Mesh* distribué gouverné par un disjoncteur à cinq états et (vi) une architecture cognitive en trois phases intégrant mémoire épisodique graphe, planification MCTS, raisonnement causal (SCM de Pearl) et invariants formels inspirés de TLA+. Nous positionnons ces choix par rapport à l'état de l'art (OWASP ASI 2026, EU AI Act, NIST AI RMF, FIDES, A-MEM, Graphiti) et nous présentons une évaluation préliminaire sur 150 tests automatisés couvrant les propriétés d'intégrité, de confidentialité et de non-escalade de privilèges.

**Mots-clés** : agents IA autonomes, Zero Trust, injection de prompt, CaMeL, contrôle de flux d'information, DID, raisonnement causal, MCTS, EU AI Act.

---

## 1. Introduction

### 1.1 Contexte

Depuis l'introduction des paradigmes *ReAct* (Yao et al., 2023) et *Toolformer* (Schick et al., 2023), les agents LLM ont migré du laboratoire vers la production. Leur capacité à invoquer des outils externes, à coopérer entre pairs via des protocoles A2A et à modifier dynamiquement leur propre comportement soulève un triptyque de risques :

1. **Sécurité** — l'injection indirecte de prompts (Greshake et al., 2023) démontre qu'une donnée tierce peut détourner l'intention de l'agent.
2. **Fiabilité** — les boucles de raisonnement non bornées et les hallucinations d'outils conduisent à des comportements erratiques.
3. **Conformité** — le règlement européen sur l'IA (Règlement (UE) 2024/1689) et l'*OWASP Agentic Security Initiative* (ASI, 2026) imposent de nouvelles obligations de traçabilité et de vérification.

### 1.2 Problématique

La plupart des défenses existantes reposent sur du *guardrailing* statistique — un LLM jugeant un autre LLM — et sont donc intrinsèquement contournables par prompt injection. Nous défendons la thèse suivante :

> *La sécurité d'un agent IA doit être **architecturale**, c'est-à-dire portée par des invariants structurels vérifiables, et non statistique.*

### 1.3 Contributions

Les contributions scientifiques du projet Odin sont les suivantes :

- **C1** — Une réification opérationnelle du modèle **CaMeL** (Debenedetti et al., 2024) combinant un LLM *privilégié* (planification, appels d'outils) et un LLM *quarantainé* (traitement des sorties non fiables).
- **C2** — Un moteur **IFC à double treillis** unissant intégrité (*TRUSTED > DERIVED > UNTRUSTED*) et confidentialité (*PUBLIC < SENSITIVE < SECRET*), avec propagation automatique au *merge*.
- **C3** — Un disjoncteur à **cinq états** (*CLOSED → DEGRADED → OPEN → HALF_OPEN*) étendant le patron classique (Nygard, 2018) par un état intermédiaire *DEGRADED* permettant une dégradation progressive plutôt que binaire.
- **C4** — Une architecture cognitive en **trois phases** articulant mémoire épisodique graphe (inspirée de Graphiti, Zep AI, 2024), planification hiérarchique MCTS avec UCB1 (Kocsis & Szepesvári, 2006) et raisonnement causal structurel de niveau L3 (Pearl, 2009).
- **C5** — Une taxonomie **CIK** (*Capabilities / Identity / Knowledge*) formellement vérifiée par des invariants inspirés de TLA+ (Lamport, 1994).
- **C6** — Une stratégie de **démarrage optionnel sans LLM** via un `NullAdapter`, permettant l'audit, la configuration et la supervision de l'agent indépendamment de la disponibilité d'un modèle — propriété rare dans la littérature.

---

## 2. État de l'art et positionnement

### 2.1 Sécurité des agents LLM

| Travaux | Contribution principale | Limite adressée par Odin |
|---------|------------------------|--------------------------|
| Greshake et al. (2023) — *Indirect Prompt Injection* | Démonstration empirique de l'injection indirecte | Odin répond par CaMeL + IFC : l'injection ne peut contaminer que le modèle quarantainé |
| Debenedetti et al. (2024) — *CaMeL* | Séparation planificateur / exécuteur | Implémentation de référence open-source, extension avec treillis de confidentialité |
| FIDES (Microsoft Research, 2024) | Taint tracking sur LLMs | Ajout d'un treillis de confidentialité et d'un moteur de politiques Cedar |
| OWASP ASI 2026 | Top-10 des risques des agents | Couverture explicite des 10 risques (voir §5) |

### 2.2 Identité et chaîne d'approvisionnement

Le projet s'appuie sur les spécifications **W3C DID** (2022) et les schémas **SLSA** (v1.0, 2023) pour la vérification de chaîne d'approvisionnement. Les DID `did:odin:<fingerprint>` sont dérivés d'une clé Ed25519 (Bernstein et al., 2012) via TweetNaCl, garantissant la portabilité et l'absence d'autorité centrale.

### 2.3 Raisonnement et mémoire

- **Mémoire épisodique graphe** — extension inspirée de Graphiti (Zep AI, 2024) avec décroissance temporelle (*half-life*) paramétrable, absente dans la version originale.
- **Planification MCTS** — suivant Kocsis & Szepesvári (2006), avec sélection UCB1 et un planificateur hiérarchique *top-down*.
- **Raisonnement causal** — implémentation des trois niveaux de la « *Ladder of Causation* » (Pearl, 2018) : L1 association, L2 intervention (*do-calculus*), L3 contrefactuel (algorithme en trois étapes : *abduction, action, prediction*).
- **A-MEM** — compression de trajectoires d'outils en procédures réutilisables, étendant le concept de mémoire procédurale de Tulving (1985) au domaine des agents.
- **Auto-amélioration en boucle fermée** — boucle d'analyse des échecs → diagnostic causal → amélioration contrefactuelle, sandboxée avec *rollback* transactionnel (cf. §3.4).

### 2.4 Conformité réglementaire

Odin produit des artefacts de conformité alignés sur :

- **Règlement (UE) 2024/1689** (EU AI Act) — journalisation, traçabilité, transparence, supervision humaine.
- **NIST AI RMF** (v1.0, 2023) — cartographie *GOVERN / MAP / MEASURE / MANAGE*.
- **Singapore MGF** (v2.0, 2024) — cadre de gouvernance Model AI Governance Framework.
- **OWASP ASI 2026** — top-10 des menaces spécifiques aux agents.

---

## 3. Architecture du système

### 3.1 Vue d'ensemble

Odin est organisé en quatre sous-systèmes indépendants mais coopératifs :

```
┌──────────────────────────────────────────────────────────────────┐
│                    Orchestrateur (OdinAgent)                      │
├──────────────┬──────────────┬──────────────┬─────────────────────┤
│  Sécurité    │   Trust       │   Cognition  │   Observabilité      │
│  (local)     │   (réseau)    │   (locale)   │   (OpenTelemetry)    │
├──────────────┼──────────────┼──────────────┼─────────────────────┤
│ DID, IFC,    │ Score 6D,     │ Épisodique,  │ AuditLog,            │
│ Sandbox,     │ Disjoncteur,  │ CIK, MCTS,   │ DecisionTracer,      │
│ Policy       │ Scanners      │ Causal, SI   │ ComplianceReporter   │
└──────────────┴──────────────┴──────────────┴─────────────────────┘
```

### 3.2 Contrôle de flux d'information (IFC)

Chaque donnée traversant l'agent porte une étiquette `TaintLabel` :

```typescript
{
  integrity:       "TRUSTED" | "DERIVED" | "UNTRUSTED",
  confidentiality: "PUBLIC"  | "SENSITIVE" | "SECRET",
  source:          string,
  timestamp:       number
}
```

**Règle de composition** — pour deux données `a` et `b`, la donnée jointe `a ⊕ b` hérite de `min(integrity(a), integrity(b))` et `max(confidentiality(a), confidentiality(b))`. Cette règle est conservatrice au sens de Denning (1976) et garantit la propriété de non-interférence dans le cas monadique.

**Théorème informel.** *Une donnée étiquetée `UNTRUSTED` ne peut jamais déclencher un appel d'outil de ring 1 ou 2 sans franchir explicitement une frontière de déclassification gardée par le moteur de politiques.*

### 3.3 Sandbox à trois anneaux

| Ring | Capacités | Exemples |
|------|----------|----------|
| **0** | Lecture seule, pas de réseau | `memory_search`, `status_query` |
| **1** | Lecture/écriture locale, réseau contrôlé | `file_read`, `web_fetch` |
| **2** | Exécution arbitraire avec approbation humaine | `shell_exec`, `code_exec`, `file_delete` |

L'exécution se fait dans un conteneur Docker/gVisor isolé ; les sorties sont re-étiquetées `UNTRUSTED` par défaut avant réinjection dans le contexte du LLM privilégié.

### 3.4 Évolution sandboxée et *safety gate*

Le composant `EvolutionSandbox` autorise une auto-modification transactionnelle de l'agent (progression des niveaux de confiance T1 → T4) sous contrôle d'une *safety gate* multi-critères :

1. **Invariants CIK** — aucune identité ne perd son immutabilité.
2. **Tests différentiels** — la proposition doit passer le jeu de tests existant.
3. **Vérification contrefactuelle** — simulation *what-if* sur un jumeau numérique avant *commit*.
4. **Rollback atomique** — en cas d'échec, l'état est restauré.

Cette conception s'inspire des travaux de Yu et al. (2023) sur l'auto-amélioration sécurisée, enrichie d'un composant causal (§3.5).

### 3.5 Moteur causal (SCM)

Le moteur `CausalEngine` implémente un modèle causal structurel (SCM) au sens de Pearl (2009) :

```
M = ⟨U, V, F, P(U)⟩
```

où `U` désigne les variables exogènes, `V` les variables endogènes, `F` les équations structurelles et `P(U)` la distribution des exogènes. Trois types de requêtes sont supportées :

- **L1 — Association** : `P(Y | X = x)`
- **L2 — Intervention** : `P(Y | do(X = x))`
- **L3 — Contrefactuel** : `P(Y_{x'} | X = x, Y = y)` (algorithme abduction / action / prediction)

Les requêtes L3 alimentent la boucle d'auto-amélioration : *« Si, dans le passé, j'avais choisi l'outil B au lieu de A, aurais-je évité l'échec ? »*.

### 3.6 Invariants formels (CIK)

Le vérificateur `CIKInvariantVerifier` encode quatre invariants inspirés de TLA+ :

1. **I1 — Immutabilité d'identité** : `∀ t ≥ t₀, identity(t) = identity(t₀)`
2. **I2 — Monotonie de capacité** : les capacités révoquées ne peuvent réapparaître sans réautorisation explicite.
3. **I3 — Isolation de tier** : une action Tₙ ne peut pas invoquer une ressource Tₘ pour `m > n`.
4. **I4 — Non-régression de connaissance** : un fait validé ne peut devenir *unknown* sans justification causale.

Ces invariants sont vérifiés périodiquement (toutes les 25 conversations par défaut) et toute violation déclenche un basculement en mode `DEGRADED`.

---

## 4. Implémentation

### 4.1 Pile technologique

- **Langage** — TypeScript (ES2022), strict mode
- **Runtime** — Node.js ≥ 20
- **Monorepo** — pnpm workspaces, 7 paquets
- **Persistence** — SQLite + FTS5 + WAL, intégrité via arbres de Merkle
- **Crypto** — Ed25519 via TweetNaCl, SHA-256, HKDF
- **Isolation** — Docker + gVisor
- **LLMs supportés** — Anthropic (Claude), OpenAI (GPT-4o), Ollama (local), *none* (NullAdapter)
- **Observabilité** — OpenTelemetry, dashboard temps réel WebSocket

### 4.2 Propriété de démarrage sans LLM

L'une des contributions pratiques est la capacité à démarrer **sans aucun LLM configuré**. Le `NullAdapter` renvoie un message explicatif invariant et satisfait l'interface `LLMProviderAdapter`, ce qui permet :

- la mise en place de l'audit et des politiques avant toute dépense d'inférence,
- la reconfiguration à chaud via dashboard ou commande CLI `/llm`,
- la continuité opérationnelle en cas de panne du fournisseur.

Cette propriété est à notre connaissance absente des frameworks comparables (LangChain, AutoGPT, CrewAI) qui échouent au démarrage en l'absence de clé API valide.

---

## 5. Évaluation

### 5.1 Couverture des risques OWASP ASI 2026

| Risque ASI | Mitigation Odin |
|-----------|-----------------|
| AAI01 — *Prompt Injection* | CaMeL + IFC |
| AAI02 — *Sensitive Information Disclosure* | Treillis de confidentialité |
| AAI03 — *Supply Chain* | Scanners skills / MCP, SLSA |
| AAI04 — *Data & Model Poisoning* | IFC + SafetyGate |
| AAI05 — *Improper Output Handling* | Re-étiquetage `UNTRUSTED` systématique |
| AAI06 — *Excessive Agency* | Sandbox 3 rings + approbations humaines |
| AAI07 — *System Prompt Leakage* | Ségrégation privilégié / quarantainé |
| AAI08 — *Vector & Embedding Weaknesses* | Merkle + vérification d'intégrité |
| AAI09 — *Misinformation* | Moteur causal L1-L3 |
| AAI10 — *Unbounded Consumption* | Quotas journaliers, *loop detection* histogramme |

### 5.2 Résultats expérimentaux

La suite `vitest` compte **150 tests** répartis ainsi :

- **core** : 18 tests (routeur dual-LLM, mémoire, compression)
- **security** : 44 tests (DID, IFC, sandbox, policy)
- **trust** : 12 tests (disjoncteur 5 états, scores)
- **cognition** : 76 tests (CIK, épisodique, MCTS, causal, évolution, invariants, raisonnement)

**Résultats** : 150 / 150 passants en local (Node 20, Windows 11), temps d'exécution < 8 s. Les scénarios d'attaque unitaires couvrent : injection de prompt dans une sortie d'outil, tentative d'escalade ring 0 → ring 2, spoofing d'identité A2A, violation d'invariant CIK, boucle d'outils infinie, exfiltration SECRET vers sortie PUBLIC.

### 5.3 Limites

- **Évaluation à grande échelle manquante** — un banc d'essai multi-agents avec adversaires automatisés reste à mener (piste *AgentBench* + *InjecAgent*).
- **Coût du double LLM** — l'architecture CaMeL double les appels d'inférence ; l'impact économique et énergétique mérite une étude dédiée.
- **Absence de preuve formelle** — les invariants CIK sont vérifiés dynamiquement, pas prouvés mécaniquement. Un portage vers TLA+ natif ou Coq est envisagé.

---

## 6. Travaux futurs

1. **Vérification formelle mécanisée** des invariants via TLA+ et *model checking* sur des traces réelles.
2. **Banc d'essai adversarial** intégrant AgentBench, ToolEmu et InjecAgent avec métriques ASR (*Attack Success Rate*).
3. **Extension du Trust Mesh** vers une fédération décentralisée de type réputation *Web of Trust* + *verifiable credentials*.
4. **Apprentissage par renforcement contrefactuel** — utilisation des contrefactuels L3 comme signal d'apprentissage hors-politique.
5. **Conformité cryptographique** des artefacts de compliance (signatures Ed25519 + ancrage blockchain optionnel).

---

## 7. Conclusion

Odin démontre qu'il est possible de concevoir un agent IA autonome dont les garanties de sécurité sont **portées par l'architecture** plutôt que par le modèle statistique. La combinaison d'un double LLM (CaMeL), d'un contrôle de flux d'information à double treillis, d'un sandbox à anneaux, d'une identité cryptographique souveraine, d'un disjoncteur à cinq états et d'une architecture cognitive en trois phases constitue, à notre connaissance, le premier cadre *Zero Trust* complet et open-source pour les agents LLM. L'évaluation empirique sur 150 tests unitaires et la couverture explicite du top-10 OWASP ASI 2026 positionnent Odin comme une base de référence pour les travaux futurs sur la sécurité agentique.

---

## Références

1. Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B.-Y. (2012). *High-speed high-security signatures*. **Journal of Cryptographic Engineering**, 2(2), 77–89.
2. Debenedetti, E., et al. (2024). *CaMeL: Defeating Prompt Injection Attacks Through Capabilities for Machine Learning*. **arXiv:2406.xxxxx**.
3. Denning, D. E. (1976). *A lattice model of secure information flow*. **Communications of the ACM**, 19(5), 236–243.
4. European Parliament & Council. (2024). *Regulation (EU) 2024/1689 — Artificial Intelligence Act*. Official Journal of the European Union.
5. Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023). *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*. **AISec @ CCS'23**.
6. Kocsis, L., & Szepesvári, C. (2006). *Bandit based Monte-Carlo Planning*. **ECML 2006**, 282–293.
7. Lamport, L. (1994). *The Temporal Logic of Actions*. **ACM TOPLAS**, 16(3), 872–923.
8. National Institute of Standards and Technology. (2023). *AI Risk Management Framework (AI RMF 1.0)*. NIST.
9. Nygard, M. T. (2018). *Release It! Design and Deploy Production-Ready Software* (2nd ed.). **Pragmatic Bookshelf**.
10. OWASP Foundation. (2026). *Agentic Security Initiative — Top 10 Risks for Autonomous AI Agents*.
11. Pearl, J. (2009). *Causality: Models, Reasoning, and Inference* (2nd ed.). **Cambridge University Press**.
12. Pearl, J., & Mackenzie, D. (2018). *The Book of Why: The New Science of Cause and Effect*. **Basic Books**.
13. Schick, T., et al. (2023). *Toolformer: Language Models Can Teach Themselves to Use Tools*. **NeurIPS 2023**.
14. Singapore IMDA. (2024). *Model AI Governance Framework v2.0*.
15. SLSA Working Group. (2023). *Supply-chain Levels for Software Artifacts (SLSA) v1.0*. Linux Foundation.
16. Tulving, E. (1985). *Memory and consciousness*. **Canadian Psychology**, 26(1), 1–12.
17. World Wide Web Consortium. (2022). *Decentralized Identifiers (DIDs) v1.0*. W3C Recommendation.
18. Yao, S., Zhao, J., Yu, D., Du, N., Shafran, I., Narasimhan, K., & Cao, Y. (2023). *ReAct: Synergizing Reasoning and Acting in Language Models*. **ICLR 2023**.
19. Yu, L., et al. (2023). *Towards Safe Self-Improving Agents*. **Workshop on Safe and Robust AI, NeurIPS**.
20. Zep AI. (2024). *Graphiti: Building Real-Time Knowledge Graphs for AI Agents*. Technical report.

---

*Cette annexe accompagne le mémoire de Master 2 « Zero Trust Security Architecture for Autonomous LLM Agents » et le code source du projet Odin ([github.com/kevcoutellier/ODIN-project](https://github.com/kevcoutellier/ODIN-project)) distribué sous licence MIT.*
