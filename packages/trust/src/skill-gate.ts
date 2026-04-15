/**
 * Skill Gate — Two-tier skill verification
 *
 * Level 1 (free, local): Basic static analysis
 * Level 2 (paid, AgentLayers): Deep security scan + reputation
 *
 * Skills get a trust tier (0/1/2) that determines their sandbox ring.
 */

import type { SkillManifest, SkillTrustTier, SandboxRing } from '@odin/core';
import type { AgentLayersClient, SkillScanResult } from './agentlayers-client.js';
import { runAstChecks } from './ast-checker.js';

export interface SkillGateDecision {
  allowed: boolean;
  trustTier: SkillTrustTier;
  ring: SandboxRing;
  localChecks: LocalCheckResult[];
  agentLayersScan: SkillScanResult | null;
  reason: string;
}

export interface LocalCheckResult {
  check: string;
  passed: boolean;
  details: string;
}

/**
 * Legacy regex patterns — only used as a fallback when AST parsing fails
 * (e.g. the source is TypeScript or uses syntax acorn doesn't understand).
 * For the canonical detection path see `ast-checker.ts`.
 */
const INJECTION_PATTERNS = [
  /eval\s*\(/i,
  /exec\s*\(/i,
  /child_process/i,
  /process\.env/i,
  /require\s*\(\s*['"]fs['"]\s*\)/i,
  /import\s+.*from\s+['"]fs['"]/i,
  /\bfetch\b.*\bhttp:/i, // non-HTTPS fetch
  /__proto__/i,
  /constructor\s*\[/i,
];

const UNDECLARED_NETWORK_PATTERNS = [
  /fetch\s*\(/i,
  /XMLHttpRequest/i,
  /\.ajax\s*\(/i,
  /net\.connect/i,
  /dgram\.createSocket/i,
];

export class SkillGate {
  constructor(private agentLayersClient: AgentLayersClient) {}

  /**
   * Full skill verification pipeline.
   */
  async verify(manifest: SkillManifest, sourceCode?: string): Promise<SkillGateDecision> {
    // Level 1: Local checks (always run, free)
    const localChecks = this.runLocalChecks(manifest, sourceCode);
    const localPassed = localChecks.every(c => c.passed);

    // If local checks fail hard, block immediately
    const criticalFailures = localChecks.filter(c => !c.passed && c.check.startsWith('CRITICAL'));
    if (criticalFailures.length > 0) {
      return {
        allowed: false,
        trustTier: 0,
        ring: 0,
        localChecks,
        agentLayersScan: null,
        reason: `Blocked by local checks: ${criticalFailures.map(c => c.details).join(', ')}`,
      };
    }

    // Level 2: AgentLayers scan (if available)
    const agentLayersScan = await this.agentLayersClient.scanSkill(manifest);

    if (agentLayersScan) {
      // Use AgentLayers decision
      if (agentLayersScan.decision === 'BLOCK') {
        return {
          allowed: false,
          trustTier: 0,
          ring: 0,
          localChecks,
          agentLayersScan,
          reason: `Blocked by AgentLayers: score ${agentLayersScan.score}/100`,
        };
      }

      const trustTier = this.determineTrustTier(manifest, agentLayersScan);
      return {
        allowed: true,
        trustTier,
        ring: trustTier as SandboxRing,
        localChecks,
        agentLayersScan,
        reason: agentLayersScan.decision === 'ASK'
          ? `Requires user approval (score: ${agentLayersScan.score})`
          : `Approved (score: ${agentLayersScan.score})`,
      };
    }

    // Fallback: local-only decision
    const trustTier: SkillTrustTier = manifest.signature ? 1 : 0;
    return {
      allowed: localPassed,
      trustTier,
      ring: trustTier as SandboxRing,
      localChecks,
      agentLayersScan: null,
      reason: localPassed
        ? `Local checks passed (no AgentLayers scan). Tier ${trustTier}`
        : `Local checks failed (no AgentLayers scan)`,
    };
  }

  private runLocalChecks(manifest: SkillManifest, sourceCode?: string): LocalCheckResult[] {
    const checks: LocalCheckResult[] = [];

    // Check: valid manifest structure
    checks.push({
      check: 'CRITICAL:manifest-valid',
      passed: !!(manifest.name && manifest.version && manifest.description),
      details: 'Manifest must have name, version, and description',
    });

    // Check: no excessive permissions
    const allPermissions = manifest.tools.flatMap(t => t.requiredPermissions);
    const dangerousPerms = allPermissions.filter(p =>
      ['shell', 'exec', 'system', 'root', 'admin'].some(d => p.toLowerCase().includes(d))
    );
    checks.push({
      check: 'permissions-safe',
      passed: dangerousPerms.length === 0,
      details: dangerousPerms.length > 0
        ? `Dangerous permissions requested: ${dangerousPerms.join(', ')}`
        : 'No dangerous permissions',
    });

    // Check: signature present
    checks.push({
      check: 'signature-present',
      passed: !!manifest.signature,
      details: manifest.signature ? 'Ed25519 signature present' : 'No signature (Tier 0)',
    });

    // Source code analysis (if provided)
    if (sourceCode) {
      // Prefer AST-based detection; fall back to regex only on parse errors.
      const ast = runAstChecks(sourceCode);
      if (ast.parseOk) {
        checks.push({
          check: 'CRITICAL:no-injection-patterns',
          passed: ast.findings.length === 0,
          details:
            ast.findings.length > 0
              ? `Injection patterns detected: ${ast.findings
                  .map(f => `${f.rule}@L${f.line}`)
                  .join(', ')}`
              : 'No injection patterns detected (AST)',
        });
      } else {
        const injectionMatches = INJECTION_PATTERNS.filter(p => p.test(sourceCode));
        checks.push({
          check: 'CRITICAL:no-injection-patterns',
          passed: injectionMatches.length === 0,
          details:
            injectionMatches.length > 0
              ? `Injection patterns detected (regex fallback): ${injectionMatches
                  .map(p => p.source)
                  .join(', ')}`
              : 'No injection patterns detected (regex fallback)',
        });
      }

      // Check: no undeclared network access (regex-based — out of scope for AST work)
      const hasNetworkPerms = allPermissions.some(p => p.toLowerCase().includes('network'));
      const networkPatterns = UNDECLARED_NETWORK_PATTERNS.filter(p => p.test(sourceCode));
      checks.push({
        check: 'network-declared',
        passed: networkPatterns.length === 0 || hasNetworkPerms,
        details: networkPatterns.length > 0 && !hasNetworkPerms
          ? 'Network access detected but not declared in permissions'
          : 'Network usage consistent with declared permissions',
      });
    }

    return checks;
  }

  private determineTrustTier(manifest: SkillManifest, scan: SkillScanResult): SkillTrustTier {
    if (manifest.signature && scan.score >= 70) return 2; // signed + scanned SAFE
    if (scan.score >= 70) return 1; // scanned SAFE
    return 0;
  }
}
