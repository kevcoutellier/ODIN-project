/**
 * Information Flow Control (IFC) Engine
 * Dual-lattice taint tracking inspired by FIDES (Microsoft)
 *
 * Every piece of data carries two labels:
 * - Integrity: TRUSTED > DERIVED > UNTRUSTED
 * - Confidentiality: SECRET > SENSITIVE > PUBLIC
 *
 * Rules:
 * - Outputs inherit the LOWEST integrity of their inputs
 * - Outputs inherit the HIGHEST confidentiality of their inputs
 * - Escalation (UNTRUSTED → TRUSTED) requires explicit validation
 * - Policies are auto-generated from the agent's capability manifest
 */

import type {
  TaintLabel,
  IntegrityLevel,
  ConfidentialityLevel,
  TaintedData,
} from '@odin/core';

const INTEGRITY_ORDER: Record<string, number> = {
  TRUSTED: 2,
  DERIVED: 1,
  UNTRUSTED: 0,
};

const CONFIDENTIALITY_ORDER: Record<string, number> = {
  PUBLIC: 0,
  SENSITIVE: 1,
  SECRET: 2,
};

export type EscalationValidator = (
  data: TaintedData,
  targetIntegrity: IntegrityLevel,
) => Promise<boolean>;

export interface IFCViolation {
  type: 'integrity_escalation' | 'confidentiality_leak' | 'taint_violation';
  from: TaintLabel;
  to: TaintLabel;
  context: string;
  timestamp: number;
}

export class IFCEngine {
  private violations: IFCViolation[] = [];
  private escalationValidators: EscalationValidator[] = [];

  /**
   * Create a TRUSTED label (for user input).
   */
  createTrustedLabel(source: string): TaintLabel {
    return {
      integrity: 'TRUSTED' as IntegrityLevel,
      confidentiality: 'PUBLIC' as ConfidentialityLevel,
      source,
      timestamp: Date.now(),
    };
  }

  /**
   * Create an UNTRUSTED label (for external data).
   */
  createUntrustedLabel(source: string): TaintLabel {
    return {
      integrity: 'UNTRUSTED' as IntegrityLevel,
      confidentiality: 'PUBLIC' as ConfidentialityLevel,
      source,
      timestamp: Date.now(),
    };
  }

  /**
   * Wrap data with a taint label.
   */
  taint<T>(value: T, label: TaintLabel): TaintedData<T> {
    return { value, label };
  }

  /**
   * Propagate taint through a computation.
   * Output gets: lowest integrity, highest confidentiality.
   */
  propagate(inputs: TaintLabel[], source: string): TaintLabel {
    if (inputs.length === 0) {
      return this.createTrustedLabel(source);
    }

    const lowestIntegrity = inputs.reduce((min, label) =>
      INTEGRITY_ORDER[label.integrity] < INTEGRITY_ORDER[min.integrity] ? label : min
    );

    const highestConfidentiality = inputs.reduce((max, label) =>
      CONFIDENTIALITY_ORDER[label.confidentiality] > CONFIDENTIALITY_ORDER[max.confidentiality] ? label : max
    );

    return {
      integrity: lowestIntegrity.integrity,
      confidentiality: highestConfidentiality.confidentiality,
      source,
      timestamp: Date.now(),
    };
  }

  /**
   * Check if data can flow from source to destination.
   * Integrity flows DOWN (trusted → untrusted ok, reverse blocked).
   * Confidentiality flows DOWN (secret → public blocked, reverse ok).
   */
  canFlow(from: TaintLabel, to: TaintLabel): boolean {
    const integrityOk = INTEGRITY_ORDER[from.integrity] >= INTEGRITY_ORDER[to.integrity];
    const confidentialityOk = CONFIDENTIALITY_ORDER[from.confidentiality] <= CONFIDENTIALITY_ORDER[to.confidentiality];
    return integrityOk && confidentialityOk;
  }

  /**
   * Attempt to escalate integrity. Requires validation.
   */
  async escalate(
    data: TaintedData,
    targetIntegrity: IntegrityLevel,
    context: string,
  ): Promise<{ allowed: boolean; newLabel: TaintLabel }> {
    const currentLevel = INTEGRITY_ORDER[data.label.integrity];
    const targetLevel = INTEGRITY_ORDER[targetIntegrity];

    // Downgrade is always allowed
    if (targetLevel <= currentLevel) {
      return {
        allowed: true,
        newLabel: { ...data.label, integrity: targetIntegrity },
      };
    }

    // Escalation requires ALL validators to approve
    for (const validator of this.escalationValidators) {
      const approved = await validator(data, targetIntegrity);
      if (!approved) {
        this.recordViolation({
          type: 'integrity_escalation',
          from: data.label,
          to: { ...data.label, integrity: targetIntegrity },
          context,
          timestamp: Date.now(),
        });
        return { allowed: false, newLabel: data.label };
      }
    }

    return {
      allowed: true,
      newLabel: {
        ...data.label,
        integrity: targetIntegrity,
        source: `escalated:${context}`,
        timestamp: Date.now(),
      },
    };
  }

  /**
   * Validate a tool call: check that tool input integrity
   * is compatible with the tool's required trust level.
   */
  validateToolCall(
    inputLabel: TaintLabel,
    requiredIntegrity: IntegrityLevel,
    toolName: string,
  ): { allowed: boolean; violation?: IFCViolation } {
    if (INTEGRITY_ORDER[inputLabel.integrity] >= INTEGRITY_ORDER[requiredIntegrity]) {
      return { allowed: true };
    }

    const violation: IFCViolation = {
      type: 'taint_violation',
      from: inputLabel,
      to: {
        integrity: requiredIntegrity,
        confidentiality: inputLabel.confidentiality,
        source: `tool:${toolName}`,
        timestamp: Date.now(),
      },
      context: `Tool "${toolName}" requires ${requiredIntegrity} but received ${inputLabel.integrity}`,
      timestamp: Date.now(),
    };

    this.recordViolation(violation);
    return { allowed: false, violation };
  }

  registerEscalationValidator(validator: EscalationValidator): void {
    this.escalationValidators.push(validator);
  }

  getViolations(): IFCViolation[] {
    return [...this.violations];
  }

  clearViolations(): void {
    this.violations = [];
  }

  private recordViolation(violation: IFCViolation): void {
    this.violations.push(violation);
    if (this.violations.length > 1000) {
      this.violations = this.violations.slice(-1000);
    }
  }
}
