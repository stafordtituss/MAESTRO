/**
 * Crosswalk from the validation module's threat families (Table 5 of CSA's
 * "Agentic AI Identity and Access Management: A New Approach") to OWASP threat
 * IDs. The mapping is a proposal of this module, not an OWASP or CSA mapping.
 *
 * `primary`: the OWASP threat the family is an instance of.
 * `related`: threats the family's scenarios also exercise (for example, the
 * evidence dimension exercises T8, Repudiation & Untraceability).
 * `llmTop10`: used where the agentic taxonomy defers to the LLM Top 10.
 */
import type { ThreatFamily } from '@/lib/validation/schema';
import type { OwaspAgenticThreatId, OwaspLlmTop10Id } from '@/data/owasp-agentic-threats';

export interface OwaspCrosswalkEntry {
  primary: readonly OwaspAgenticThreatId[];
  related: readonly OwaspAgenticThreatId[];
  llmTop10: readonly OwaspLlmTop10Id[];
  rationale: string;
}

export const OWASP_CROSSWALK: Record<ThreatFamily, OwaspCrosswalkEntry> = {
  did_spoofing: {
    primary: ['T9'],
    related: [],
    llmTop10: [],
    rationale: 'Impersonating an agent with a forged or unbound identity is agent identity compromise.',
  },
  vc_replay: {
    primary: ['T9'],
    related: ['T3'],
    llmTop10: [],
    rationale: 'Replaying a captured credential misuses another party’s identity to gain its privileges.',
  },
  ephemeral_agent_abuse: {
    primary: ['T4'],
    related: ['T8', 'T13'],
    llmTop10: [],
    rationale:
      'Spawning many short-lived agents overloads resources and evades per-agent limits; spreading activity across identities also hinders attribution.',
  },
  delegation_escalation: {
    primary: ['T3', 'T14'],
    related: ['T8', 'T16'],
    llmTop10: [],
    rationale:
      'Chained delegation that widens scope is privilege compromise through inter-agent delegation; the evidence dimension tests traceability, and delegation often crosses agent protocols.',
  },
  prompt_injection: {
    primary: ['T6'],
    related: ['T2'],
    llmTop10: [],
    rationale: 'Instructions injected through tool output redirect the agent’s goals and drive tool calls outside its scope.',
  },
  data_poisoning: {
    primary: [],
    related: ['T1'],
    llmTop10: ['LLM04:2025'],
    rationale:
      'The agentic taxonomy defers dataset poisoning to LLM04:2025; T1 covers the related case of poisoned agent memory.',
  },
  model_inversion: {
    primary: [],
    related: [],
    llmTop10: ['LLM02:2025', 'LLM07:2025'],
    rationale:
      'Extracting model artifacts or system prompts is not a separate threat in the agentic taxonomy; the LLM Top 10 covers it as information disclosure and system prompt leakage.',
  },
};

/** All OWASP agentic threat IDs a family maps to, primary first. */
export function owaspAgenticIdsFor(family: ThreatFamily): OwaspAgenticThreatId[] {
  const entry = OWASP_CROSSWALK[family];
  return [...entry.primary, ...entry.related];
}
