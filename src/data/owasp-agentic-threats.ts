/**
 * Threat IDs from the OWASP Agentic Security Initiative taxonomy.
 *
 * Source: OWASP GenAI Security Project, "Agentic AI - Threats and Mitigations",
 * Version 1.1, December 2025, Detailed Threat Model table (T1-T17).
 * https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
 * The document is licensed CC BY-SA 4.0. Only the threat IDs and names are
 * reproduced here; see the document for descriptions and mitigations.
 *
 * Version 1.0 (February 2025) listed T1-T15. Version 1.1 added T16 and T17.
 */

export const OWASP_AGENTIC_SOURCE = {
  title: 'Agentic AI - Threats and Mitigations',
  publisher: 'OWASP GenAI Security Project, Agentic Security Initiative',
  version: '1.1',
  date: '2025-12',
  url: 'https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/',
  license: 'CC BY-SA 4.0',
} as const;

export const OWASP_AGENTIC_THREATS = {
  T1: 'Memory Poisoning',
  T2: 'Tool Misuse',
  T3: 'Privilege Compromise',
  T4: 'Resource Overload',
  T5: 'Cascading Hallucination Attacks',
  T6: 'Intent Breaking & Goal Manipulation',
  T7: 'Misaligned & Deceptive Behaviors',
  T8: 'Repudiation & Untraceability',
  T9: 'Identity Spoofing & Impersonation / Agent Identity Compromise',
  T10: 'Overwhelming Human in the Loop',
  T11: 'Unexpected RCE and Code Attacks',
  T12: 'Agent Communication Poisoning',
  T13: 'Rogue Agents in Multi-Agent Systems',
  T14: 'Human Attacks on Multi-Agent Systems',
  T15: 'Human Manipulation',
  T16: 'Insecure Inter-Agent Protocol Abuse',
  T17: 'Supply Chain Compromise',
} as const;

export type OwaspAgenticThreatId = keyof typeof OWASP_AGENTIC_THREATS;

/**
 * Entries from the OWASP Top 10 for LLM Applications 2025, for threats the
 * agentic taxonomy defers to it (the agentic document itself points to
 * LLM04:2025 for data poisoning).
 */
export const OWASP_LLM_TOP10_2025 = {
  'LLM02:2025': 'Sensitive Information Disclosure',
  'LLM04:2025': 'Data and Model Poisoning',
  'LLM07:2025': 'System Prompt Leakage',
} as const;

export type OwaspLlmTop10Id = keyof typeof OWASP_LLM_TOP10_2025;
