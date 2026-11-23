import { describe, it, expect } from 'vitest';
import { OWASP_AGENTIC_SOURCE, OWASP_AGENTIC_THREATS, OWASP_LLM_TOP10_2025 } from '@/data/owasp-agentic-threats';
import { OWASP_CROSSWALK, owaspAgenticIdsFor } from '@/data/validation/owasp-crosswalk';
import { THREAT_FAMILY_IDS } from '../schema';

describe('OWASP agentic threat taxonomy', () => {
  it('lists T1 to T17 from version 1.1', () => {
    expect(Object.keys(OWASP_AGENTIC_THREATS)).toEqual(Array.from({ length: 17 }, (_, i) => `T${i + 1}`));
    expect(OWASP_AGENTIC_SOURCE.version).toBe('1.1');
    expect(OWASP_AGENTIC_SOURCE.url).toMatch(/^https:\/\/genai\.owasp\.org\//);
  });
});

describe('OWASP crosswalk for validation threat families', () => {
  it('covers every threat family', () => {
    expect(Object.keys(OWASP_CROSSWALK).sort()).toEqual([...THREAT_FAMILY_IDS].sort());
  });

  it('uses only known IDs and never lists an ID as both primary and related', () => {
    for (const [family, entry] of Object.entries(OWASP_CROSSWALK)) {
      for (const id of [...entry.primary, ...entry.related]) expect(id in OWASP_AGENTIC_THREATS, `${family} ${id}`).toBe(true);
      for (const id of entry.llmTop10) expect(id in OWASP_LLM_TOP10_2025, `${family} ${id}`).toBe(true);
      expect(entry.primary.filter((id) => entry.related.includes(id))).toEqual([]);
    }
  });

  it('maps every family to at least one OWASP entry, with a rationale', () => {
    for (const [family, entry] of Object.entries(OWASP_CROSSWALK)) {
      expect(entry.primary.length + entry.related.length + entry.llmTop10.length, family).toBeGreaterThan(0);
      expect(entry.rationale.length).toBeGreaterThan(20);
    }
  });

  it('maps the delegation family to privilege compromise and inter-agent delegation abuse', () => {
    expect(owaspAgenticIdsFor('delegation_escalation')).toEqual(['T3', 'T14', 'T8', 'T16']);
  });
});
