/**
 * EPIC K — Multi-agent consensus (N-of-M agreement) for high-risk actions.
 *
 * Certain actions are too dangerous for a single agent to authorize: deleting
 * data, sending payments, mass notifications. For these, require M-of-N agents
 * to independently agree the action is warranted. Each agent evaluates the
 * proposed action in isolation; only when ≥ M agree does it execute.
 *
 * The tool registry declares which tools are "high-risk" (require consensus)
 * via the `consensus` field.
 */

// Default quorum: high-risk tools need 2-of-3 independent evaluations.
const DEFAULT_QUORUM = { required: 2, evaluators: 3 };

/**
 * Run an N-of-M consensus check.
 *
 * @param {Function} evaluate  async (evaluatorIndex) => boolean  — each evaluator's independent verdict
 * @param {{required, evaluators}} quorum
 * @returns {Promise<{approved: boolean, votes: boolean[]}>}
 */
export async function consensus(evaluate, quorum = DEFAULT_QUORUM) {
  const votes = [];
  for (let i = 0; i < quorum.evaluators; i++) {
    try {
      votes.push(Boolean(await evaluate(i)));
    } catch {
      votes.push(false); // an evaluator that errors counts as a "no"
    }
  }
  const yes = votes.filter(Boolean).length;
  return { approved: yes >= quorum.required, votes, required: quorum.required };
}

/** Is a given tool high-risk (requires consensus)? */
export function isHighRisk(tool) {
  const HIGH_RISK = new Set((process.env.CONSENSUS_HIGH_RISK_TOOLS || "delete,payment,mass_notify").split(","));
  return HIGH_RISK.has(tool);
}
