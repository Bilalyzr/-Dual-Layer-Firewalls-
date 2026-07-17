/**
 * Loader for the prompt-injection attack battery.
 *
 *   import { allPrompts, byCategory, benignControls } from "../prompts/index.js";
 *
 * Works in Node (ESM) and bundlers. Keeps the JSON the single source of truth.
 */
import data from "./prompt_injection_attacks.json" with { type: "json" };

export const battery = data;

/** Every single-turn attack prompt flattened, tagged with its category + OWASP id. */
export const allPrompts = data.categories.flatMap((cat) => {
  const items = (cat.prompts || []).map((text) => ({
    text,
    category: cat.id,
    name: cat.name,
    owasp: cat.owasp,
    difficulty: cat.difficulty,
    kind: "single",
  }));
  const seqs = (cat.sequences || []).map((sequence, i) => ({
    text: sequence, // array of turns
    category: cat.id,
    name: cat.name,
    owasp: cat.owasp,
    difficulty: cat.difficulty,
    kind: "multi",
    seqIndex: i,
  }));
  return [...items, ...seqs];
});

/** Look up a category by id, e.g. byCategory("encoding_smuggling"). */
export function byCategory(id) {
  return data.categories.find((c) => c.id === id);
}

/** Benign control prompts (must NOT be blocked). */
export const benignControls = data.benign_control.prompts.map((text) => ({
  text,
  kind: "benign",
}));

export default data;
