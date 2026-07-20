/**
 * JSON Schemas for Trifecta agent outputs (Req 2.2, 2.3).
 *
 * The Reader-Agent MUST emit JSON conforming to READER_OUTPUT. The Actor-Agent
 * receives validated JSON and emits a TOOL_CALL envelope conforming to one of
 * the per-tool ACTION schemas. The Validator checks against these.
 *
 * We use a tiny subset of JSON Schema (type, properties, required, enum,
 * items, additionalProperties:false) — enough to enforce structure without
 * pulling in ajv. validator.js implements the matching checker.
 */

const READER_OUTPUT = {
  type: "object",
  required: ["summary", "intent", "confidence"],
  additionalProperties: false,
  properties: {
    // Natural-language-free structured summary of the untrusted content.
    summary: { type: "string", minLength: 1, maxLength: 500 },
    // Classified intent — must be one of the known safe intents.
    intent: {
      type: "string",
      enum: ["informational", "summarize", "translate", "classify", "unknown"],
    },
    // Reader's confidence in its own classification (0..1).
    confidence: { type: "number", minimum: 0, maximum: 1 },
    // Optional: fields the Reader extracted (e.g. names, dates). String values only.
    fields: {
      type: "object",
      additionalProperties: { type: "string" },
    },
  },
};

// Per-tool ACTION schemas. The Actor emits one of these envelopes.
const ACTION_LOOKUP = {
  type: "object",
  required: ["tool", "args"],
  additionalProperties: false,
  properties: {
    tool: { type: "string", enum: ["lookup"] },
    args: {
      type: "object",
      required: ["query"],
      additionalProperties: false,
      properties: { query: { type: "string", minLength: 1, maxLength: 120 } },
    },
    reason: { type: "string", maxLength: 200 },
  },
};

const ACTION_SUMMARIZE = {
  type: "object",
  required: ["tool", "args"],
  additionalProperties: false,
  properties: {
    tool: { type: "string", enum: ["summarize"] },
    args: {
      type: "object",
      required: ["topic"],
      additionalProperties: false,
      properties: { topic: { type: "string", minLength: 1, maxLength: 120 } },
    },
    reason: { type: "string", maxLength: 200 },
  },
};

const ACTION_NOTIFY = {
  type: "object",
  required: ["tool", "args"],
  additionalProperties: false,
  properties: {
    tool: { type: "string", enum: ["notify"] },
    args: {
      type: "object",
      required: ["message"],
      additionalProperties: false,
      properties: {
        message: { type: "string", minLength: 1, maxLength: 280 },
        channel: { type: "string", enum: ["email", "sms", "dashboard"] },
      },
    },
    reason: { type: "string", maxLength: 200 },
  },
};

// Map tool name -> action schema (used by the Validator + Actor).
const ACTION_SCHEMAS = {
  lookup: ACTION_LOOKUP,
  summarize: ACTION_SUMMARIZE,
  notify: ACTION_NOTIFY,
};

export {
  READER_OUTPUT,
  ACTION_SCHEMAS,
  ACTION_LOOKUP,
  ACTION_SUMMARIZE,
  ACTION_NOTIFY,
};
