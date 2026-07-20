/**
 * JSON Schema validator (Req 2.3) — a deliberately tiny checker.
 *
 * Supports the subset of JSON Schema we actually use in schemas.js:
 *   type, properties, required, additionalProperties, enum, items,
 *   string/number/object/array constraints (minLength/maxLength/minimum/maximum).
 *
 * This avoids pulling in ajv (a heavy dependency) for a mini-project while still
 * giving REAL deterministic validation: any Reader output that deviates from
 * the schema is rejected, exactly as the PRD requires. Returns a structured
 * result so callers can publish the failure reason to the audit trail.
 *
 * @returns {{ valid: boolean, errors: string[], value: any }}
 */
function validate(value, schema, path = "$") {
  const errors = [];

  if (!schema) return { valid: true, errors: [], value };

  // type
  if (schema.type) {
    const t = schema.type;
    if (t === "object" && (typeof value !== "object" || value === null || Array.isArray(value))) {
      errors.push(`${path}: expected object, got ${Array.isArray(value) ? "array" : typeof value}`);
      return { valid: false, errors, value };
    }
    if (t === "array" && !Array.isArray(value)) {
      errors.push(`${path}: expected array, got ${typeof value}`);
      return { valid: false, errors, value };
    }
    if (t === "string" && typeof value !== "string") {
      errors.push(`${path}: expected string, got ${typeof value}`);
      return { valid: false, errors, value };
    }
    if (t === "number" && typeof value !== "number") {
      errors.push(`${path}: expected number, got ${typeof value}`);
      return { valid: false, errors, value };
    }
    if (t === "boolean" && typeof value !== "boolean") {
      errors.push(`${path}: expected boolean, got ${typeof value}`);
      return { valid: false, errors, value };
    }
  }

  // enum
  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${path}: value ${JSON.stringify(value)} not in enum [${schema.enum.join(", ")}]`);
  }

  // string bounds
  if (typeof value === "string") {
    if (schema.minLength != null && value.length < schema.minLength) {
      errors.push(`${path}: string shorter than minLength ${schema.minLength}`);
    }
    if (schema.maxLength != null && value.length > schema.maxLength) {
      errors.push(`${path}: string longer than maxLength ${schema.maxLength} (got ${value.length})`);
    }
  }

  // number bounds
  if (typeof value === "number") {
    if (schema.minimum != null && value < schema.minimum) {
      errors.push(`${path}: number ${value} below minimum ${schema.minimum}`);
    }
    if (schema.maximum != null && value > schema.maximum) {
      errors.push(`${path}: number ${value} above maximum ${schema.maximum}`);
    }
  }

  // object: required + properties + additionalProperties
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    if (schema.required) {
      for (const key of schema.required) {
        if (!(key in value)) errors.push(`${path}: missing required property "${key}"`);
      }
    }
    if (schema.properties) {
      for (const [k, sub] of Object.entries(schema.properties)) {
        if (k in value) {
          const subRes = validate(value[k], sub, `${path}.${k}`);
          errors.push(...subRes.errors);
        }
      }
    }
    if (schema.additionalProperties === false) {
      const allowed = schema.properties ? new Set(Object.keys(schema.properties)) : new Set();
      for (const k of Object.keys(value)) {
        if (!allowed.has(k)) errors.push(`${path}: additional property "${k}" not allowed`);
      }
    } else if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
      // additionalProperties as a schema (used for free-form field maps)
      for (const [k, v] of Object.entries(value)) {
        if (!schema.properties || !(k in schema.properties)) {
          const subRes = validate(v, schema.additionalProperties, `${path}.${k}`);
          errors.push(...subRes.errors);
        }
      }
    }
  }

  // array items
  if (Array.isArray(value) && schema.items) {
    value.forEach((item, i) => {
      const subRes = validate(item, schema.items, `${path}[${i}]`);
      errors.push(...subRes.errors);
    });
  }

  return { valid: errors.length === 0, errors, value };
}

/**
 * Try to extract a JSON object from an LLM response that may be wrapped in
 * prose or code fences. Returns the parsed object or null.
 */
function extractJSON(text) {
  if (!text || typeof text !== "string") return null;
  // Strip code fences if present.
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1] : text;
  // Find the first {...} block.
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  try {
    return JSON.parse(candidate.slice(start, end + 1));
  } catch {
    return null;
  }
}

export { validate, extractJSON };
