import assert from "node:assert/strict";
import { isDeepStrictEqual } from "node:util";

function resolveReference(reference, rootSchema) {
  const prefix = "#/$defs/";
  assert.ok(reference.startsWith(prefix), `unsupported schema reference ${reference}`);
  const name = reference.slice(prefix.length);
  const target = rootSchema.$defs?.[name];
  assert.ok(target, `unknown schema definition ${name}`);
  return target;
}

function matches(value, schema, rootSchema, path) {
  try {
    validate(value, schema, rootSchema, path);
    return true;
  } catch {
    return false;
  }
}

function validate(value, schema, rootSchema, path) {
  if (schema.$ref) {
    validate(value, resolveReference(schema.$ref, rootSchema), rootSchema, path);
    return;
  }
  if (Object.hasOwn(schema, "const")) {
    assert.ok(isDeepStrictEqual(value, schema.const), `${path} must equal its constant`);
  }
  if (schema.enum) {
    assert.ok(schema.enum.some((candidate) => isDeepStrictEqual(value, candidate)), `${path} is not an allowed value`);
  }
  if (
    schema.type === "object" ||
    schema.properties !== undefined ||
    schema.required !== undefined ||
    schema.additionalProperties !== undefined
  ) {
    assert.ok(value && typeof value === "object" && !Array.isArray(value), `${path} must be an object`);
    for (const field of schema.required ?? []) {
      assert.ok(Object.hasOwn(value, field), `${path}.${field} is required`);
    }
    for (const [field, child] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(value, field)) validate(value[field], child, rootSchema, `${path}.${field}`);
    }
    if (schema.additionalProperties === false) {
      const known = new Set(Object.keys(schema.properties ?? {}));
      for (const field of Object.keys(value)) {
        assert.ok(known.has(field), `${path}.${field} is not allowed`);
      }
    }
  } else if (schema.type === "array") {
    assert.ok(Array.isArray(value), `${path} must be an array`);
    if (schema.items) {
      value.forEach((item, index) => validate(item, schema.items, rootSchema, `${path}[${index}]`));
    }
  } else if (schema.type === "string") {
    assert.equal(typeof value, "string", `${path} must be a string`);
    if (schema.minLength !== undefined) assert.ok(value.length >= schema.minLength, `${path} is too short`);
    if (schema.pattern) assert.match(value, new RegExp(schema.pattern), `${path} has an invalid format`);
  } else if (schema.type === "integer") {
    assert.ok(Number.isInteger(value), `${path} must be an integer`);
    if (schema.minimum !== undefined) assert.ok(value >= schema.minimum, `${path} is below its minimum`);
  } else if (schema.type === "boolean") {
    assert.equal(typeof value, "boolean", `${path} must be a boolean`);
  } else if (schema.type === "null") {
    assert.equal(value, null, `${path} must be null`);
  }
  if (schema.oneOf) {
    const matching = schema.oneOf.filter((candidate) => matches(value, candidate, rootSchema, path));
    assert.equal(matching.length, 1, `${path} must match exactly one schema branch`);
  }
}

export function assertJsonSchema(value, rootSchema, definition) {
  const schema = rootSchema.$defs?.[definition];
  assert.ok(schema, `unknown CLI JSON definition ${definition}`);
  validate(value, schema, rootSchema, definition);
}
