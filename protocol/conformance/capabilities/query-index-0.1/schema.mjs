import assert from "node:assert/strict";
import { isDeepStrictEqual } from "node:util";

function dereference(schema, root) {
  if (!schema.$ref) return schema;
  const prefix = "#/$defs/";
  assert.ok(schema.$ref.startsWith(prefix), `unsupported reference ${schema.$ref}`);
  const resolved = root.$defs?.[schema.$ref.slice(prefix.length)];
  assert.ok(resolved, `unknown reference ${schema.$ref}`);
  return resolved;
}

function accepts(value, schema, root, path) {
  try {
    validate(value, schema, root, path);
    return true;
  } catch {
    return false;
  }
}

function matchesType(value, type) {
  if (type === "null") return value === null;
  if (type === "array") return Array.isArray(value);
  if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
  if (type === "integer") return Number.isInteger(value);
  return typeof value === type;
}

function validate(value, inputSchema, root, path) {
  const schema = dereference(inputSchema, root);
  if (schema.allOf) {
    for (const branch of schema.allOf) validate(value, branch, root, path);
  }
  if (schema.oneOf) {
    const branches = schema.oneOf.filter((branch) => accepts(value, branch, root, path));
    assert.equal(branches.length, 1, `${path} must match exactly one branch`);
    return;
  }
  if (schema.anyOf) {
    assert.ok(
      schema.anyOf.some((branch) => accepts(value, branch, root, path)),
      `${path} must match at least one branch`,
    );
  }
  if (schema.not) {
    assert.ok(!accepts(value, schema.not, root, path), `${path} matches a forbidden branch`);
  }
  if (schema.if) {
    if (accepts(value, schema.if, root, path)) {
      if (schema.then) validate(value, schema.then, root, path);
    } else if (schema.else) validate(value, schema.else, root, path);
  }
  if (Object.hasOwn(schema, "const")) {
    assert.ok(isDeepStrictEqual(value, schema.const), `${path} must equal its constant`);
  }
  if (schema.enum) {
    assert.ok(schema.enum.some((item) => isDeepStrictEqual(value, item)), `${path} is not allowed`);
  }
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    assert.ok(types.some((type) => matchesType(value, type)), `${path} has the wrong type`);
  }
  if (matchesType(value, "object") && (schema.type === "object" || schema.properties || schema.required)) {
    for (const field of schema.required ?? []) {
      assert.ok(Object.hasOwn(value, field), `${path}.${field} is required`);
    }
    for (const [field, child] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(value, field)) validate(value[field], child, root, `${path}.${field}`);
    }
    if (schema.additionalProperties === false) {
      const known = new Set(Object.keys(schema.properties ?? {}));
      for (const field of Object.keys(value)) {
        assert.ok(known.has(field), `${path}.${field} is not allowed`);
      }
    }
  }
  if (Array.isArray(value) && schema.type === "array") {
    if (schema.minItems !== undefined) assert.ok(value.length >= schema.minItems, `${path} has too few items`);
    if (schema.maxItems !== undefined) assert.ok(value.length <= schema.maxItems, `${path} has too many items`);
    if (schema.uniqueItems) {
      for (let left = 0; left < value.length; left += 1) {
        for (let right = left + 1; right < value.length; right += 1) {
          assert.ok(!isDeepStrictEqual(value[left], value[right]), `${path} has duplicate items`);
        }
      }
    }
    if (schema.items) value.forEach((item, index) => validate(item, schema.items, root, `${path}[${index}]`));
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined) assert.ok(value.length >= schema.minLength, `${path} is too short`);
    if (schema.maxLength !== undefined) assert.ok(value.length <= schema.maxLength, `${path} is too long`);
    if (schema.pattern) assert.match(value, new RegExp(schema.pattern), `${path} has an invalid format`);
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined) assert.ok(value >= schema.minimum, `${path} is below minimum`);
    if (schema.maximum !== undefined) assert.ok(value <= schema.maximum, `${path} is above maximum`);
  }
}

export function assertQuerySchema(value, root, definition) {
  const schema = root.$defs?.[definition];
  assert.ok(schema, `unknown query schema definition ${definition}`);
  validate(value, schema, root, definition);
}
