import assert from "node:assert/strict";
import test from "node:test";

import { verifyRequiredResults } from "../ci/verify-required-results.mjs";

const successfulPlan = {
  planResult: "success",
  lanes: {
    install: { required: false, result: "skipped" },
    npm: { required: true, result: "success" },
    platform: { required: false, result: "skipped" },
    rust: { required: true, result: "success" },
  },
};

test("accepts successful required lanes and skipped inapplicable lanes", () => {
  assert.doesNotThrow(() => verifyRequiredResults(successfulPlan));
});

test("rejects a required lane that was skipped", () => {
  assert.throws(
    () =>
      verifyRequiredResults({
        ...successfulPlan,
        lanes: {
          ...successfulPlan.lanes,
          rust: { required: true, result: "skipped" },
        },
      }),
    /rust was required but ended with skipped/,
  );
});

test("rejects an inapplicable lane that ran", () => {
  assert.throws(
    () =>
      verifyRequiredResults({
        ...successfulPlan,
        lanes: {
          ...successfulPlan.lanes,
          install: { required: false, result: "success" },
        },
      }),
    /install was not required but ended with success/,
  );
});

test("rejects a failed CI plan before evaluating lanes", () => {
  assert.throws(
    () => verifyRequiredResults({ ...successfulPlan, planResult: "failure" }),
    /CI plan ended with failure/,
  );
});

test("rejects ambiguous required values", () => {
  assert.throws(
    () =>
      verifyRequiredResults({
        ...successfulPlan,
        lanes: {
          ...successfulPlan.lanes,
          npm: { required: "yes", result: "success" },
        },
      }),
    /npm has invalid required value: yes/,
  );
});
