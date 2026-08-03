import { pathToFileURL } from "node:url";

function parseRequired(name, value) {
  if (value === true || value === "true") return true;
  if (value === false || value === "false") return false;
  throw new Error(`${name} has invalid required value: ${value}`);
}

export function verifyRequiredResults({ planResult, lanes }) {
  if (planResult !== "success") {
    throw new Error(`CI plan ended with ${planResult}`);
  }

  for (const [name, lane] of Object.entries(lanes)) {
    const required = parseRequired(name, lane.required);
    const expected = required ? "success" : "skipped";
    if (lane.result !== expected) {
      throw new Error(
        required
          ? `${name} was required but ended with ${lane.result}`
          : `${name} was not required but ended with ${lane.result}`,
      );
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const input = {
    planResult: process.env.PLAN_RESULT,
    lanes: {
      docs: {
        required: process.env.DOCS_REQUIRED,
        result: process.env.DOCS_RESULT,
      },
      install: {
        required: process.env.INSTALL_REQUIRED,
        result: process.env.INSTALL_RESULT,
      },
      npm: {
        required: process.env.NPM_REQUIRED,
        result: process.env.NPM_RESULT,
      },
      platform: {
        required: process.env.PLATFORM_REQUIRED,
        result: process.env.PLATFORM_RESULT,
      },
      rust: {
        required: process.env.RUST_REQUIRED,
        result: process.env.RUST_RESULT,
      },
    },
  };

  try {
    verifyRequiredResults(input);
    process.stdout.write(`${JSON.stringify({ ok: true })}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
