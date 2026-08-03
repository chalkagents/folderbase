import { createHash } from "node:crypto";

function escapeRegex(character) {
  return /[\\^$+?.()|{}\[\]]/u.test(character) ? `\\${character}` : character;
}

function globRegex(pattern) {
  let source = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "*") {
      if (pattern[index + 1] === "*") {
        index += 1;
        if (pattern[index + 1] === "/") {
          index += 1;
          source += "(?:.*/)?";
        } else source += ".*";
      } else source += "[^/]*";
    } else if (character === "?") source += "[^/]";
    else source += escapeRegex(character);
  }
  return source;
}

export function compileGitignore(lines) {
  // This deliberately implements the fixed public conformance vectors, not
  // the entire ignore crate grammar. Implementations may use any complete
  // Gitignore engine; the runner's observations are the normative proof.
  const rules = [];
  for (const raw of lines) {
    if (raw === "" || raw.startsWith("#")) continue;
    let pattern = raw;
    let negated = false;
    if (pattern.startsWith("!")) {
      negated = true;
      pattern = pattern.slice(1);
    }
    if (!pattern) continue;
    const directoryOnly = pattern.endsWith("/");
    if (directoryOnly) pattern = pattern.slice(0, -1);
    const rooted = pattern.startsWith("/");
    if (rooted) pattern = pattern.slice(1);
    const hasSlash = pattern.includes("/");
    const body = globRegex(pattern);
    const prefix = rooted || hasSlash ? "^" : "(?:^|.*/)";
    rules.push({
      negated,
      directoryOnly,
      regex: new RegExp(`${prefix}${body}${directoryOnly ? "(?:/.*)?" : ""}$`, "u"),
    });
  }
  return rules;
}

export function ignoredByGitignore(path, isDirectory, rules) {
  let ignored = false;
  for (const rule of rules) {
    if (rule.directoryOnly && !isDirectory && !path.includes("/")) continue;
    if (rule.regex.test(path)) ignored = !rule.negated;
  }
  return ignored;
}

export function effectiveCaptureIgnoreDigest(engineRules, encoded, present = true) {
  const digest = createHash("sha256");
  digest.update("folderbase-ignore-policy-v2\0", "utf8");
  digest.update(present ? "present\0" : "absent\0", "utf8");
  for (const rule of engineRules) digest.update(`${rule}\n`, "utf8");
  digest.update("\0", "utf8");
  digest.update(encoded);
  return digest.digest("hex");
}
