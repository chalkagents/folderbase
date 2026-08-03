import { createHash } from "node:crypto";

function escapeRegex(character) {
  return /[\\^$+?.()|{}\[\]]/u.test(character) ? `\\${character}` : character;
}

function trimGitignoreTrailingSpaces(line) {
  let end = line.length;
  while (end > 0 && line[end - 1] === " ") {
    let slashes = 0;
    for (let index = end - 2; index >= 0 && line[index] === "\\"; index -= 1) slashes += 1;
    if (slashes % 2 === 1) {
      return `${line.slice(0, end - 2)} ${line.slice(end)}`;
    }
    end -= 1;
  }
  return line.slice(0, end);
}

function globRegex(pattern) {
  let source = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "\\" && index + 1 < pattern.length) {
      source += escapeRegex(pattern[index + 1]);
      index += 1;
    } else if (character === "[") {
      let end = index + 1;
      if (pattern[end] === "!" || pattern[end] === "^") end += 1;
      if (pattern[end] === "]") end += 1;
      while (end < pattern.length && pattern[end] !== "]") end += 1;
      if (end === pattern.length) source += "\\[";
      else {
        let body = pattern.slice(index + 1, end);
        if (body.startsWith("!")) body = `^${body.slice(1)}`;
        source += `[${body.replaceAll("\\", "\\\\")}]`;
        index = end;
      }
    } else if (character === "*") {
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
    let pattern = trimGitignoreTrailingSpaces(raw.replace(/\r$/u, ""));
    if (pattern === "" || pattern.startsWith("#")) continue;
    let negated = false;
    if (pattern.startsWith("\\!") || pattern.startsWith("\\#")) {
      pattern = pattern.slice(1);
    } else if (pattern.startsWith("!")) {
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
      exact: new RegExp(`${prefix}${body}$`, "u"),
      descendants: directoryOnly
        ? new RegExp(`${prefix}${body}/[\\s\\S]+$`, "u")
        : null,
    });
  }
  return rules;
}

export function ignoredByGitignore(path, isDirectory, rules) {
  let ignored = false;
  for (const rule of rules) {
    const matches = (rule.exact.test(path) && (!rule.directoryOnly || isDirectory)) ||
      rule.descendants?.test(path);
    if (matches) ignored = !rule.negated;
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
