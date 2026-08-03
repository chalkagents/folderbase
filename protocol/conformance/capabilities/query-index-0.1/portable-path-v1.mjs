import { FULL_DEFAULT_CASE_FOLD_V9 } from "./unicode-casefold-v9-data.mjs";
import {
  CANONICAL_COMBINING_CLASS_V17,
  CANONICAL_COMPOSITION_V17,
  CANONICAL_DECOMPOSITION_V17,
} from "./unicode-nfc-v17-data.mjs";

export function unicode17Nfc(value) {
  const decomposed = [];
  const S_BASE = 0xac00, L_BASE = 0x1100, V_BASE = 0x1161, T_BASE = 0x11a7;
  const L_COUNT = 19, V_COUNT = 21, T_COUNT = 28, N_COUNT = V_COUNT * T_COUNT;
  for (const character of value) {
    const scalar = character.codePointAt(0);
    const sIndex = scalar - S_BASE;
    const expansion = sIndex >= 0 && sIndex < L_COUNT * N_COUNT
      ? [L_BASE + Math.floor(sIndex / N_COUNT), V_BASE + Math.floor((sIndex % N_COUNT) / T_COUNT),
          ...(sIndex % T_COUNT === 0 ? [] : [T_BASE + (sIndex % T_COUNT)])]
      : (CANONICAL_DECOMPOSITION_V17.get(scalar) ?? [scalar]);
    for (const point of expansion) {
      const currentClass = CANONICAL_COMBINING_CLASS_V17.get(point) ?? 0;
      let insertion = decomposed.length;
      while (currentClass !== 0 && insertion > 0) {
        const priorClass = CANONICAL_COMBINING_CLASS_V17.get(decomposed[insertion - 1]) ?? 0;
        if (priorClass === 0 || priorClass <= currentClass) break;
        insertion -= 1;
      }
      decomposed.splice(insertion, 0, point);
    }
  }
  const output = [];
  let starterIndex = -1;
  let lastClass = 0;
  for (const point of decomposed) {
    const currentClass = CANONICAL_COMBINING_CLASS_V17.get(point) ?? 0;
    let composed;
    if (starterIndex >= 0 && (lastClass === 0 || lastClass < currentClass)) {
      const starter = output[starterIndex];
      const lIndex = starter - L_BASE;
      const vIndex = point - V_BASE;
      const sIndex = starter - S_BASE;
      const tIndex = point - T_BASE;
      if (lIndex >= 0 && lIndex < L_COUNT && vIndex >= 0 && vIndex < V_COUNT) {
        composed = S_BASE + (lIndex * V_COUNT + vIndex) * T_COUNT;
      } else if (sIndex >= 0 && sIndex < L_COUNT * N_COUNT && sIndex % T_COUNT === 0 && tIndex > 0 && tIndex < T_COUNT) {
        composed = starter + tIndex;
      } else {
        composed = CANONICAL_COMPOSITION_V17.get(starter * 0x110000 + point);
      }
    }
    if (composed !== undefined) output[starterIndex] = composed;
    else {
      if (currentClass === 0) starterIndex = output.length;
      output.push(point);
      lastClass = currentClass;
    }
  }
  return String.fromCodePoint(...output);
}

export function fullDefaultCaseFoldV9(value) {
  let folded = "";
  for (const character of value) {
    const mapped = FULL_DEFAULT_CASE_FOLD_V9.get(character.codePointAt(0));
    folded += mapped === undefined
      ? character
      : String.fromCodePoint(...mapped);
  }
  return folded;
}

export function portablePathKeys(path) {
  const nfc = unicode17Nfc(path);
  return {
    nfc,
    folded: unicode17Nfc(fullDefaultCaseFoldV9(nfc)),
  };
}

export class PortablePathCollisionIndex {
  #exact = new Map();
  #nfc = new Map();
  #folded = new Map();

  insert(path, owner = null, { exactDuplicates = "reject" } = {}) {
    const keys = portablePathKeys(path);
    const exact = this.#exact.get(path);
    if (exact !== undefined && exactDuplicates === "reject") {
      throw new Error(`exact portable paths collide: ${path}`);
    }
    for (const [label, index, key] of [
      ["NFC normalization", this.#nfc, keys.nfc],
      ["full default case folding", this.#folded, keys.folded],
    ]) {
      const existing = index.get(key);
      if (existing !== undefined && existing !== path) {
        throw new Error(`portable paths collide after ${label}: ${existing} and ${path}`);
      }
    }
    this.#exact.set(path, owner);
    this.#nfc.set(keys.nfc, path);
    this.#folded.set(keys.folded, path);
    return keys;
  }

  exactOwner(path) {
    return this.#exact.get(path);
  }

  rejectAlias(path) {
    const keys = portablePathKeys(path);
    for (const [label, index, key] of [
      ["NFC normalization", this.#nfc, keys.nfc],
      ["full default case folding", this.#folded, keys.folded],
    ]) {
      const existing = index.get(key);
      if (existing !== undefined && existing !== path) {
        throw new Error(`portable paths collide after ${label}: ${existing} and ${path}`);
      }
    }
  }
}
