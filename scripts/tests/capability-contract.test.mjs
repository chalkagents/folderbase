import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { assertJsonSchema } from "../../protocol/conformance/cli-json-v1/schema.mjs";

const contractUrl = new URL(
  "../../protocol/compatibility/v1/contract.json",
  import.meta.url,
);
const registryUrl = new URL(
  "../../protocol/capabilities/v1/registry.json",
  import.meta.url,
);
const registrySchemaUrl = new URL(
  "../../protocol/schemas/capabilities/1/registry.schema.json",
  import.meta.url,
);
const changeSetCapabilityUrl = new URL(
  "../../protocol/capabilities/change-set/0.1.0/capability.json",
  import.meta.url,
);
const daemonCapabilityUrl = new URL(
  "../../protocol/capabilities/daemon-stdio/0.1.0/capability.json",
  import.meta.url,
);
const queryCapabilityUrl = new URL(
  "../../protocol/capabilities/query-index/0.1.0/capability.json",
  import.meta.url,
);
const rootReconstructionCapabilityUrl = new URL(
  "../../protocol/capabilities/root-reconstruction/0.1.0/capability.json",
  import.meta.url,
);
const templateCapabilityUrl = new URL(
  "../../protocol/capabilities/template-expansion/0.1.0/capability.json",
  import.meta.url,
);
const embeddedRegistryUrl = new URL(
  "../../crates/folderbase-cli/assets/capability-registry-v1.json",
  import.meta.url,
);
const unchangedCandidateUrl = new URL(
  "../../protocol/conformance/capabilities/fixtures/v1-minimum-candidate.json",
  import.meta.url,
);
const naiveQueryCandidateUrl = new URL(
  "../../protocol/conformance/capabilities/fixtures/naive-query-minimum-candidate.json",
  import.meta.url,
);
const releasedV05ManifestUrl = new URL(
  "../../protocol/releases/0.5/folderbase-version-v1.json",
  import.meta.url,
);
const releasedV05SidecarUrl = new URL(
  "../../protocol/releases/0.5/folderbase-version-v1.sha256",
  import.meta.url,
);

async function load(url) {
  return JSON.parse(await readFile(url, "utf8"));
}

function assertSameMinimum(candidate, contract) {
  assert.deepEqual(candidate.cli_json.commands, contract.cli_json.commands);
}

test("optional capabilities do not expand Compatibility Contract v1's minimum", async () => {
  const [contract, registry, unchangedCandidate, naiveQueryCandidate] =
    await Promise.all([
      load(contractUrl),
      load(registryUrl),
      load(unchangedCandidateUrl),
      load(naiveQueryCandidateUrl),
    ]);

  assert.doesNotThrow(() => assertSameMinimum(unchangedCandidate, contract));
  assert.throws(
    () => assertSameMinimum(naiveQueryCandidate, contract),
    /Expected values to be strictly deep-equal/,
  );
  assert.equal(registry.format, "folderbase-capability-registry-v1");
});

test("the public and embedded capability registries are exact after advertised profiles turn GREEN", async () => {
  const [registry, embeddedRegistry, changeSetCapability, daemonCapability, queryCapability, rootReconstructionCapability, templateCapability, schema] = await Promise.all([
    load(registryUrl),
    load(embeddedRegistryUrl),
    load(changeSetCapabilityUrl),
    load(daemonCapabilityUrl),
    load(queryCapabilityUrl),
    load(rootReconstructionCapabilityUrl),
    load(templateCapabilityUrl),
    load(registrySchemaUrl),
  ]);

  assert.deepEqual(embeddedRegistry, registry);
  assert.equal(
    embeddedRegistry.capabilities.some(
      ({ name }) => name === "folderbase.root-reconstruction",
    ),
    true,
  );
  assert.equal(
    schema.$id,
    "https://folderbase.ai/protocol/capabilities/1/registry.schema.json",
  );
  assert.doesNotThrow(() => assertJsonSchema(registry, schema, "registry"));
  assert.deepEqual(schema.$defs.capabilityProfile.properties.stability.enum, [
    "stable",
    "experimental",
  ]);

  const profiles = registry.capabilities.map(
    ({ name, version, stability }) => ({ name, version, stability }),
  );
  assert.deepEqual(profiles, [
    {
      name: "folderbase.change-set",
      version: "0.1.0",
      stability: "stable",
    },
    {
      name: "folderbase.daemon-stdio",
      version: "0.1.0",
      stability: "experimental",
    },
    {
      name: "folderbase.query-index",
      version: "0.1.0",
      stability: "experimental",
    },
    {
      name: "folderbase.root-reconstruction",
      version: "0.1.0",
      stability: "stable",
    },
    {
      name: "folderbase.template-expansion",
      version: "0.1.0",
      stability: "stable",
    },
    {
      name: "folderbase.version-cli-json",
      version: "0.1.0",
      stability: "experimental",
    },
  ]);
  const selectors = registry.capabilities.map(
    ({ name, version }) => `${name}@${version}`,
  );
  assert.deepEqual(selectors, [...new Set(selectors)].sort());
  assert.deepEqual(
    registry.capabilities.find(({ name }) => name === "folderbase.change-set"),
    changeSetCapability,
  );
  assert.deepEqual(
    registry.capabilities.find(({ name }) => name === "folderbase.daemon-stdio"),
    daemonCapability,
  );
  assert.deepEqual(
    registry.capabilities.find(({ name }) => name === "folderbase.query-index"),
    queryCapability,
  );
  assert.deepEqual(
    registry.capabilities.find(({ name }) => name === "folderbase.root-reconstruction"),
    rootReconstructionCapability,
  );
  assert.deepEqual(
    registry.capabilities.find(({ name }) => name === "folderbase.template-expansion"),
    templateCapability,
  );
});

test("capability discovery does not rewrite the immutable protocol 0.5 release", async () => {
  const [manifestBytes, sidecar] = await Promise.all([
    readFile(releasedV05ManifestUrl),
    readFile(releasedV05SidecarUrl, "utf8"),
  ]);
  const releasedDigest =
    "1ec1d3b6561998dfc55ff2a30c7484b9342ba5c10659e4a648078169b33945f2";

  assert.equal(sidecar.trim(), releasedDigest);
  assert.equal(
    createHash("sha256").update(manifestBytes).digest("hex"),
    releasedDigest,
  );
  const manifest = JSON.parse(manifestBytes);
  assert.equal(manifest.protocol_version, "0.5");
  assert.equal(manifest.status, "released");
  assert.equal(
    manifest.files.some(({ path }) => path.includes("capabilit")),
    false,
  );
});
