import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

const loadJson = async (path: string) => JSON.parse(await readFile(new URL(path, import.meta.url), "utf8"));

test("G1-A/02 inventory freezes exact reviewed wheels and key native hashes", async () => {
  const inventory = await loadJson("../docs/evidence/g1a02/g1a02-python-native-inventory.json");
  assert.equal(inventory.approval, "NOT APPROVED");
  assert.equal(inventory.registry_image_digest, "NOT VERIFIED");
  assert.equal(inventory.python_wheels.length, 9);
  assert.equal(inventory.native_members.length, 41);

  const wheels = Object.fromEntries(inventory.python_wheels.map((item: { name: string }) => [item.name, item]));
  assert.equal(wheels.pikepdf.sha256, "365b94f2be7e2857c6cb5445b56dc52dc7417ba9f06c8a4282d9f521cb2d0fb8");
  assert.equal(wheels.pillow.sha256, "23d27a3e0307ec2244cc51e7287b919aa68d097504ebe19df4e76a98a3eea5bd");

  const nativeByMember = Object.fromEntries(inventory.native_members.map((item: { member: string }) => [item.member, item]));
  assert.equal(nativeByMember["pikepdf.libs/libqpdf-b00d82b7.so.30.3.2"].sha256, "63ddaa79f709b48d2d555c289ec1b6724acf343edff07eb8b2ed3d3fb32342d7");
  assert.equal(nativeByMember["pillow.libs/liblcms2-dade1fbf.so.2.0.19"].sha256, "2549d6886e7de9960792e10ac87acfb9895e2afae85b7aac02108080cc7d3a71");
  assert.equal(nativeByMember["pillow.libs/libjpeg-31e2ca52.so.62.4.0"].sha256, "6d7c754529b30aff22efaaf88ba02061714591702c03f297f00ccb32ee6d9d9a");
  assert.equal(inventory.native_members.some((item: { member: string }) => /imagequant/iu.test(item.member)), false);
});

test("Unified candidate SBOM distinguishes missing registry digest and incomplete layers", async () => {
  const sbom = await loadJson("../docs/evidence/g1a02/g1a02-unified-candidate-sbom.cdx.json");
  const properties = Object.fromEntries(sbom.metadata.properties.map((item: { name: string; value: string }) => [item.name, item.value]));
  assert.equal(properties["dip:approval"], "NOT APPROVED");
  assert.equal(properties["dip:registry-image-digest"], "NOT VERIFIED");
  assert.equal(properties["dip:debian-full-artifact-locally-available"], "false");
  assert.equal(properties["dip:debian-spdx-total-packages"], "301");
  assert.ok(sbom.components.some((item: { properties: Array<{ name: string; value: string }> }) => item.properties.some((property) => property.name === "dip:layer" && property.value === "python-wheel")));
  assert.ok(sbom.components.some((item: { properties: Array<{ name: string; value: string }> }) => item.properties.some((property) => property.name === "dip:layer" && property.value === "native-wheel-member")));
  assert.ok(sbom.components.some((item: { properties: Array<{ name: string; value: string }> }) => item.properties.some((property) => property.name === "dip:layer" && property.value === "node-production-lock-candidate")));
  assert.ok(sbom.components.some((item: { properties: Array<{ name: string; value: string }> }) => item.properties.some((property) => property.name === "dip:layer" && property.value === "debian-g0-selected")));
});

test("G1-A/02 preserves OFF and no-production-integration boundaries", async () => {
  const [dockerfile, registry, worker, config, decision] = await Promise.all([
    readFile(new URL("../Dockerfile.worker", import.meta.url), "utf8"),
    readFile(new URL("../src/lib/tools/registry.ts", import.meta.url), "utf8"),
    readFile(new URL("../workers/document-worker.ts", import.meta.url), "utf8"),
    readFile(new URL("../src/config/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../docs/g1a-02-licensing-gate-decision-record.md", import.meta.url), "utf8"),
  ]);
  assert.doesNotMatch(dockerfile, /dip-gray-stage3b|structural-grayscale|pikepdf==10\.13\.0|Pillow==12\.3\.0/u);
  for (const source of [registry, worker, config]) assert.doesNotMatch(source, /["']grayscale-pdf["']/u);
  assert.match(decision, /OPEN — NOT APPROVED/u);
  assert.match(decision, /DIP_GRAYSCALE_LICENSING_GATE_APPROVED.*unset\/false/u);
});
