import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";

const root = resolve(import.meta.dirname, "../..");
const stage6 = resolve(root, "docs/evidence/oci-arm64/clamav-stage6");
const stage5 = resolve(root, "docs/evidence/oci-arm64/clamav-stage5");
const inputStage = process.env.INPUT_STAGE === "stage5" ? stage5 : stage6;
const outputPrefix = process.env.OUTPUT_PREFIX ?? process.env.INPUT_STAGE ?? "stage6";
const outputDirectory = resolve(process.env.OUTPUT_DIR ?? stage6);

const grypePath = resolve(process.env.GRYPE_PATH ?? resolve(inputStage, "custom.grype.json"));
const linkagePath = resolve(process.env.LINKAGE_PATH ?? resolve(stage6, "clamd-runtime-linkage.txt"));
const licensesPath = resolve(process.env.LICENSES_PATH ?? resolve(stage6, "package-license-inventory.tsv"));
const grype = JSON.parse(readFileSync(grypePath, "utf8"));
const linkage = readFileSync(linkagePath, "utf8");
const licenseLines = readFileSync(licensesPath, "utf8").trimEnd().split(/\r?\n/);

const directlyLinked = new Set(
  [...linkage.matchAll(/^([^\s:]+)(?::[^:]+)?: \/.+$/gm)].map((match) => match[1]),
);
const startupHealthPackages = new Set(["bash", "coreutils", "findutils", "grep"]);

const findings = new Map();
for (const match of grype.matches) {
  const vulnerability = match.vulnerability;
  const artifact = match.artifact;
  const row = findings.get(vulnerability.id) ?? {
    vulnerabilityId: vulnerability.id,
    severity: vulnerability.severity,
    scannerAffected: "affected",
    packages: new Map(),
    fixVersions: new Set(),
    scannerFixStates: new Set(),
    evidence: new Set(),
  };
  row.packages.set(artifact.name, artifact.version);
  row.scannerFixStates.add(vulnerability.fix?.state ?? "unknown");
  for (const version of vulnerability.fix?.versions ?? []) row.fixVersions.add(version);
  row.evidence.add(vulnerability.dataSource ?? "missing-data-source");
  findings.set(vulnerability.id, row);
}

const dispositions = [...findings.values()]
  .map((row) => {
    const packageNames = [...row.packages.keys()].sort();
    const direct = packageNames.filter((name) => directlyLinked.has(name));
    const startup = packageNames.filter((name) => startupHealthPackages.has(name));
    const reachability = direct.length
      ? `reachable: directly linked by clamd (${direct.join(", ")})`
      : startup.length
        ? `reachable: freshness/startup command (${startup.join(", ")})`
        : "not demonstrated by clamd linkage or freshness/startup command inventory";
    const fixVersions = [...row.fixVersions].sort();
    const fixAvailability = fixVersions.length
      ? `fix available: ${fixVersions.join(", ")}`
      : `no fix reported by scanner (${[...row.scannerFixStates].sort().join(", ")})`;
    const disposition = fixVersions.length ? "remediate" : "investigate";
    const rationale = fixVersions.length
      ? "Rebuild from the pinned base with current Ubuntu updates, then rescan the resulting digest."
      : reachability.startsWith("reachable:")
        ? "Do not accept without vulnerability-specific exploitability review because the affected package participates in the scanner path."
        : "No reachability was demonstrated, but absence was not proven; retain for vulnerability-specific review rather than issuing VEX."
    return {
      vulnerabilityId: row.vulnerabilityId,
      severity: row.severity,
      affected: row.scannerAffected,
      packages: packageNames.map((name) => `${name}@${row.packages.get(name)}`).join("; "),
      fixAvailability,
      reachability,
      disposition,
      rationale,
      evidence: [...row.evidence].sort().join("; "),
    };
  })
  .sort((a, b) => a.vulnerabilityId.localeCompare(b.vulnerabilityId));

const expectedCount = process.env.EXPECTED_UNIQUE ? Number(process.env.EXPECTED_UNIQUE) : null;
if (expectedCount !== null && dispositions.length !== expectedCount) {
  throw new Error(`Expected ${expectedCount} unique vulnerabilities, found ${dispositions.length}`);
}

const csvEscape = (value) => `"${String(value).replaceAll('"', '""')}"`;
const headers = Object.keys(dispositions[0]);
const csv = [
  headers.map(csvEscape).join(","),
  ...dispositions.map((row) => headers.map((header) => csvEscape(row[header])).join(",")),
].join("\n") + "\n";
writeFileSync(resolve(outputDirectory, `${outputPrefix}-security-dispositions.csv`), csv);
writeFileSync(resolve(outputDirectory, `${outputPrefix}-security-dispositions.json`), `${JSON.stringify(dispositions, null, 2)}\n`);

const licenseRows = licenseLines.slice(1).map((line) => {
  const [packageName, version, copyrightStatus, resolvedPath, sha256, declaredLicenseFields] = line.split("\t");
  return { packageName, version, copyrightStatus, resolvedPath, sha256, declaredLicenseFields };
});
if (licenseRows.length !== 124) {
  throw new Error(`Expected 124 package license rows, found ${licenseRows.length}`);
}

const summary = {
  evidenceIdentity: {
    localImageId: process.env.LOCAL_IMAGE_ID ?? null,
    archiveSha256: process.env.ARCHIVE_SHA256 ?? null,
    registryDigest: process.env.REGISTRY_DIGEST ?? null,
    grypeEvidenceSha256: createHash("sha256").update(readFileSync(grypePath)).digest("hex"),
  },
  security: {
    rawMatches: grype.matches.length,
    uniqueVulnerabilities: dispositions.length,
    affected: dispositions.filter((row) => row.affected === "affected").length,
    fixAvailable: dispositions.filter((row) => row.fixAvailability.startsWith("fix available:")).length,
    directlyOrStartupReachable: dispositions.filter((row) => row.reachability.startsWith("reachable:")).length,
    reachabilityNotDemonstrated: dispositions.filter((row) => row.reachability.startsWith("not demonstrated")).length,
    remediate: dispositions.filter((row) => row.disposition === "remediate").length,
    investigate: dispositions.filter((row) => row.disposition === "investigate").length,
    accept: dispositions.filter((row) => row.disposition === "accept").length,
    blanketVexIssued: false,
  },
  licensing: {
    installedPackages: licenseRows.length,
    copyrightPresent: licenseRows.filter((row) => row.copyrightStatus === "present").length,
    copyrightMissing: licenseRows.filter((row) => row.copyrightStatus !== "present").length,
    machineReadableDeclaredLicenseFields: licenseRows.filter((row) => row.declaredLicenseFields).length,
    legacyOrNoDeclaredLicenseField: licenseRows.filter((row) => !row.declaredLicenseFields).length,
    noticesArchive: basename(resolve(outputDirectory, "custom-transitive-copyrights.tar.gz")),
    legalApproval: "not-approved",
  },
};
writeFileSync(resolve(outputDirectory, `${outputPrefix}-closure-summary.json`), `${JSON.stringify(summary, null, 2)}\n`);
console.log(JSON.stringify(summary, null, 2));
