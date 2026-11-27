import { publicErrorCode, jobErrorRecord } from "../../src/lib/jobs/error-boundary";
import { MalwareScanError } from "../../src/lib/malware/types";
import { QpdfError } from "../../src/lib/pdf/qpdf";

const cases: [string, unknown, string][] = [
  ["scanner unavailable", new MalwareScanError("SCANNER_UNAVAILABLE"), "SCANNER_UNAVAILABLE"],
  ["infected upload", new MalwareScanError("INFECTED"), "INFECTED"],
  ["scan timeout", new MalwareScanError("SCAN_TIMEOUT"), "SCAN_TIMEOUT"],
  ["pdf password", new QpdfError("PDF_PASSWORD_INVALID", "The supplied password could not open this PDF."), "PDF_PASSWORD_INVALID"],
];
let failures = 0;
for (const [name, error, expected] of cases) {
  const actual = publicErrorCode(error);
  const record = jobErrorRecord(error);
  const leaked = /password|secret|supplied|could not open|scan safely/u.test(JSON.stringify(record));
  if (actual !== expected) { console.log(`FAIL ${name}: got ${actual}, want ${expected}`); failures++; }
  else if (leaked) { console.log(`FAIL ${name}: raw message leaked into ${JSON.stringify(record)}`); failures++; }
  else console.log(`ok ${name} -> ${actual} ${JSON.stringify(record)}`);
}
console.log(failures === 0 ? "ALL 4 PASS" : `${failures} FAILED`);
