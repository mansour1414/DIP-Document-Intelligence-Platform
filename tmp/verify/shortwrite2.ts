// Definitive: does writeSync on a *pipe* ever return fewer bytes than requested?
// Use a non-blocking fd, which is the condition under which short writes occur.
import { openSync, writeSync, closeSync, constants } from "node:fs";
const results: number[] = [];
// O_NONBLOCK on a pipe forces write() to return EAGAIN or a partial count.
const fd = openSync("/tmp/pipe-probe", constants.O_WRONLY | constants.O_NONBLOCK | constants.O_CREAT, 0o600);
const buf = Buffer.alloc(200_000, 0x42);
try { const n = writeSync(fd, buf); results.push(n); } catch (e: any) { results.push(-1); console.log("error:", e.code); }
closeSync(fd);
console.log("writeSync to non-blocking fd returned:", results[0], "of", buf.byteLength);
console.log("=> short write observed:", results[0] > 0 && results[0] < buf.byteLength);
