/**
 * PDF.js rejects Node Buffer even though Buffer extends Uint8Array.
 * Copy exactly the visible byte range into an own, plain Uint8Array so PDF.js
 * can transfer it without detaching caller-owned or pooled backing storage.
 */
export function normalizePdfJsData(bytes: Uint8Array): Uint8Array {
  const data = new Uint8Array(bytes.byteLength);
  data.set(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  return data;
}
