// Short-lived hosted output files for tools that produce binary data (screenshots, PDFs, images).
// Binary results are written here and returned as an unguessable URL under /mcp/files/ that
// expires after FILE_TTL_MS, instead of stuffing megabytes of base64 into the JSON-RPC text
// result. Callers that want the bytes inline can pass includeBase64 (size-capped).
import { mkdirSync, readdirSync, statSync, unlinkSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes, createHash } from "node:crypto";

export const FILE_TTL_MS = 60 * 60 * 1000; // 1 hour
const FILES_DIR = process.env.TOOLBELT_FILES_DIR ?? join(import.meta.dir, "..", "..", ".files");
const MAX_STORE_BYTES = 512 * 1024 * 1024; // hard cap on disk used by hosted outputs
const MAX_INLINE_BASE64_BYTES = 3 * 1024 * 1024;
const PUBLIC_BASE = (process.env.X402_PUBLIC_BASE_URL ?? "https://papacasper.com/mcp").replace(/\/$/, "");

export const CONTENT_TYPES: Record<string, string> = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  webp: "image/webp",
  avif: "image/avif",
  pdf: "application/pdf",
};

const NAME_RE = /^[A-Za-z0-9_-]{22}\.(png|jpg|jpeg|webp|avif|pdf)$/;

mkdirSync(FILES_DIR, { recursive: true, mode: 0o750 });

export function cleanupFiles(): void {
  let entries: Array<{ path: string; mtime: number; size: number }> = [];
  try {
    entries = readdirSync(FILES_DIR).filter((n) => NAME_RE.test(n)).map((n) => {
      const path = join(FILES_DIR, n);
      const st = statSync(path);
      return { path, mtime: st.mtimeMs, size: st.size };
    });
  } catch {
    return;
  }
  const now = Date.now();
  let total = 0;
  const live: typeof entries = [];
  for (const e of entries) {
    if (now - e.mtime > FILE_TTL_MS) {
      try { unlinkSync(e.path); } catch {}
    } else {
      live.push(e);
      total += e.size;
    }
  }
  // Over the disk cap: drop the oldest first.
  live.sort((a, b) => a.mtime - b.mtime);
  while (total > MAX_STORE_BYTES && live.length) {
    const e = live.shift()!;
    try { unlinkSync(e.path); } catch {}
    total -= e.size;
  }
}

setInterval(cleanupFiles, 5 * 60 * 1000).unref?.();

export function storeFile(buf: Uint8Array, ext: keyof typeof CONTENT_TYPES, includeBase64 = false) {
  cleanupFiles();
  const name = `${randomBytes(16).toString("base64url")}.${ext}`;
  writeFileSync(join(FILES_DIR, name), buf, { mode: 0o640 });
  const out: Record<string, unknown> = {
    url: `${PUBLIC_BASE}/files/${name}`,
    expiresAt: new Date(Date.now() + FILE_TTL_MS).toISOString(),
    contentType: CONTENT_TYPES[ext],
    bytes: buf.byteLength,
    sha256: createHash("sha256").update(buf).digest("hex"),
  };
  if (includeBase64) {
    if (buf.byteLength <= MAX_INLINE_BASE64_BYTES) out.base64 = Buffer.from(buf).toString("base64");
    else out.base64Omitted = `Output is ${buf.byteLength} bytes; inline base64 is capped at ${MAX_INLINE_BASE64_BYTES} bytes. Download it from url instead.`;
  }
  return out;
}

/** Returns the stored file for a GET /files/:name request, or null if missing/expired/invalid. */
export function readStoredFile(name: string): { body: Buffer; contentType: string } | null {
  if (!NAME_RE.test(name)) return null;
  const path = join(FILES_DIR, name);
  if (!existsSync(path)) return null;
  const st = statSync(path);
  if (Date.now() - st.mtimeMs > FILE_TTL_MS) {
    try { unlinkSync(path); } catch {}
    return null;
  }
  const ext = name.split(".").pop()!;
  return { body: readFileSync(path), contentType: CONTENT_TYPES[ext] ?? "application/octet-stream" };
}

/** Reads a fetch() Response body with a hard byte cap (the SSRF-guarded global fetch is used upstream). */
export async function readCapped(res: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared && declared > maxBytes) throw new Error(`Response is ${declared} bytes; the limit is ${maxBytes} bytes`);
  if (!res.body) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      try { await reader.cancel(); } catch {}
      throw new Error(`Response exceeds the ${maxBytes}-byte limit`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.byteLength; }
  return out;
}
