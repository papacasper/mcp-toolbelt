// Data conversion tools: image_resize (sharp/libvips) and csv_to_json (RFC 4180 parser).
// Deterministic transforms only, no AI.
import sharp from "sharp";
import { storeFile, readCapped } from "./files";

const MAX_IMAGE_INPUT_BYTES = 15 * 1024 * 1024;
const MAX_INPUT_PIXELS = 50_000_000;
const MAX_OUTPUT_DIM = 4096;
const MAX_CSV_BYTES = 2 * 1024 * 1024;
const MAX_CSV_ROWS = 10_000;

sharp.cache(false);
sharp.concurrency(2);

function normalizeHttpUrl(input: string): string {
  const raw = String(input ?? "").trim();
  if (!raw) throw new Error("url is required");
  const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http(s) URLs are supported");
  return u.toString();
}

async function fetchCapped(url: string, maxBytes: number, accept: string) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20_000);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)", accept },
      redirect: "follow",
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`Fetch failed: ${res.status} ${res.statusText}`);
    const body = await readCapped(res, maxBytes);
    return { body, contentType: res.headers.get("content-type") ?? "", finalUrl: res.url || url };
  } catch (e: any) {
    if (e?.name === "AbortError") throw new Error("Fetching the source timed out after 20s");
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ---- csv_to_json ---------------------------------------------------------------------------
function detectDelimiter(text: string): string {
  const sample = text.split(/\r?\n/).slice(0, 10).join("\n");
  const candidates = [",", ";", "\t", "|"];
  let best = ",";
  let bestScore = -1;
  for (const d of candidates) {
    // Count delimiters outside quotes on each sampled line; prefer consistent, non-zero counts.
    const counts = sample.split("\n").filter(Boolean).map((line) => {
      let n = 0, q = false;
      for (const ch of line) { if (ch === '"') q = !q; else if (ch === d && !q) n++; }
      return n;
    });
    if (!counts.length || counts[0] === 0) continue;
    const consistent = counts.filter((c) => c === counts[0]).length;
    const score = consistent * 100 + counts[0];
    if (score > bestScore) { bestScore = score; best = d; }
  }
  return best;
}

function parseCsv(text: string, delimiter: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
        inQuotes = false; i++; continue;
      }
      field += ch; i++; continue;
    }
    if (ch === '"' && field === "") { inQuotes = true; i++; continue; }
    if (ch === delimiter) { row.push(field); field = ""; i++; continue; }
    if (ch === "\r" || ch === "\n") {
      row.push(field); field = "";
      rows.push(row); row = [];
      if (ch === "\r" && text[i + 1] === "\n") i++;
      i++;
      if (rows.length > MAX_CSV_ROWS + 1) break;
      continue;
    }
    field += ch; i++;
  }
  if (inQuotes) throw new Error("Unterminated quoted field in CSV");
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows;
}

function inferValue(v: string): unknown {
  const t = v.trim();
  if (t === "") return null;
  if (/^(true|false)$/i.test(t)) return t.toLowerCase() === "true";
  if (/^-?(0|[1-9]\d{0,14})(\.\d+)?([eE][+-]?\d+)?$/.test(t)) {
    const num = Number(t);
    if (Number.isFinite(num)) return num;
  }
  return v;
}

async function csvToJson(args: { csv?: string; url?: string; delimiter?: string; header?: boolean; inferTypes?: boolean; skipEmptyLines?: boolean; maxRows?: number }) {
  if (!args.csv && !args.url) throw new Error("Provide csv (text) or url");
  if (args.csv && args.url) throw new Error("Provide csv OR url, not both");
  let text: string;
  let source: Record<string, unknown>;
  if (args.csv) {
    text = String(args.csv);
    if (Buffer.byteLength(text, "utf8") > MAX_CSV_BYTES) throw new Error(`csv is over the ${MAX_CSV_BYTES}-byte limit`);
    source = { source: "text" };
  } else {
    const url = normalizeHttpUrl(args.url!);
    const r = await fetchCapped(url, MAX_CSV_BYTES, "text/csv, text/plain, */*");
    text = new TextDecoder("utf-8").decode(r.body);
    source = { source: "url", url: r.finalUrl, contentType: r.contentType || null };
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1); // strip BOM
  const delimiter = args.delimiter
    ? (args.delimiter === "\\t" || args.delimiter.toLowerCase() === "tab" ? "\t" : args.delimiter)
    : detectDelimiter(text);
  if (delimiter.length !== 1 || delimiter === '"' || delimiter === "\n" || delimiter === "\r") throw new Error("delimiter must be a single character other than quote or newline");
  const header = args.header ?? true;
  const inferTypes = args.inferTypes ?? true;
  const skipEmpty = args.skipEmptyLines ?? true;
  const maxRows = Math.min(MAX_CSV_ROWS, Math.max(1, Math.round(Number(args.maxRows) || MAX_CSV_ROWS)));

  let rows = parseCsv(text, delimiter);
  if (skipEmpty) rows = rows.filter((r) => !(r.length === 1 && r[0].trim() === ""));
  const warnings: string[] = [];
  let columns: string[] | null = null;
  if (header && rows.length) {
    const seen = new Map<string, number>();
    columns = rows.shift()!.map((h, idx) => {
      let name = h.trim() || `column_${idx + 1}`;
      const count = seen.get(name) ?? 0;
      seen.set(name, count + 1);
      if (count) { warnings.push(`Duplicate header "${name}" renamed to "${name}_${count + 1}"`); name = `${name}_${count + 1}`; }
      return name;
    });
  }
  const totalRows = rows.length;
  const truncated = totalRows > maxRows;
  if (truncated) rows = rows.slice(0, maxRows);
  const conv = (v: string) => (inferTypes ? inferValue(v) : v);
  let ragged = 0;
  const data = rows.map((r) => {
    if (!columns) return r.map(conv);
    if (r.length !== columns.length) ragged++;
    const obj: Record<string, unknown> = {};
    columns.forEach((c, idx) => { obj[c] = idx < r.length ? conv(r[idx]) : null; });
    if (r.length > columns.length) obj._extra = r.slice(columns.length).map(conv);
    return obj;
  });
  if (ragged) warnings.push(`${ragged} row(s) had a different number of fields than the header`);
  return {
    ...source,
    delimiter: delimiter === "\t" ? "\\t" : delimiter,
    header,
    columns,
    rowCount: data.length,
    totalRows,
    truncated,
    rows: data,
    warnings,
  };
}

// ---- image_resize --------------------------------------------------------------------------
const FITS = ["inside", "cover", "contain", "fill", "outside"] as const;
const FORMATS = ["png", "jpeg", "webp", "avif"] as const;

async function resizeImage(args: { url: string; width?: number; height?: number; fit?: string; format?: string; quality?: number; withoutEnlargement?: boolean; background?: string; includeBase64?: boolean }) {
  const url = normalizeHttpUrl(args.url);
  const width = args.width !== undefined && args.width !== null ? Math.round(Number(args.width)) : undefined;
  const height = args.height !== undefined && args.height !== null ? Math.round(Number(args.height)) : undefined;
  if (!width && !height) throw new Error("Provide width and/or height");
  for (const [k, v] of [["width", width], ["height", height]] as const) {
    if (v !== undefined && (!Number.isFinite(v) || v < 1 || v > MAX_OUTPUT_DIM)) throw new Error(`${k} must be between 1 and ${MAX_OUTPUT_DIM}`);
  }
  const fit = (FITS as readonly string[]).includes(args.fit ?? "") ? (args.fit as (typeof FITS)[number]) : "inside";
  const quality = Math.min(100, Math.max(1, Math.round(Number(args.quality) || 82)));
  const background = typeof args.background === "string" && /^#?[0-9a-f]{6}$/i.test(args.background) ? `#${args.background.replace(/^#/, "")}` : "#ffffff";

  const src = await fetchCapped(url, MAX_IMAGE_INPUT_BYTES, "image/avif,image/webp,image/png,image/jpeg,image/gif,image/*;q=0.8");
  let meta: sharp.Metadata;
  try {
    meta = await sharp(src.body, { limitInputPixels: MAX_INPUT_PIXELS, failOn: "error" }).metadata();
  } catch (e: any) {
    throw new Error(`Source is not a supported image (${src.contentType || "unknown type"}): ${e?.message ?? e}`);
  }
  const inFormat = meta.format ?? "unknown";
  let outFormat = (FORMATS as readonly string[]).includes(args.format ?? "") ? (args.format as (typeof FORMATS)[number]) : null;
  if (!outFormat) outFormat = inFormat === "jpeg" || inFormat === "jpg" ? "jpeg" : inFormat === "webp" ? "webp" : inFormat === "avif" || inFormat === "heif" ? "avif" : "png";

  let pipeline = sharp(src.body, { limitInputPixels: MAX_INPUT_PIXELS, failOn: "error", animated: false })
    .rotate() // honour EXIF orientation
    .resize({ width, height, fit, withoutEnlargement: args.withoutEnlargement ?? false, background });
  if (outFormat === "jpeg") pipeline = pipeline.flatten({ background }).jpeg({ quality, mozjpeg: true });
  else if (outFormat === "webp") pipeline = pipeline.webp({ quality });
  else if (outFormat === "avif") pipeline = pipeline.avif({ quality: Math.min(quality, 70) });
  else pipeline = pipeline.png({ compressionLevel: 9 });
  const { data, info } = await pipeline.toBuffer({ resolveWithObject: true });
  const ext = outFormat === "jpeg" ? "jpg" : outFormat;
  return {
    sourceUrl: src.finalUrl,
    source: { format: inFormat, width: meta.width ?? null, height: meta.height ?? null, bytes: src.body.byteLength },
    options: { width: width ?? null, height: height ?? null, fit, format: outFormat, quality: outFormat === "png" ? null : quality, withoutEnlargement: args.withoutEnlargement ?? false },
    image: {
      format: outFormat,
      width: info.width,
      height: info.height,
      ...storeFile(data, ext as any, !!args.includeBase64),
    },
  };
}

export const tools = {
  image_resize: {
    price: "$0.01",
    description:
      "Download an image from a URL and resize it with libvips (sharp): set width and/or height, fit mode (inside keeps aspect ratio within the box, cover crops to fill, contain letterboxes, fill stretches), output format (PNG, JPEG, WebP, AVIF) and quality. Honors EXIF rotation. Input up to 15 MB / 50 megapixels, output up to 4096px per side. Returns a short-lived download URL (valid 1 hour) with final dimensions and byte size; set includeBase64 for the bytes inline (up to 3 MB). Deterministic, no AI.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Public URL of the source image (PNG, JPEG, WebP, AVIF, GIF, TIFF, SVG)" },
        width: { type: "number", description: "Target width in pixels, 1-4096 (give width, height, or both)" },
        height: { type: "number", description: "Target height in pixels, 1-4096" },
        fit: { type: "string", enum: [...FITS], description: "How to fit both dimensions (default inside = keep aspect ratio, no crop)" },
        format: { type: "string", enum: [...FORMATS], description: "Output format (default: same family as the source, PNG otherwise)" },
        quality: { type: "number", description: "JPEG/WebP/AVIF quality 1-100 (default 82)" },
        withoutEnlargement: { type: "boolean", description: "Never upscale a smaller source (default false)" },
        background: { type: "string", description: "Hex color for contain padding / JPEG flattening, e.g. #ffffff (default white)" },
        includeBase64: { type: "boolean", description: "Also return the image as base64 in the response (default false; omitted if over 3 MB)" },
      },
      required: ["url"],
    },
    async run(args: any) {
      return resizeImage(args);
    },
  },

  csv_to_json: {
    price: "$0.01",
    description:
      "Convert CSV to JSON with a strict RFC 4180 parser: quoted fields, escaped quotes, embedded newlines, CRLF, BOM. Auto-detects the delimiter (comma, semicolon, tab, pipe) or takes one; uses the first row as keys by default (or returns arrays), and optionally infers numbers, booleans and empty-as-null. Pass CSV text or a URL to fetch (max 2 MB, 10,000 rows returned; truncation is flagged). Deterministic, no AI.",
    inputSchema: {
      type: "object",
      properties: {
        csv: { type: "string", description: "CSV text (provide csv OR url)" },
        url: { type: "string", description: "Public URL of a CSV file to fetch instead" },
        delimiter: { type: "string", description: "Field delimiter: ',', ';', '|', or 'tab' (default auto-detect)" },
        header: { type: "boolean", description: "Treat the first row as column names and return objects (default true); false returns arrays" },
        inferTypes: { type: "boolean", description: "Convert numbers, true/false, and empty cells to null (default true); false keeps every value a string" },
        skipEmptyLines: { type: "boolean", description: "Drop blank lines (default true)" },
        maxRows: { type: "number", description: "Maximum data rows to return, up to 10,000 (default 10,000)" },
      },
    },
    async run(args: any) {
      return csvToJson(args);
    },
  },
};

export type ToolName = keyof typeof tools;
