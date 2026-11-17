// Deterministic validators that pair with email_address_validate: phone numbers (libphonenumber
// metadata), EU VAT numbers (official EU VIES service), and US postal addresses (USPS Pub. 28
// standard abbreviations). No AI — rule tables and official lookups only.
import { parsePhoneNumberFromString, isPossiblePhoneNumber, type CountryCode } from "libphonenumber-js/max";

// ---- phone_validate ------------------------------------------------------------------------
function validatePhone(phone: string, defaultCountry?: string) {
  const input = String(phone ?? "").trim();
  if (!input) throw new Error("phone is required");
  if (input.length > 64) throw new Error("phone is too long");
  const country = defaultCountry ? (defaultCountry.trim().toUpperCase() as CountryCode) : undefined;
  const parsed = parsePhoneNumberFromString(input, country ? { defaultCountry: country } : undefined);
  if (!parsed) {
    return {
      input,
      defaultCountry: country ?? null,
      valid: false,
      possible: false,
      reason: country
        ? "Could not parse a phone number from the input"
        : "Could not parse a phone number; include the +country code or pass defaultCountry (e.g. US)",
    };
  }
  const valid = parsed.isValid();
  return {
    input,
    defaultCountry: country ?? null,
    valid,
    possible: parsed.isPossible(),
    possibleLength: isPossiblePhoneNumber(parsed.number),
    e164: parsed.number,
    international: parsed.formatInternational(),
    national: parsed.formatNational(),
    uri: parsed.getURI(),
    country: parsed.country ?? null,
    countryCallingCode: `+${parsed.countryCallingCode}`,
    nationalNumber: parsed.nationalNumber,
    extension: parsed.ext ?? null,
    type: valid ? (parsed.getType() ?? "UNKNOWN") : null,
    reason: valid ? null : parsed.isPossible() ? "Number has a plausible length but is not a valid number for its region" : "Number length is not possible for its region",
  };
}

// ---- vat_validate --------------------------------------------------------------------------
const VAT_FORMATS: Record<string, { name: string; re: RegExp }> = {
  AT: { name: "Austria", re: /^U\d{8}$/ },
  BE: { name: "Belgium", re: /^[01]\d{9}$/ },
  BG: { name: "Bulgaria", re: /^\d{9,10}$/ },
  CY: { name: "Cyprus", re: /^\d{8}[A-Z]$/ },
  CZ: { name: "Czechia", re: /^\d{8,10}$/ },
  DE: { name: "Germany", re: /^\d{9}$/ },
  DK: { name: "Denmark", re: /^\d{8}$/ },
  EE: { name: "Estonia", re: /^\d{9}$/ },
  EL: { name: "Greece", re: /^\d{9}$/ },
  ES: { name: "Spain", re: /^[A-Z0-9]\d{7}[A-Z0-9]$/ },
  FI: { name: "Finland", re: /^\d{8}$/ },
  FR: { name: "France", re: /^[A-HJ-NP-Z0-9]{2}\d{9}$/ },
  HR: { name: "Croatia", re: /^\d{11}$/ },
  HU: { name: "Hungary", re: /^\d{8}$/ },
  IE: { name: "Ireland", re: /^(\d{7}[A-W][A-IW]?|\d[A-Z+*]\d{5}[A-W])$/ },
  IT: { name: "Italy", re: /^\d{11}$/ },
  LT: { name: "Lithuania", re: /^(\d{9}|\d{12})$/ },
  LU: { name: "Luxembourg", re: /^\d{8}$/ },
  LV: { name: "Latvia", re: /^\d{11}$/ },
  MT: { name: "Malta", re: /^\d{8}$/ },
  NL: { name: "Netherlands", re: /^\d{9}B\d{2}$/ },
  PL: { name: "Poland", re: /^\d{10}$/ },
  PT: { name: "Portugal", re: /^\d{9}$/ },
  RO: { name: "Romania", re: /^\d{2,10}$/ },
  SE: { name: "Sweden", re: /^\d{12}$/ },
  SI: { name: "Slovenia", re: /^\d{8}$/ },
  SK: { name: "Slovakia", re: /^\d{10}$/ },
  XI: { name: "Northern Ireland", re: /^(\d{9}|\d{12}|GD\d{3}|HA\d{3})$/ },
};

const VIES_ENDPOINT = "https://ec.europa.eu/taxation_customs/vies/rest-api/check-vat-number";
const VIES_UNAVAILABLE = /MS_UNAVAILABLE|SERVICE_UNAVAILABLE|TIMEOUT|MS_MAX_CONCURRENT_REQ|GLOBAL_MAX_CONCURRENT_REQ|SERVER_BUSY/i;

function viesText(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const t = v.trim();
  return !t || t === "---" ? null : t.replace(/\s*\n\s*/g, ", ");
}

async function validateVat(vatNumber: string, countryCode?: string) {
  let raw = String(vatNumber ?? "").toUpperCase().replace(/[\s.\-_/]/g, "");
  if (!raw) throw new Error("vatNumber is required");
  let cc = countryCode ? countryCode.trim().toUpperCase() : "";
  if (/^[A-Z]{2}/.test(raw) && (!cc || raw.startsWith(cc) || (cc === "GR" && raw.startsWith("EL")))) {
    const prefix = raw.slice(0, 2);
    if (VAT_FORMATS[prefix] || prefix === "GR") { cc = prefix; raw = raw.slice(2); }
  }
  if (cc === "GR") cc = "EL"; // VIES uses EL for Greece
  if (!cc) throw new Error("Include the 2-letter country prefix in vatNumber (e.g. IE6388047V) or pass countryCode");
  const fmt = VAT_FORMATS[cc];
  if (!fmt) throw new Error(`${cc} is not an EU VIES member state code (VIES covers EU countries and XI/Northern Ireland only)`);
  const formatValid = fmt.re.test(raw);
  const base = { input: vatNumber, countryCode: cc, country: fmt.name, vatNumber: raw, formatValid };
  if (!formatValid) {
    return { ...base, valid: false, source: "format", reason: `Does not match the ${fmt.name} VAT number format, so VIES was not queried` };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15_000);
  let data: any;
  try {
    const res = await fetch(VIES_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
      body: JSON.stringify({ countryCode: cc, vatNumber: raw }),
      signal: controller.signal,
    });
    const text = await res.text();
    try { data = JSON.parse(text); } catch { data = null; }
    if (!res.ok && !data) throw new Error(`HTTP ${res.status}`);
  } catch (e: any) {
    // Thrown errors refund API-key credits; the caller can retry later.
    throw new Error(`EU VIES service is unreachable right now (${e?.name === "AbortError" ? "timeout" : e?.message ?? e}). The number's format is valid for ${fmt.name}; retry later for the official check.`);
  } finally {
    clearTimeout(timer);
  }

  const errorCode: string | undefined = data?.errorWrappers?.[0]?.error ?? data?.userError ?? (data?.actionSucceed === false ? "UNKNOWN_ERROR" : undefined);
  if (errorCode && errorCode !== "VALID" && errorCode !== "INVALID") {
    if (VIES_UNAVAILABLE.test(errorCode)) {
      throw new Error(`EU VIES cannot check ${fmt.name} numbers right now (${errorCode}); the member state's service is down or busy. The number's format is valid; retry later for the official check.`);
    }
    if (/INVALID_INPUT/i.test(errorCode)) {
      return { ...base, valid: false, source: "vies", reason: "VIES rejected the input as malformed (INVALID_INPUT)" };
    }
    throw new Error(`EU VIES returned an error: ${errorCode}`);
  }
  const valid = data?.valid === true || data?.isValid === true;
  return {
    ...base,
    valid,
    source: "vies",
    name: viesText(data?.name),
    address: viesText(data?.address),
    requestDate: data?.requestDate ?? new Date().toISOString(),
    reason: valid ? null : "VIES reports this VAT number is not active/registered for intra-EU trade",
  };
}

// ---- address_normalize ---------------------------------------------------------------------
const STATES: Record<string, string> = {
  ALABAMA: "AL", ALASKA: "AK", ARIZONA: "AZ", ARKANSAS: "AR", CALIFORNIA: "CA", COLORADO: "CO", CONNECTICUT: "CT",
  DELAWARE: "DE", "DISTRICT OF COLUMBIA": "DC", FLORIDA: "FL", GEORGIA: "GA", HAWAII: "HI", IDAHO: "ID", ILLINOIS: "IL",
  INDIANA: "IN", IOWA: "IA", KANSAS: "KS", KENTUCKY: "KY", LOUISIANA: "LA", MAINE: "ME", MARYLAND: "MD",
  MASSACHUSETTS: "MA", MICHIGAN: "MI", MINNESOTA: "MN", MISSISSIPPI: "MS", MISSOURI: "MO", MONTANA: "MT",
  NEBRASKA: "NE", NEVADA: "NV", "NEW HAMPSHIRE": "NH", "NEW JERSEY": "NJ", "NEW MEXICO": "NM", "NEW YORK": "NY",
  "NORTH CAROLINA": "NC", "NORTH DAKOTA": "ND", OHIO: "OH", OKLAHOMA: "OK", OREGON: "OR", PENNSYLVANIA: "PA",
  "RHODE ISLAND": "RI", "SOUTH CAROLINA": "SC", "SOUTH DAKOTA": "SD", TENNESSEE: "TN", TEXAS: "TX", UTAH: "UT",
  VERMONT: "VT", VIRGINIA: "VA", WASHINGTON: "WA", "WEST VIRGINIA": "WV", WISCONSIN: "WI", WYOMING: "WY",
  "PUERTO RICO": "PR", GUAM: "GU", "VIRGIN ISLANDS": "VI", "AMERICAN SAMOA": "AS", "NORTHERN MARIANA ISLANDS": "MP",
};
const STATE_CODES = new Set([...Object.values(STATES), "AA", "AE", "AP"]);

// USPS Publication 28, Appendix C1 (common street suffixes) -> standard abbreviation.
const SUFFIXES: Record<string, string> = {
  ALLEY: "ALY", ALY: "ALY", ANNEX: "ANX", ARCADE: "ARC", AVENUE: "AVE", AVE: "AVE", AV: "AVE", AVEN: "AVE", AVNUE: "AVE",
  BAYOU: "BYU", BEACH: "BCH", BEND: "BND", BLUFF: "BLF", BOULEVARD: "BLVD", BLVD: "BLVD", BOUL: "BLVD", BRANCH: "BR",
  BRIDGE: "BRG", BROOK: "BRK", BYPASS: "BYP", CAMP: "CP", CANYON: "CYN", CAPE: "CPE", CAUSEWAY: "CSWY", CENTER: "CTR",
  CENTRE: "CTR", CTR: "CTR", CIRCLE: "CIR", CIR: "CIR", CIRCL: "CIR", CLIFF: "CLF", CLUB: "CLB", COMMON: "CMN",
  CORNER: "COR", CORNERS: "CORS", COURSE: "CRSE", COURT: "CT", CT: "CT", COURTS: "CTS", COVE: "CV", CREEK: "CRK",
  CRESCENT: "CRES", CREST: "CRST", CROSSING: "XING", CROSSROAD: "XRD", CURVE: "CURV", DALE: "DL", DAM: "DM",
  DIVIDE: "DV", DRIVE: "DR", DR: "DR", DRIV: "DR", DRV: "DR", ESTATE: "EST", ESTATES: "ESTS", EXPRESSWAY: "EXPY",
  EXPY: "EXPY", EXTENSION: "EXT", EXT: "EXT", FALLS: "FLS", FERRY: "FRY", FIELD: "FLD", FIELDS: "FLDS", FLAT: "FLT",
  FORD: "FRD", FOREST: "FRST", FORGE: "FRG", FORK: "FRK", FORT: "FT", FREEWAY: "FWY", FWY: "FWY", GARDEN: "GDN",
  GARDENS: "GDNS", GATEWAY: "GTWY", GLEN: "GLN", GREEN: "GRN", GROVE: "GRV", HARBOR: "HBR", HAVEN: "HVN",
  HEIGHTS: "HTS", HTS: "HTS", HIGHWAY: "HWY", HWY: "HWY", HIGHWY: "HWY", HILL: "HL", HILLS: "HLS", HOLLOW: "HOLW",
  INLET: "INLT", ISLAND: "IS", ISLANDS: "ISS", JUNCTION: "JCT", KEY: "KY", KNOLL: "KNL", LAKE: "LK", LAKES: "LKS",
  LANDING: "LNDG", LANE: "LN", LN: "LN", LIGHT: "LGT", LOAF: "LF", LOCK: "LCK", LODGE: "LDG", LOOP: "LOOP",
  MALL: "MALL", MANOR: "MNR", MEADOW: "MDW", MEADOWS: "MDWS", MILL: "ML", MILLS: "MLS", MISSION: "MSN",
  MOTORWAY: "MTWY", MOUNT: "MT", MOUNTAIN: "MTN", NECK: "NCK", ORCHARD: "ORCH", OVAL: "OVAL", OVERPASS: "OPAS",
  PARK: "PARK", PARKWAY: "PKWY", PKWY: "PKWY", PKY: "PKWY", PASS: "PASS", PASSAGE: "PSGE", PATH: "PATH", PIKE: "PIKE",
  PINE: "PNE", PINES: "PNES", PLACE: "PL", PL: "PL", PLAIN: "PLN", PLAINS: "PLNS", PLAZA: "PLZ", PLZ: "PLZ",
  POINT: "PT", POINTS: "PTS", PORT: "PRT", PRAIRIE: "PR", RADIAL: "RADL", RANCH: "RNCH", RAPIDS: "RPDS", REST: "RST",
  RIDGE: "RDG", RIVER: "RIV", ROAD: "RD", RD: "RD", ROADS: "RDS", ROUTE: "RTE", ROW: "ROW", RUN: "RUN",
  SHOAL: "SHL", SHORE: "SHR", SHORES: "SHRS", SKYWAY: "SKWY", SPRING: "SPG", SPRINGS: "SPGS", SQUARE: "SQ", SQ: "SQ",
  STATION: "STA", STRAVENUE: "STRA", STREAM: "STRM", STREET: "ST", ST: "ST", STR: "ST", STRT: "ST", STREETS: "STS",
  SUMMIT: "SMT", TERRACE: "TER", TER: "TER", THROUGHWAY: "TRWY", TRACE: "TRCE", TRACK: "TRAK", TRAIL: "TRL", TRL: "TRL",
  TRAILER: "TRLR", TUNNEL: "TUNL", TURNPIKE: "TPKE", UNDERPASS: "UPAS", UNION: "UN", VALLEY: "VLY", VIADUCT: "VIA",
  VIEW: "VW", VILLAGE: "VLG", VILLE: "VL", VISTA: "VIS", WALK: "WALK", WALL: "WALL", WAY: "WAY", WELL: "WL", WELLS: "WLS",
};
const DIRECTIONS: Record<string, string> = {
  NORTH: "N", SOUTH: "S", EAST: "E", WEST: "W", NORTHEAST: "NE", NORTHWEST: "NW", SOUTHEAST: "SE", SOUTHWEST: "SW",
  N: "N", S: "S", E: "E", W: "W", NE: "NE", NW: "NW", SE: "SE", SW: "SW",
};
// USPS Pub. 28 Appendix C2 secondary unit designators.
const UNITS: Record<string, string> = {
  APARTMENT: "APT", APT: "APT", BASEMENT: "BSMT", BUILDING: "BLDG", BLDG: "BLDG", DEPARTMENT: "DEPT", DEPT: "DEPT",
  FLOOR: "FL", FL: "FL", FRONT: "FRNT", HANGAR: "HNGR", KEY: "KEY", LOBBY: "LBBY", LOT: "LOT", LOWER: "LOWR",
  OFFICE: "OFC", OFC: "OFC", PENTHOUSE: "PH", PH: "PH", PIER: "PIER", REAR: "REAR", ROOM: "RM", RM: "RM", SIDE: "SIDE",
  SLIP: "SLIP", SPACE: "SPC", SPC: "SPC", STOP: "STOP", SUITE: "STE", STE: "STE", TRAILER: "TRLR", UNIT: "UNIT",
  UPPER: "UPPR", "#": "#",
};

function tokens(s: string) { return s.split(/\s+/).filter(Boolean); }

function normalizeStreet(line: string) {
  const warnings: string[] = [];
  let s = line.toUpperCase().replace(/[.,]/g, " ").replace(/\s*#\s*/g, " # ").replace(/\s+/g, " ").trim();
  // PO Box
  const po = s.match(/^(?:P\s*O|POST\s+OFFICE)?\s*BOX\s+(\w+)$/) || s.match(/^PO\s*BOX\s+(\w+)$/);
  if (po) return { line: `PO BOX ${po[1]}`, parts: { poBox: po[1] }, warnings };
  let t = tokens(s);
  let unit: { type: string; number: string | null } | null = null;
  // Secondary unit: designator + optional number, anywhere after the first two tokens.
  const NO_NUMBER = new Set(["BSMT", "FRNT", "LBBY", "LOWR", "OFC", "PH", "REAR", "SIDE", "UPPR"]);
  const UNIT_ID = /^#?([A-Z]?\d+[A-Z]?(-\d+)?|[A-Z])$/;
  for (let i = 2; i < t.length; i++) {
    const d = UNITS[t[i]];
    if (!d) continue;
    if (d !== "#" && t[i + 1] === "#" && t[i + 2]) t.splice(i + 1, 1); // "APT # 4" -> "APT 4"
    const next = t[i + 1];
    if (next && UNIT_ID.test(next)) {
      unit = { type: d, number: next.replace(/^#/, "") };
      t = t.slice(0, i).concat(t.slice(i + 2));
      break;
    }
    if (NO_NUMBER.has(d) && i === t.length - 1) {
      unit = { type: d, number: null };
      t = t.slice(0, i);
      break;
    }
  }
  let number: string | null = null;
  if (t.length && /^\d+[A-Z]?(-\d+[A-Z]?)?$|^\d+\s?\d\/\d$/.test(t[0])) number = t.shift()!;
  else warnings.push("No house number found at the start of the street line");
  let pre: string | null = null;
  if (t.length > 1 && DIRECTIONS[t[0]]) pre = DIRECTIONS[t.shift()!];
  let post: string | null = null;
  if (t.length > 1 && DIRECTIONS[t[t.length - 1]]) post = DIRECTIONS[t.pop()!];
  let suffix: string | null = null;
  if (t.length > 1 && SUFFIXES[t[t.length - 1]]) suffix = SUFFIXES[t.pop()!];
  const name = t.join(" ");
  if (!name) warnings.push("Street name is empty");
  const unitStr = unit ? (unit.type === "#" ? `# ${unit.number ?? ""}` : `${unit.type}${unit.number ? ` ${unit.number}` : ""}`).trim() : null;
  const out = [number, pre, name, suffix, post, unitStr].filter(Boolean).join(" ");
  return {
    line: out,
    parts: { houseNumber: number, preDirectional: pre, streetName: name || null, suffix, postDirectional: post, unitType: unit?.type ?? null, unitNumber: unit?.number ?? null },
    warnings,
  };
}

function normalizeAddress(address: string, country?: string) {
  const input = String(address ?? "").trim();
  if (!input) throw new Error("address is required");
  if (input.length > 500) throw new Error("address is too long (max 500 characters)");
  const cc = (country ?? "US").trim().toUpperCase();
  const warnings: string[] = [];
  let parts = input.replace(/\r?\n/g, ",").split(",").map((p) => p.trim()).filter(Boolean);

  if (cc !== "US" && cc !== "USA") {
    const cleaned = parts.map((p) => p.replace(/\s+/g, " ")).join(", ");
    return {
      input, country: cc, normalized: cleaned, components: null, standard: "whitespace-only",
      warnings: ["Full normalization is US-only (USPS Publication 28); non-US addresses get whitespace/comma cleanup only"],
      verified: false,
    };
  }

  // Drop a trailing country.
  if (parts.length && /^(USA?|UNITED STATES( OF AMERICA)?)$/i.test(parts[parts.length - 1])) parts.pop();

  let state: string | null = null;
  let zip: string | null = null;
  let city: string | null = null;
  // Last part usually "STATE ZIP" or "CITY STATE ZIP".
  if (parts.length) {
    let last = parts[parts.length - 1].toUpperCase().replace(/\./g, "").replace(/\s+/g, " ").trim();
    const zm = last.match(/\b(\d{5})(?:[- ]?(\d{4}))?$/);
    if (zm) { zip = zm[2] ? `${zm[1]}-${zm[2]}` : zm[1]; last = last.slice(0, zm.index).trim(); }
    const tk = tokens(last);
    if (tk.length && STATE_CODES.has(tk[tk.length - 1])) { state = tk.pop()!; }
    else {
      for (let n = Math.min(4, tk.length); n >= 1; n--) {
        const name = tk.slice(tk.length - n).join(" ");
        if (STATES[name]) { state = STATES[name]; tk.splice(tk.length - n, n); break; }
      }
    }
    const rest = tk.join(" ");
    if (state || zip) {
      parts.pop();
      if (rest) city = rest;
    }
  }
  if (!city && parts.length >= 2) city = parts.pop()!.toUpperCase().replace(/\./g, "").replace(/\s+/g, " ").trim();
  if (!parts.length) throw new Error("Could not find a street line in the address");

  // Remaining parts: street line(s). A second line that is only a unit gets merged.
  let streetLine = parts[0];
  const extras = parts.slice(1);
  for (const extra of extras) {
    const first = tokens(extra.toUpperCase().replace(/[.,#]/g, " "))[0];
    if (first && UNITS[first]) streetLine += ` ${extra}`;
    else if (/^#\s*\w+$/.test(extra)) streetLine += ` ${extra}`;
    else { warnings.push(`Ignored extra address line: "${extra}"`); }
  }
  const street = normalizeStreet(streetLine);
  warnings.push(...street.warnings);
  if (!state) warnings.push("No US state found");
  if (!zip) warnings.push("No ZIP code found");
  if (!city) warnings.push("No city found");

  const lastLine = [city, state].filter(Boolean).join(" ") + (zip ? `  ${zip}` : "");
  const normalized = [street.line, lastLine.trim()].filter(Boolean).join(", ").replace(/ {2}/, " ");
  return {
    input,
    country: "US",
    normalized,
    lines: { delivery: street.line, lastLine: lastLine.trim().replace(/ {2}/, " ") || null },
    components: { ...street.parts, city, state, zip5: zip ? zip.slice(0, 5) : null, zip4: zip && zip.length > 5 ? zip.slice(6) : null },
    standard: "USPS Publication 28 abbreviations, uppercase",
    verified: false,
    note: "Formatting only — the address is not checked against the USPS delivery database.",
    warnings,
  };
}

export const tools = {
  phone_validate: {
    price: "$0.01",
    description:
      "Validate and format a phone number with Google's libphonenumber metadata: valid/possible for its region, E.164, international and national formats, tel: URI, country, and line type (MOBILE, FIXED_LINE, TOLL_FREE, VOIP, …). Pass defaultCountry for numbers written without a +country code. Offline metadata check — it does not dial or confirm the line is in service. Companion to email_address_validate.",
    inputSchema: {
      type: "object",
      properties: {
        phone: { type: "string", description: "Phone number in any common format, e.g. +1 650-253-0000 or (650) 253-0000" },
        defaultCountry: { type: "string", description: "ISO 3166-1 alpha-2 country to assume when the number has no + prefix, e.g. US, GB, DE" },
      },
      required: ["phone"],
    },
    async run({ phone, defaultCountry }: { phone: string; defaultCountry?: string }) {
      return validatePhone(phone, defaultCountry);
    },
  },

  vat_validate: {
    price: "$0.01",
    description:
      "Validate an EU VAT number against the European Commission's official VIES service: checks the country-specific format first, then asks VIES whether the number is active for intra-EU trade and returns the registered business name and address when the member state shares them. Covers all EU states plus XI (Northern Ireland); Greece accepts GR or EL. If VIES or the member state's service is down, the call errors (API-key credits are refunded) instead of guessing.",
    inputSchema: {
      type: "object",
      properties: {
        vatNumber: { type: "string", description: "VAT number, ideally with its country prefix, e.g. IE6388047V or DE 123456789" },
        countryCode: { type: "string", description: "2-letter EU country code if vatNumber has no prefix, e.g. DE" },
      },
      required: ["vatNumber"],
    },
    async run({ vatNumber, countryCode }: { vatNumber: string; countryCode?: string }) {
      return validateVat(vatNumber, countryCode);
    },
  },

  address_normalize: {
    price: "$0.01",
    description:
      "Normalize a free-form US postal address to USPS Publication 28 style, deterministically (rule tables, no AI): uppercase, standard street-suffix, directional and unit abbreviations (Street -> ST, Suite -> STE, North -> N), state names to 2-letter codes, ZIP/ZIP+4 cleanup, and a parsed breakdown (house number, street, unit, city, state, ZIP). Formatting only — it does not verify the address is deliverable. Non-US addresses get whitespace cleanup only.",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string", description: "Full address on one line or several, e.g. '1600 Pennsylvania Avenue Northwest, Washington, District of Columbia 20500'" },
        country: { type: "string", description: "ISO country code (default US; only US gets full normalization)" },
      },
      required: ["address"],
    },
    async run({ address, country }: { address: string; country?: string }) {
      return normalizeAddress(address, country);
    },
  },
};

export type ToolName = keyof typeof tools;
