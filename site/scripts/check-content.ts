/**
 * Fail on forbidden tokens and whitespace-glued copy.
 * Warn, without failing, on links that do not resolve inside dist.
 *
 * Forbidden tokens are compared as SHA-256 digests so a personal identifier
 * never appears as plain text in this public repo. HTML character references
 * are decoded and the text is Unicode-NFKC normalized before tokens are split,
 * lowercased, and hashed. Every printed line is redacted so a forbidden token
 * in a path, href, or sample is not echoed.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const dist = path.resolve(import.meta.dir, '../dist');
const base = '';

/**
 * SHA-256 hex digests of lowercased tokens that must not appear in built HTML.
 * Hashes, not the words: this repository is public and must not store personal
 * identifiers as plain text.
 */
const FORBIDDEN_TOKEN_SHA256 = [
  '6d0b27514ad5e4618c90bcf9aa3cf3c1ed021bbbbb459f895ac868c3f6e71462',
] as const;

/**
 * Common named character references (HTML 4 plus usual punctuation and spaces).
 * Numeric references cover every other code point. Values are code points.
 */
const NAMED_CODEPOINTS: readonly (readonly [string, number])[] = [
  ['apos', 0x27],
  ['amp', 0x26],
  ['lt', 0x3c],
  ['gt', 0x3e],
  ['quot', 0x22],
  ['nbsp', 0xa0],
  ['iexcl', 0xa1],
  ['cent', 0xa2],
  ['pound', 0xa3],
  ['curren', 0xa4],
  ['yen', 0xa5],
  ['brvbar', 0xa6],
  ['sect', 0xa7],
  ['uml', 0xa8],
  ['copy', 0xa9],
  ['ordf', 0xaa],
  ['laquo', 0xab],
  ['not', 0xac],
  ['shy', 0xad],
  ['reg', 0xae],
  ['macr', 0xaf],
  ['deg', 0xb0],
  ['plusmn', 0xb1],
  ['sup2', 0xb2],
  ['sup3', 0xb3],
  ['acute', 0xb4],
  ['micro', 0xb5],
  ['para', 0xb6],
  ['middot', 0xb7],
  ['cedil', 0xb8],
  ['sup1', 0xb9],
  ['ordm', 0xba],
  ['raquo', 0xbb],
  ['frac14', 0xbc],
  ['frac12', 0xbd],
  ['frac34', 0xbe],
  ['iquest', 0xbf],
  ['Agrave', 0xc0],
  ['Aacute', 0xc1],
  ['Acirc', 0xc2],
  ['Atilde', 0xc3],
  ['Auml', 0xc4],
  ['Aring', 0xc5],
  ['AElig', 0xc6],
  ['Ccedil', 0xc7],
  ['Egrave', 0xc8],
  ['Eacute', 0xc9],
  ['Ecirc', 0xca],
  ['Euml', 0xcb],
  ['Igrave', 0xcc],
  ['Iacute', 0xcd],
  ['Icirc', 0xce],
  ['Iuml', 0xcf],
  ['ETH', 0xd0],
  ['Ntilde', 0xd1],
  ['Ograve', 0xd2],
  ['Oacute', 0xd3],
  ['Ocirc', 0xd4],
  ['Otilde', 0xd5],
  ['Ouml', 0xd6],
  ['times', 0xd7],
  ['Oslash', 0xd8],
  ['Ugrave', 0xd9],
  ['Uacute', 0xda],
  ['Ucirc', 0xdb],
  ['Uuml', 0xdc],
  ['Yacute', 0xdd],
  ['THORN', 0xde],
  ['szlig', 0xdf],
  ['agrave', 0xe0],
  ['aacute', 0xe1],
  ['acirc', 0xe2],
  ['atilde', 0xe3],
  ['auml', 0xe4],
  ['aring', 0xe5],
  ['aelig', 0xe6],
  ['ccedil', 0xe7],
  ['egrave', 0xe8],
  ['eacute', 0xe9],
  ['ecirc', 0xea],
  ['euml', 0xeb],
  ['igrave', 0xec],
  ['iacute', 0xed],
  ['icirc', 0xee],
  ['iuml', 0xef],
  ['eth', 0xf0],
  ['ntilde', 0xf1],
  ['ograve', 0xf2],
  ['oacute', 0xf3],
  ['ocirc', 0xf4],
  ['otilde', 0xf5],
  ['ouml', 0xf6],
  ['divide', 0xf7],
  ['oslash', 0xf8],
  ['ugrave', 0xf9],
  ['uacute', 0xfa],
  ['ucirc', 0xfb],
  ['uuml', 0xfc],
  ['yacute', 0xfd],
  ['thorn', 0xfe],
  ['yuml', 0xff],
  ['OElig', 0x152],
  ['oelig', 0x153],
  ['Scaron', 0x160],
  ['scaron', 0x161],
  ['Yuml', 0x178],
  ['fnof', 0x192],
  ['circ', 0x2c6],
  ['tilde', 0x2dc],
  ['ensp', 0x2002],
  ['emsp', 0x2003],
  ['thinsp', 0x2009],
  ['zwnj', 0x200c],
  ['zwj', 0x200d],
  ['lrm', 0x200e],
  ['rlm', 0x200f],
  ['ndash', 0x2013],
  ['mdash', 0x2014],
  ['lsquo', 0x2018],
  ['rsquo', 0x2019],
  ['sbquo', 0x201a],
  ['ldquo', 0x201c],
  ['rdquo', 0x201d],
  ['bdquo', 0x201e],
  ['dagger', 0x2020],
  ['Dagger', 0x2021],
  ['bull', 0x2022],
  ['hellip', 0x2026],
  ['permil', 0x2030],
  ['lsaquo', 0x2039],
  ['rsaquo', 0x203a],
  ['euro', 0x20ac],
  ['trade', 0x2122],
  ['minus', 0x2212],
];

/** HTML numeric references in 0x80–0x9F use the Windows-1252 characters. */
const WINDOWS_1252: Readonly<Record<number, string>> = {
  0x80: '\u20AC',
  0x82: '\u201A',
  0x83: '\u0192',
  0x84: '\u201E',
  0x85: '\u2026',
  0x86: '\u2020',
  0x87: '\u2021',
  0x88: '\u02C6',
  0x89: '\u2030',
  0x8a: '\u0160',
  0x8b: '\u2039',
  0x8c: '\u0152',
  0x8e: '\u017D',
  0x91: '\u2018',
  0x92: '\u2019',
  0x93: '\u201C',
  0x94: '\u201D',
  0x95: '\u2022',
  0x96: '\u2013',
  0x97: '\u2014',
  0x98: '\u02DC',
  0x99: '\u2122',
  0x9a: '\u0161',
  0x9b: '\u203A',
  0x9c: '\u0153',
  0x9e: '\u017E',
  0x9f: '\u0178',
};

function namedEntities(): ReadonlyMap<string, string> {
  const named = new Map<string, string>();
  for (const [name, cp] of NAMED_CODEPOINTS) named.set(name, String.fromCodePoint(cp));
  // All-caps aliases. Capital-letter names (AElig → AELIG) claim the alias
  // before a lowercase name (aelig) can point that spelling at a different character.
  const claim = (name: string, cp: number) => {
    const upper = name.toUpperCase();
    if (upper !== name && !named.has(upper)) named.set(upper, String.fromCodePoint(cp));
  };
  for (const [name, cp] of NAMED_CODEPOINTS) {
    if (name !== name.toLowerCase()) claim(name, cp);
  }
  for (const [name, cp] of NAMED_CODEPOINTS) {
    if (name === name.toLowerCase()) claim(name, cp);
  }
  return named;
}

const NAMED = namedEntities();

/** Decimal `&#121;`, hex `&#x79;`, and a named reference such as `&amp;`. Semicolon optional. */
const CHAR_REF = /&(?:#[xX]([0-9a-fA-F]+)|#([0-9]+)|([A-Za-z][A-Za-z0-9]+));?/g;

function parseCodePoint(digits: string, radix: number): number {
  const trimmed = digits.replace(/^0+(?=\d)/, '');
  const limit = radix === 16 ? 6 : 7;
  if (trimmed.length > limit) return 0x11_0000;
  const cp = radix === 16 ? Number.parseInt(trimmed, 16) : Number(trimmed);
  return Number.isInteger(cp) ? cp : 0x11_0000;
}

function fromNumericReference(cp: number): string {
  if (!Number.isInteger(cp) || cp < 0 || cp > 0x10_ffff) return '\uFFFD';
  const win = WINDOWS_1252[cp];
  if (win !== undefined) return win;
  if (cp === 0 || (cp >= 0xd8_00 && cp <= 0xdf_ff)) return '\uFFFD';
  return String.fromCodePoint(cp);
}

/** One HTML parse of character references. Does not decode twice (`&amp;amp;` stays `&amp;`). */
function decodeHtmlCharRefs(input: string): string {
  return input.replace(CHAR_REF, (match, hex: string | undefined, dec: string | undefined, name: string | undefined) => {
    if (typeof hex === 'string') return fromNumericReference(parseCodePoint(hex, 16));
    if (typeof dec === 'string') return fromNumericReference(parseCodePoint(dec, 10));
    if (typeof name === 'string') {
      const value = NAMED.get(name);
      if (value !== undefined) return value;
    }
    return match;
  });
}

function extraForbiddenDigests(): string[] {
  const raw = process.env.POSTKEEP_FORBIDDEN_SHA256;
  if (!raw) return [];
  return raw
    .split(/[\s,]+/)
    .map((part) => part.trim().toLowerCase())
    .filter((part) => /^[0-9a-f]{64}$/.test(part));
}

function sha256Hex(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Decode character references, NFKC-normalize, then split on non-letters and
 * non-digits and lowercase. Unique per call.
 */
function tokensOf(html: string): Set<string> {
  const text = decodeHtmlCharRefs(html).normalize('NFKC');
  const unique = new Set<string>();
  for (const word of text.split(/[^\p{L}\p{N}]+/u)) {
    if (word !== '') unique.add(word.toLowerCase());
  }
  return unique;
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.name.endsWith('.html')) out.push(full);
  }
  return out;
}

const forbidden = new Set<string>([...FORBIDDEN_TOKEN_SHA256, ...extraForbiddenDigests()]);

/** Replace a token whose digest is forbidden. The marker is the digest prefix, not the token. */
function redact(text: string): string {
  return text.replace(/[\p{L}\p{N}]+/gu, (token) => {
    const digest = sha256Hex(token.normalize('NFKC').toLowerCase());
    if (!forbidden.has(digest)) return token;
    return `[redacted:${digest.slice(0, 12)}]`;
  });
}

function emit(level: 'log' | 'warn' | 'error', line: string): void {
  const safe = redact(line);
  if (level === 'error') console.error(safe);
  else if (level === 'warn') console.warn(safe);
  else console.log(safe);
}

const files = walk(dist);
let failed = false;
const warnings: string[] = [];
const seen = new Set<string>();

for (const file of files) {
  const html = fs.readFileSync(file, 'utf8');
  const rel = path.relative(dist, file);
  for (const token of tokensOf(html)) {
    const digest = sha256Hex(token);
    if (forbidden.has(digest)) {
      emit('error', `FAIL ${rel}: forbidden token ${digest.slice(0, 12)}`);
      failed = true;
    }
  }
  if (html.includes('MIT OR Apache')) {
    emit('error', `FAIL ${rel}: contains MIT OR Apache`);
    failed = true;
  }
  if (html.includes('Claude·ChatGPT') || html.includes('ChatGPTGrok') || /[A-Za-z]·[A-Za-z]/.test(html)) {
    const sample = html.match(/[A-Za-z]·[A-Za-z]|Claude·ChatGPT|ChatGPTGrok/)?.[0];
    emit('error', `FAIL ${rel}: glued separator ${sample ?? ''}`);
    failed = true;
  }

  for (const match of html.matchAll(/\shref="([^"]*)"/g)) {
    const href = match[1] ?? '';
    if (!href || href.startsWith('#') || /^(https?:|mailto:)/.test(href)) continue;
    if (href.startsWith(base + '/') || href === base) {
      const rest = href.slice(base.length).split('#')[0] ?? '/';
      const local = rest.endsWith('/') ? path.join(dist, rest, 'index.html') : path.join(dist, rest);
      if (!fs.existsSync(local)) warnings.push(`${rel}: missing ${href}`);
      continue;
    }
    if (href.startsWith('/')) warnings.push(`${rel}: absolute href outside base ${href}`);
    else warnings.push(`${rel}: relative href ${href}`);
  }
}

for (const warning of warnings) {
  if (seen.has(warning)) continue;
  seen.add(warning);
  emit('warn', `WARN ${warning}`);
}

if (failed) process.exit(1);
emit('log', `check-content: ok (${seen.size} warning${seen.size === 1 ? '' : 's'})`);
