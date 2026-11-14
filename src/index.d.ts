// SPDX-License-Identifier: MIT
// Types for the library entry, 'vexproof'. The CLI is the supported interface (docs/CONTRACT.md); these
// functions are what it is built from.

/** A CycloneDX document, as parsed JSON. */
export type Bom = Record<string, any>;

export interface ParsedPurl { type: string; name: string; version: string | undefined }

/** One advisory on one package. */
export interface Finding { purl: string; id: string; aliases: string[] }

/** What `normalizeFindings` reads: `[{ purl, ids }]`, `[{ purl, id, aliases }]`, or osv-scanner JSON. */
export type FindingsInput =
  | Array<{ purl: string; ids?: string[]; id?: string; aliases?: string[] }>
  | { results?: unknown[] };

export type VexState = 'not_affected' | 'in_triage' | 'exploitable' | 'false_positive' | 'resolved' | 'resolved_with_pedigree';

export interface TriageResult extends Finding {
  /** `npm/<name>`, or null when the purl could not be parsed. */
  key: string | null;
  state: VexState;
  justification?: string;
  detail?: string;
  /** Whether the package is absent (`package`) or only its vulnerable files are (`module`). */
  level: 'package' | 'module' | null;
  evidence: unknown;
  proWouldSettle: boolean;
  moduleReason: string | null;
  origin: 'auto' | 'reviewed';
  [extra: string]: unknown;
}

export interface TriageOptions {
  lockfileSbom: Bom;
  bundleSbom: Bom;
  findings: FindingsInput;
  moduleMap?: unknown;
  rules?: unknown;
  moduleCheck?: ((input: Record<string, unknown>) => { ok: boolean; reason?: string | null; detail?: string; evidence?: unknown; derived?: boolean }) | null;
  pro?: boolean;
  acceptDerived?: boolean;
}

export interface VexOptions {
  results: TriageResult[];
  bundleSbom: Bom;
  lockfileSbom: Bom;
  productPurl: string;
  inputs?: Array<{ role: string; path: string; sha256: string }>;
  licensee?: string | null;
  scope?: string | null;
  aliasEntries?: boolean;
  specVersion?: '1.6' | '1.7';
  now?: Date;
}

export interface Summary { not_affected: number; in_triage: number; module: number; package: number; reviewed: number; proWouldSettle: number; [state: string]: number }

/** The package version. */
export const VERSION: string;
export const CYCLONEDX_VERSIONS: string[];

/** Decides each finding from the lockfile SBOM and what shipped. */
export function triage(options: TriageOptions): TriageResult[];
/** The CycloneDX VEX document for a set of results. Throws on an unsupported `specVersion`. */
export function toCycloneDxVex(options: VexOptions): Bom;
export function summarize(results: TriageResult[]): Summary;

export function normalizeFindings(input: FindingsInput): Finding[];
export function mergeFindings(list: Array<{ purl: string; id: string; aliases?: string[] }>): Finding[];
export function applyRuleAliases(findings: Finding[], rules: unknown): Finding[];

export function parsePurl(purl: string): ParsedPurl | null;
export function packageKey(purl: string): string | null;
export function npmPurl(name: string, version?: string): string;
export function sbomPurls(sbom: Bom): string[];
/** `npm/<name>` → the versions of it in the SBOM. */
export function indexSbom(sbom: Bom): Map<string, Set<string>>;
export function bomLinks(lockfileSbom: Bom, purl: string): string[];
export function vulnerabilitySource(id: string): { name: string; url: string } | null;
export function goQueryEscape(s: string): string;
export function contentUuid(doc: unknown): string;
/** `SOURCE_DATE_EPOCH` when set, otherwise now. Throws on a value that is not whole seconds. */
export function outputTime(env?: Record<string, string | undefined>): Date;
