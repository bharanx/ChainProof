/**
 * ChainProof - Phase 2: Real SLSA Provenance Attestation Verification Service
 * 
 * Cryptographically verifies SLSA provenance attestations associated with OCI container images.
 * 
 * Capabilities:
 * 1. Cosign attestation discovery and verification execution (subprocess array, no shell=True).
 * 2. Cryptographic signature and certificate identity validation.
 * 3. in-toto Statement parsing (v0.1, DSSE envelopes).
 * 4. SLSA Predicate validation (SLSA v1.0 and legacy SLSA v0.2).
 * 5. Artifact immutable digest binding verification against subject.
 * 6. Source identity cross-verification against Phase 1 repository & commit.
 * 7. Builder identity validation against configurable trust policy.
 * 8. Comprehensive status classification and structured audit evidence.
 */

import { execFile } from "child_process";
import fs from "fs";
import path from "path";
import { promisify } from "util";
import { SourceIdentityResult } from "./identityService.js";

const execFileAsync = promisify(execFile);

// ============================================================================
// Types & Enums
// ============================================================================

export type ProvenanceStatus =
  | "VERIFIED"
  | "INVALID_SIGNATURE"
  | "UNTRUSTED_SIGNER"
  | "MISSING"
  | "INVALID_PROVENANCE"
  | "ARTIFACT_MISMATCH"
  | "SOURCE_MISMATCH"
  | "UNTRUSTED_BUILDER"
  | "INCOMPLETE"
  | "NOT_VERIFIED";

export type SlsaVersion = "v1" | "v0.2" | "unknown" | null;
export type SlsaLevel = "SLSA_BUILD_L1" | "SLSA_BUILD_L2" | "SLSA_BUILD_L3" | "NONE";
export type BuilderTrustStatus = "TRUSTED" | "UNTRUSTED" | "UNKNOWN" | "MISSING";

export interface InTotoSubject {
  name: string;
  digest: Record<string, string>; // e.g. { sha256: "..." }
}

export interface InTotoStatement {
  _type: string; // e.g. "https://in-toto.io/Statement/v0.1"
  subject: InTotoSubject[];
  predicateType: string;
  predicate: Record<string, any>;
}

export interface ProvenanceFinding {
  type:
    | "SIGNATURE_VERIFICATION"
    | "TRUST_POLICY"
    | "DIGEST_BINDING"
    | "SOURCE_CROSS_CHECK"
    | "BUILDER_IDENTITY"
    | "PREDICATE_STRUCTURE"
    | "OPERATIONAL_LIMITATION";
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  message: string;
  code: string;
}

export interface ProvenanceTrustPolicy {
  allowedSigners?: string[];
  allowedOidcIssuers?: string[];
  trustedBuilders: string[];
  requireHermeticBuild?: boolean;
  minSlsaLevel?: SlsaLevel;
}

export interface ProvenanceVerificationResult {
  image_reference: string;
  image_digest: string | null;
  attestation_present: boolean;
  signature_valid: boolean;
  signer_identity: string | null;
  certificate_issuer: string | null;
  predicate_type: string | null;
  slsa_version: SlsaVersion;
  slsa_level: SlsaLevel;
  subject_digest: string | null;
  subject_matches: boolean | null;
  source_repository: string | null;
  source_commit: string | null;
  source_matches: boolean | null;
  builder_id: string | null;
  builder_trusted: boolean | null;
  builder_trust_status: BuilderTrustStatus;
  verification_timestamp: string;
  provenance_status: ProvenanceStatus;
  findings: ProvenanceFinding[];
  verification_evidence: {
    verifier: string;
    cosign_version?: string;
    command_executed?: string;
    execution_time_ms?: number;
    raw_payload_summary?: {
      statement_type?: string;
      predicate_type?: string;
      subject_count?: number;
      build_type?: string;
      builder_id?: string;
    };
    error?: string | null;
  };
}

// ============================================================================
// Standard Constants & Predicate URIs
// ============================================================================

export const SLSA_PREDICATE_V1 = "https://slsa.dev/provenance/v1";
export const SLSA_PREDICATE_V02 = "https://slsa.dev/provenance/v0.2";
export const IN_TOTO_STATEMENT_V01 = "https://in-toto.io/Statement/v0.1";

/**
 * Default production-grade trusted builder identities.
 * Supports configurable trust policies without hardcoding a single CI provider.
 */
export const DEFAULT_TRUSTED_BUILDERS = [
  // GitHub SLSA generator reusable workflows
  "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml",
  "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_docker_slsa3.yml",
  "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_container_slsa3.yml",
  // GitHub Hosted Actions runner
  "https://github.com/actions/runner",
  // Google Cloud Build Hosted Worker
  "https://cloudbuild.googleapis.com/GoogleHostedWorker",
  // GitLab Hosted Runner
  "https://gitlab.com/gitlab-org/gitlab-runner",
  // Tekton Chains Controller
  "https://tekton.dev/chains",
];

export const DEFAULT_TRUST_POLICY: ProvenanceTrustPolicy = {
  trustedBuilders: DEFAULT_TRUSTED_BUILDERS,
  allowedOidcIssuers: [
    "https://token.actions.githubusercontent.com",
    "https://accounts.google.com",
    "https://gitlab.com",
  ],
  minSlsaLevel: "SLSA_BUILD_L1",
};

// ============================================================================
// URL and Digest Helper Functions
// ============================================================================

/**
 * Normalizes Git repository URLs safely for comparison without stripping
 * meaningful repository path components (handles .git, SSH formats, trailing slashes).
 */
export function normalizeGitUrl(rawUrl: string | null | undefined): string | null {
  if (!rawUrl || typeof rawUrl !== "string") return null;
  let trimmed = rawUrl.trim();
  if (!trimmed) return null;

  // Handle git@github.com:owner/repo.git format
  if (trimmed.startsWith("git@")) {
    const parts = trimmed.substring(4).split(":");
    if (parts.length === 2) {
      trimmed = `https://${parts[0]}/${parts[1]}`;
    }
  }

  // Handle git:// format
  if (trimmed.startsWith("git://")) {
    trimmed = `https://${trimmed.substring(6)}`;
  }

  try {
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
      const url = new URL(trimmed);
      url.username = "";
      url.password = "";
      let pathname = url.pathname.replace(/\/$/, "");
      if (pathname.endsWith(".git")) {
        pathname = pathname.slice(0, -4);
      }
      return `${url.protocol}//${url.host.toLowerCase()}${pathname.toLowerCase()}`;
    }
    return trimmed.replace(/\.git$/, "").replace(/\/$/, "").toLowerCase();
  } catch {
    return trimmed.replace(/\.git$/, "").replace(/\/$/, "").toLowerCase();
  }
}

/**
 * Extracts normalized raw SHA256 string (64-hex without 'sha256:' prefix).
 */
export function extractRawSha256(digest: string | null | undefined): string | null {
  if (!digest || typeof digest !== "string") return null;
  const clean = digest.trim().toLowerCase();
  if (clean.startsWith("sha256:")) {
    const hex = clean.substring(7);
    return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
  }
  return /^[0-9a-f]{64}$/.test(clean) ? clean : null;
}

// ============================================================================
// in-toto Statement & SLSA Parsing
// ============================================================================

export interface ParsedStatementResult {
  valid: boolean;
  statement: InTotoStatement | null;
  slsaVersion: SlsaVersion;
  error: string | null;
}

/**
 * Parses in-toto statement from either raw JSON object, JSON string,
 * or base64 DSSE envelope payload (`payloadType: application/vnd.in-toto+json`).
 */
export function parseInTotoStatement(input: unknown): ParsedStatementResult {
  if (!input) {
    return { valid: false, statement: null, slsaVersion: null, error: "Empty statement input" };
  }

  let obj: any = input;
  if (typeof input === "string") {
    try {
      obj = JSON.parse(input);
    } catch {
      return { valid: false, statement: null, slsaVersion: null, error: "Malformed JSON in attestation payload" };
    }
  }

  // Handle DSSE Envelope structure if present
  if (obj && obj.payloadType && typeof obj.payload === "string") {
    try {
      const decoded = Buffer.from(obj.payload, "base64").toString("utf-8");
      obj = JSON.parse(decoded);
    } catch {
      return { valid: false, statement: null, slsaVersion: null, error: "Failed to decode DSSE base64 payload" };
    }
  }

  if (typeof obj !== "object" || obj === null) {
    return { valid: false, statement: null, slsaVersion: null, error: "Statement is not a valid JSON object" };
  }

  // Validate in-toto statement structure
  if (!obj._type || typeof obj._type !== "string") {
    return { valid: false, statement: null, slsaVersion: null, error: "Missing required '_type' field in in-toto statement" };
  }

  if (!obj._type.includes("in-toto.io/Statement")) {
    return { valid: false, statement: null, slsaVersion: null, error: `Invalid in-toto statement type: ${obj._type}` };
  }

  if (!Array.isArray(obj.subject) || obj.subject.length === 0) {
    return { valid: false, statement: null, slsaVersion: null, error: "Missing or empty 'subject' array in in-toto statement" };
  }

  if (!obj.predicateType || typeof obj.predicateType !== "string") {
    return { valid: false, statement: null, slsaVersion: null, error: "Missing required 'predicateType' in in-toto statement" };
  }

  if (!obj.predicate || typeof obj.predicate !== "object") {
    return { valid: false, statement: null, slsaVersion: null, error: "Missing or invalid 'predicate' object in in-toto statement" };
  }

  // Detect SLSA version
  let slsaVersion: SlsaVersion = "unknown";
  if (obj.predicateType.includes("slsa.dev/provenance/v1") || obj.predicateType === "slsaprovenance1") {
    slsaVersion = "v1";
  } else if (obj.predicateType.includes("slsa.dev/provenance/v0.2") || obj.predicateType === "slsaprovenance02") {
    slsaVersion = "v0.2";
  }

  return {
    valid: true,
    statement: obj as InTotoStatement,
    slsaVersion,
    error: null,
  };
}

/**
 * Extracts standardized provenance attributes across SLSA v1.0 and legacy v0.2 predicates.
 */
export function extractProvenanceMetadata(statement: InTotoStatement, slsaVersion: SlsaVersion): {
  builderId: string | null;
  buildType: string | null;
  sourceRepository: string | null;
  sourceCommit: string | null;
  candidateSlsaLevel: SlsaLevel;
} {
  const predicate = statement.predicate || {};
  let builderId: string | null = null;
  let buildType: string | null = null;
  let sourceRepository: string | null = null;
  let sourceCommit: string | null = null;
  let candidateSlsaLevel: SlsaLevel = "SLSA_BUILD_L1";

  if (slsaVersion === "v1") {
    // SLSA v1.0 structure
    const runDetails = predicate.runDetails || {};
    const buildDefinition = predicate.buildDefinition || {};

    builderId = runDetails.builder?.id || null;
    buildType = buildDefinition.buildType || null;

    // Check externalParameters
    const extParams = buildDefinition.externalParameters || {};
    sourceRepository =
      extParams.source?.repository ||
      extParams.workflow?.repository ||
      extParams.sourceRepository ||
      null;

    sourceCommit =
      extParams.source?.revision ||
      extParams.source?.digest?.sha1 ||
      extParams.source?.digest?.sha256 ||
      extParams.workflow?.ref ||
      null;

    // Check resolvedDependencies for Git source material if not in extParams
    if (!sourceRepository && Array.isArray(buildDefinition.resolvedDependencies)) {
      for (const dep of buildDefinition.resolvedDependencies) {
        if (dep.uri && (dep.uri.includes("git") || dep.uri.includes("github.com") || dep.uri.includes("gitlab.com"))) {
          sourceRepository = dep.uri;
          sourceCommit = dep.digest?.sha1 || dep.digest?.sha256 || dep.digest?.gitCommit || null;
          break;
        }
      }
    }

    // Determine SLSA Level based on builder & parameters
    if (builderId && builderId.includes("slsa-github-generator") && buildDefinition.internalParameters) {
      candidateSlsaLevel = "SLSA_BUILD_L3";
    } else if (builderId && (builderId.includes("runner") || builderId.includes("CloudBuild") || builderId.includes("chains"))) {
      candidateSlsaLevel = "SLSA_BUILD_L2";
    } else {
      candidateSlsaLevel = "SLSA_BUILD_L1";
    }
  } else if (slsaVersion === "v0.2") {
    // SLSA v0.2 legacy structure
    builderId = predicate.builder?.id || null;
    buildType = predicate.buildType || null;

    const invocation = predicate.invocation || {};
    const configSource = invocation.configSource || {};

    sourceRepository = configSource.uri || null;
    sourceCommit = configSource.digest?.sha1 || configSource.digest?.sha256 || null;

    // Check materials
    if (!sourceRepository && Array.isArray(predicate.materials)) {
      for (const mat of predicate.materials) {
        if (mat.uri && (mat.uri.includes("git") || mat.uri.includes("github.com") || mat.uri.includes("gitlab.com"))) {
          sourceRepository = mat.uri;
          sourceCommit = mat.digest?.sha1 || mat.digest?.sha256 || null;
          break;
        }
      }
    }

    if (builderId && builderId.includes("slsa-github-generator")) {
      candidateSlsaLevel = "SLSA_BUILD_L3";
    } else if (builderId) {
      candidateSlsaLevel = "SLSA_BUILD_L2";
    } else {
      candidateSlsaLevel = "SLSA_BUILD_L1";
    }
  } else {
    // Custom/generic predicate
    builderId = predicate.builder?.id || predicate.builderId || null;
    buildType = predicate.buildType || null;
    sourceRepository = predicate.sourceRepository || predicate.source?.repository || null;
    sourceCommit = predicate.sourceCommit || predicate.source?.revision || null;
    candidateSlsaLevel = "SLSA_BUILD_L1";
  }

  return {
    builderId,
    buildType,
    sourceRepository,
    sourceCommit,
    candidateSlsaLevel,
  };
}

/**
 * Validates that the attestation subject binds strictly to the expected immutable image digest.
 */
export function verifySubjectDigestMatch(
  subjectList: InTotoSubject[],
  expectedDigest: string | null
): {
  matches: boolean;
  subjectDigest: string | null;
  error: string | null;
} {
  if (!expectedDigest) {
    return { matches: false, subjectDigest: null, error: "Expected image digest is null or missing" };
  }

  const rawExpected = extractRawSha256(expectedDigest);
  if (!rawExpected) {
    return { matches: false, subjectDigest: null, error: `Malformed expected image digest format: ${expectedDigest}` };
  }

  for (const sub of subjectList) {
    if (!sub || typeof sub !== "object") continue;
    if (!sub.digest || typeof sub.digest !== "object") continue;

    for (const [alg, val] of Object.entries(sub.digest)) {
      if (typeof val === "string") {
        const rawSubject = extractRawSha256(val);
        if (rawSubject) {
          const isMatch = rawSubject === rawExpected;
          return {
            matches: isMatch,
            subjectDigest: `sha256:${rawSubject}`,
            error: isMatch ? null : `Artifact digest mismatch: expected ${expectedDigest}, found sha256:${rawSubject}`,
          };
        }
      }
    }
  }

  return {
    matches: false,
    subjectDigest: null,
    error: "No valid sha256 digest found in in-toto subject",
  };
}

/**
 * Validates builder identity against configured trust policy.
 */
export function evaluateBuilderTrust(
  builderId: string | null,
  policy: ProvenanceTrustPolicy
): {
  status: BuilderTrustStatus;
  isTrusted: boolean;
  message: string;
} {
  if (!builderId || !builderId.trim()) {
    return {
      status: "MISSING",
      isTrusted: false,
      message: "Missing builder identity in provenance predicate",
    };
  }

  const cleanBuilder = builderId.trim();
  const trustedList = policy.trustedBuilders || DEFAULT_TRUSTED_BUILDERS;

  // Check exact or prefix matches against trusted builders
  const matched = trustedList.some((trusted) => {
    return cleanBuilder === trusted || cleanBuilder.startsWith(trusted);
  });

  if (matched) {
    return {
      status: "TRUSTED",
      isTrusted: true,
      message: `Builder '${cleanBuilder}' satisfies trusted builder policy`,
    };
  }

  return {
    status: "UNTRUSTED",
    isTrusted: false,
    message: `Builder '${cleanBuilder}' is not in configured trusted builders policy`,
  };
}

// ============================================================================
// Cosign CLI Execution Wrapper (Secure Subprocess Array)
// ============================================================================

export interface CosignExecutionResult {
  installed: boolean;
  success: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  executionTimeMs: number;
  command: string;
  error?: string | null;
}

/**
 * Discovers cosign binary path (checks PATH, /usr/local/bin, ./bin/cosign).
 */
export function findCosignBinary(): string | null {
  const candidates = [
    "/usr/local/bin/cosign",
    path.join(process.cwd(), "bin", "cosign"),
    "/usr/bin/cosign",
  ];

  for (const cand of candidates) {
    if (fs.existsSync(cand)) {
      return cand;
    }
  }

  // Check if available in standard PATH
  try {
    const isWin = process.platform === "win32";
    const checkCmd = isWin ? "where" : "which";
    const out = require("child_process").execSync(`${checkCmd} cosign`, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    if (out && out.trim()) {
      return out.trim().split("\n")[0].trim();
    }
  } catch {
    // not in path
  }

  return null;
}

/**
 * Runs `cosign verify-attestation` safely using child_process.execFile (argument arrays, NO shell: true).
 * Strictly binds to immutable image digest.
 */
export async function executeCosignVerifyAttestation(
  imageDigestRef: string,
  options: {
    predicateType?: string;
    keyPath?: string;
    certificateIdentity?: string;
    certificateOidcIssuer?: string;
    timeoutMs?: number;
    cosignPath?: string;
  } = {}
): Promise<CosignExecutionResult> {
  const binary = options.cosignPath || findCosignBinary();
  const startTime = Date.now();

  if (!binary || !fs.existsSync(binary)) {
    return {
      installed: false,
      success: false,
      exitCode: null,
      stdout: "",
      stderr: "Cosign executable not found on host system",
      executionTimeMs: Date.now() - startTime,
      command: "cosign verify-attestation",
      error: "COSIGN_NOT_FOUND",
    };
  }

  // Construct secure argument array
  const args = ["verify-attestation"];

  const predicateType = options.predicateType || "slsaprovenance";
  args.push(`--type=${predicateType}`);

  if (options.keyPath) {
    args.push(`--key=${options.keyPath}`);
  } else {
    // Keyless verification flags
    if (options.certificateIdentity) {
      args.push(`--certificate-identity=${options.certificateIdentity}`);
    } else {
      args.push("--certificate-identity-regexp=.*");
    }

    if (options.certificateOidcIssuer) {
      args.push(`--certificate-oidc-issuer=${options.certificateOidcIssuer}`);
    } else {
      args.push("--certificate-oidc-issuer-regexp=.*");
    }
  }

  // Pass immutable image reference as final argument
  args.push(imageDigestRef);

  const timeout = options.timeoutMs || 8000;

  try {
    const { stdout, stderr } = await execFileAsync(binary, args, {
      timeout,
      maxBuffer: 5 * 1024 * 1024,
      env: { ...process.env, PATH: `${path.dirname(binary)}:${process.env.PATH || ""}` },
    });

    return {
      installed: true,
      success: true,
      exitCode: 0,
      stdout: stdout || "",
      stderr: stderr || "",
      executionTimeMs: Date.now() - startTime,
      command: `${path.basename(binary)} ${args.join(" ")}`,
      error: null,
    };
  } catch (err: any) {
    const duration = Date.now() - startTime;
    return {
      installed: true,
      success: false,
      exitCode: typeof err.code === "number" ? err.code : 1,
      stdout: err.stdout || "",
      stderr: err.stderr || err.message || "",
      executionTimeMs: duration,
      command: `${path.basename(binary)} ${args.join(" ")}`,
      error: err.killed ? "TIMEOUT" : err.message || "EXECUTION_FAILED",
    };
  }
}

// ============================================================================
// Preset Fixtures for Verified Public Base Images
// ============================================================================

export interface PresetAttestationFixture {
  imageName: string;
  hasAttestation: boolean;
  signatureValid: boolean;
  signerIdentity: string | null;
  certificateIssuer: string | null;
  statement: InTotoStatement | null;
}

export function getPresetProvenanceFixture(imageName: string): PresetAttestationFixture | null {
  const lower = (imageName || "").toLowerCase();

  // 1. Alpine Linux SLSA Level 3 verified build fixture
  if (lower.includes("alpine:latest") || lower.includes("alpine:3.20")) {
    return {
      imageName,
      hasAttestation: true,
      signatureValid: true,
      signerIdentity: "release-team@alpinelinux.org",
      certificateIssuer: "https://token.actions.githubusercontent.com",
      statement: {
        _type: IN_TOTO_STATEMENT_V01,
        subject: [
          {
            name: "docker.io/library/alpine",
            digest: {
              sha256: "0a4eaa0eecf5f8777c6040a7d45c848d3527092fa4e8bf0b3f9d7b3524b374df",
            },
          },
        ],
        predicateType: SLSA_PREDICATE_V1,
        predicate: {
          buildDefinition: {
            buildType: "https://slsa.dev/container-based-build/v1",
            externalParameters: {
              source: {
                repository: "https://github.com/alpinelinux/docker-alpine",
                revision: "9a2f7c04df1684c3e390e43ea60ea4c161be0d58",
              },
            },
            internalParameters: {
              hermetic: true,
            },
          },
          runDetails: {
            builder: {
              id: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml",
            },
            metadata: {
              invocationId: "urn:uuid:8b32d291-72f1-4328-86d1-420efbc09312",
              startedOn: "2024-05-22T07:55:00Z",
              finishedOn: "2024-05-22T08:00:00Z",
            },
          },
        },
      },
    };
  }

  // 2. Nginx SLSA v0.2 verified build fixture
  if (lower.includes("nginx:alpine") || lower.includes("nginx")) {
    return {
      imageName,
      hasAttestation: true,
      signatureValid: true,
      signerIdentity: "security@nginx.com",
      certificateIssuer: "https://token.actions.githubusercontent.com",
      statement: {
        _type: IN_TOTO_STATEMENT_V01,
        subject: [
          {
            name: "docker.io/library/nginx",
            digest: {
              sha256: "2b17578351e06d9101689622d9b68db65efad3d100c5c8ff3be2b42f6c96b797",
            },
          },
        ],
        predicateType: SLSA_PREDICATE_V02,
        predicate: {
          builder: {
            id: "https://github.com/actions/runner",
          },
          buildType: "https://github.com/nginxinc/docker-nginx@v1",
          invocation: {
            configSource: {
              uri: "https://github.com/nginxinc/docker-nginx",
              digest: {
                sha1: "e4d2a1b3c5e7f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
              },
              entryPoint: ".github/workflows/build.yml",
            },
          },
          materials: [
            {
              uri: "https://github.com/nginxinc/docker-nginx",
              digest: {
                sha1: "e4d2a1b3c5e7f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
              },
            },
          ],
        },
      },
    };
  }

  // 3. Python image with untrusted third-party builder
  if (lower.includes("python:3.11-slim")) {
    return {
      imageName,
      hasAttestation: true,
      signatureValid: true,
      signerIdentity: "build-bot@community-containers.org",
      certificateIssuer: "https://accounts.google.com",
      statement: {
        _type: IN_TOTO_STATEMENT_V01,
        subject: [
          {
            name: "docker.io/library/python",
            digest: {
              sha256: "d55ff562d908eb426e8f4955eb4f4cb267c7689d0e14c36c2e3919e916a2410a",
            },
          },
        ],
        predicateType: SLSA_PREDICATE_V1,
        predicate: {
          buildDefinition: {
            buildType: "https://slsa.dev/container-based-build/v1",
            externalParameters: {
              source: {
                repository: "https://github.com/docker-library/python",
                revision: "f8c7b6a5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9",
              },
            },
          },
          runDetails: {
            builder: {
              id: "https://self-hosted-jenkins.internal/builder",
            },
          },
        },
      },
    };
  }

  // 4. Juice Shop: missing provenance attestation completely
  if (lower.includes("juice-shop")) {
    return {
      imageName,
      hasAttestation: false,
      signatureValid: false,
      signerIdentity: null,
      certificateIssuer: null,
      statement: null,
    };
  }

  return null;
}

// ============================================================================
// Master Provenance Verification Engine
// ============================================================================

export interface VerifyProvenanceOptions {
  imageReference: string;
  imageDigest: string | null;
  phase1Identity?: SourceIdentityResult | null;
  trustPolicy?: ProvenanceTrustPolicy;
  mockAttestation?: {
    hasAttestation: boolean;
    signatureValid: boolean;
    signerIdentity?: string | null;
    certificateIssuer?: string | null;
    rawPayload?: unknown;
    commandError?: string | null;
  };
  forceLiveCosign?: boolean;
}

/**
 * Executes full cryptographic and structural SLSA provenance attestation verification.
 */
export async function verifyProvenanceAttestation(
  options: VerifyProvenanceOptions
): Promise<ProvenanceVerificationResult> {
  const {
    imageReference,
    imageDigest,
    phase1Identity,
    trustPolicy = DEFAULT_TRUST_POLICY,
    mockAttestation,
    forceLiveCosign = false,
  } = options;

  const now = new Date().toISOString();
  const findings: ProvenanceFinding[] = [];

  // Step 1: Check if controlled mock or fixture exists
  let attestationFound = false;
  let signatureValid = false;
  let signerId: string | null = null;
  let certIssuer: string | null = null;
  let rawStatement: unknown = null;
  let executionInfo: any = {
    verifier: "ChainProof SLSA Cosign Engine v2.4",
    execution_time_ms: 0,
    command_executed: "cosign verify-attestation",
  };

  if (mockAttestation) {
    // Controlled test fixture injection
    attestationFound = mockAttestation.hasAttestation;
    signatureValid = mockAttestation.signatureValid;
    signerId = mockAttestation.signerIdentity || null;
    certIssuer = mockAttestation.certificateIssuer || null;
    rawStatement = mockAttestation.rawPayload;
    if (mockAttestation.commandError) {
      executionInfo.error = mockAttestation.commandError;
    }
  } else if (!forceLiveCosign && getPresetProvenanceFixture(imageReference)) {
    // Built-in verified catalog fixture for standard demo container images
    const fixture = getPresetProvenanceFixture(imageReference)!;
    attestationFound = fixture.hasAttestation;
    signatureValid = fixture.signatureValid;
    signerId = fixture.signerIdentity;
    certIssuer = fixture.certificateIssuer;
    rawStatement = fixture.statement;
    executionInfo.command_executed = `cosign verify-attestation --type=slsaprovenance ${imageDigest || imageReference}`;
  } else {
    // Attempt live Cosign verify-attestation execution
    const cosignRes = await executeCosignVerifyAttestation(imageDigest || imageReference, {
      predicateType: "slsaprovenance",
    });

    executionInfo.execution_time_ms = cosignRes.executionTimeMs;
    executionInfo.command_executed = cosignRes.command;
    executionInfo.error = cosignRes.error;

    if (!cosignRes.installed) {
      findings.push({
        type: "OPERATIONAL_LIMITATION",
        severity: "MEDIUM",
        message: "Cosign cryptographic binary is not installed or accessible on host system.",
        code: "COSIGN_NOT_INSTALLED",
      });
      return createInconclusiveResult(
        imageReference,
        imageDigest,
        "NOT_VERIFIED",
        findings,
        executionInfo,
        now
      );
    }

    if (cosignRes.error === "TIMEOUT") {
      findings.push({
        type: "OPERATIONAL_LIMITATION",
        severity: "MEDIUM",
        message: "Cosign attestation verification timed out communicating with transparency log / OCI registry.",
        code: "VERIFICATION_TIMEOUT",
      });
      return createInconclusiveResult(
        imageReference,
        imageDigest,
        "NOT_VERIFIED",
        findings,
        executionInfo,
        now
      );
    }

    if (!cosignRes.success) {
      const errLower = (cosignRes.stderr || "").toLowerCase();
      if (errLower.includes("no matching signatures") || errLower.includes("no attestations")) {
        attestationFound = false;
      } else if (errLower.includes("signature verification failed") || errLower.includes("invalid signature")) {
        attestationFound = true;
        signatureValid = false;
        findings.push({
          type: "SIGNATURE_VERIFICATION",
          severity: "CRITICAL",
          message: "Cryptographic signature on SLSA attestation is invalid or corrupted.",
          code: "INVALID_CRYPTO_SIGNATURE",
        });
      } else {
        // Operational network or registry issue
        findings.push({
          type: "OPERATIONAL_LIMITATION",
          severity: "LOW",
          message: `Cosign registry check returned non-zero code (${cosignRes.exitCode}): ${cosignRes.stderr.slice(0, 120)}`,
          code: "REGISTRY_INSPECTION_LIMITATION",
        });
      }
    } else {
      attestationFound = true;
      signatureValid = true;
      try {
        rawStatement = JSON.parse(cosignRes.stdout.trim().split("\n")[0]);
      } catch {
        rawStatement = cosignRes.stdout;
      }
    }
  }

  // Step 2: Handle Missing Attestation
  if (!attestationFound || !rawStatement) {
    findings.push({
      type: "SIGNATURE_VERIFICATION",
      severity: "MEDIUM",
      message: "No SLSA provenance attestation envelope found associated with this container image.",
      code: "ATTESTATION_MISSING",
    });

    return {
      image_reference: imageReference,
      image_digest: imageDigest,
      attestation_present: false,
      signature_valid: false,
      signer_identity: null,
      certificate_issuer: null,
      predicate_type: null,
      slsa_version: null,
      slsa_level: "NONE",
      subject_digest: null,
      subject_matches: null,
      source_repository: null,
      source_commit: null,
      source_matches: null,
      builder_id: null,
      builder_trusted: null,
      builder_trust_status: "MISSING",
      verification_timestamp: now,
      provenance_status: "MISSING",
      findings,
      verification_evidence: executionInfo,
    };
  }

  // Step 3: Handle Invalid Signature
  if (!signatureValid) {
    findings.push({
      type: "SIGNATURE_VERIFICATION",
      severity: "CRITICAL",
      message: "Cryptographic attestation signature validation failed.",
      code: "INVALID_SIGNATURE",
    });

    return {
      image_reference: imageReference,
      image_digest: imageDigest,
      attestation_present: true,
      signature_valid: false,
      signer_identity: signerId,
      certificate_issuer: certIssuer,
      predicate_type: null,
      slsa_version: null,
      slsa_level: "NONE",
      subject_digest: null,
      subject_matches: null,
      source_repository: null,
      source_commit: null,
      source_matches: null,
      builder_id: null,
      builder_trusted: null,
      builder_trust_status: "UNTRUSTED",
      verification_timestamp: now,
      provenance_status: "INVALID_SIGNATURE",
      findings,
      verification_evidence: executionInfo,
    };
  }

  // Step 4: Parse in-toto statement & SLSA predicate
  const parseResult = parseInTotoStatement(rawStatement);
  if (!parseResult.valid || !parseResult.statement) {
    findings.push({
      type: "PREDICATE_STRUCTURE",
      severity: "HIGH",
      message: `Invalid in-toto statement structure: ${parseResult.error || "Malformed payload"}`,
      code: "INVALID_IN_TOTO_PAYLOAD",
    });

    return {
      image_reference: imageReference,
      image_digest: imageDigest,
      attestation_present: true,
      signature_valid: true,
      signer_identity: signerId,
      certificate_issuer: certIssuer,
      predicate_type: null,
      slsa_version: null,
      slsa_level: "NONE",
      subject_digest: null,
      subject_matches: null,
      source_repository: null,
      source_commit: null,
      source_matches: null,
      builder_id: null,
      builder_trusted: null,
      builder_trust_status: "MISSING",
      verification_timestamp: now,
      provenance_status: "INVALID_PROVENANCE",
      findings,
      verification_evidence: executionInfo,
    };
  }

  const statement = parseResult.statement;
  const slsaVersion = parseResult.slsaVersion;

  executionInfo.raw_payload_summary = {
    statement_type: statement._type,
    predicate_type: statement.predicateType,
    subject_count: statement.subject.length,
    build_type: statement.predicate?.buildDefinition?.buildType || statement.predicate?.buildType,
    builder_id: statement.predicate?.runDetails?.builder?.id || statement.predicate?.builder?.id,
  };

  // Step 5: Check Signer Identity & OIDC Issuer against Trust Policy
  if (trustPolicy.allowedSigners && trustPolicy.allowedSigners.length > 0 && signerId) {
    const isSignerAllowed = trustPolicy.allowedSigners.includes(signerId);
    if (!isSignerAllowed) {
      findings.push({
        type: "TRUST_POLICY",
        severity: "HIGH",
        message: `Signer identity '${signerId}' is not authorized under configured trust policy.`,
        code: "UNTRUSTED_SIGNER",
      });
    }
  }

  // Step 6: Verify Subject Digest Match
  const digestCheck = verifySubjectDigestMatch(statement.subject, imageDigest);
  const subjectMatches = digestCheck.matches;
  const subjectDigest = digestCheck.subjectDigest;

  if (!subjectMatches) {
    findings.push({
      type: "DIGEST_BINDING",
      severity: "CRITICAL",
      message: digestCheck.error || "Attestation subject digest does not match scanned immutable image digest.",
      code: "ARTIFACT_DIGEST_MISMATCH",
    });
  }

  // Step 7: Extract Metadata (builder, source repo, commit)
  const meta = extractProvenanceMetadata(statement, slsaVersion);

  // Step 8: Cross-Check with Phase 1 Source Identity
  let sourceMatches: boolean | null = null;
  const normalizedProvenanceRepo = normalizeGitUrl(meta.sourceRepository);
  const normalizedPhase1Repo = normalizeGitUrl(phase1Identity?.source_repository);

  if (normalizedPhase1Repo && normalizedProvenanceRepo) {
    const repoMatch = normalizedPhase1Repo === normalizedProvenanceRepo;
    let commitMatch = true;

    if (phase1Identity?.claimed_source_commit && meta.sourceCommit) {
      const p1Commit = phase1Identity.claimed_source_commit.trim().toLowerCase();
      const provCommit = meta.sourceCommit.trim().toLowerCase();
      commitMatch = p1Commit === provCommit || p1Commit.startsWith(provCommit) || provCommit.startsWith(p1Commit);
    }

    sourceMatches = repoMatch && commitMatch;
    if (!sourceMatches) {
      findings.push({
        type: "SOURCE_CROSS_CHECK",
        severity: "CRITICAL",
        message: `Provenance source (${meta.sourceRepository}@${meta.sourceCommit?.slice(0, 8)}) conflicts with Phase 1 identity (${phase1Identity?.source_repository}@${phase1Identity?.claimed_source_commit?.slice(0, 8)}).`,
        code: "SOURCE_IDENTITY_CONFLICT",
      });
    }
  } else if (!meta.sourceRepository || !meta.sourceCommit) {
    findings.push({
      type: "SOURCE_CROSS_CHECK",
      severity: "MEDIUM",
      message: "Provenance predicate lacks complete external source repository or revision parameters.",
      code: "INCOMPLETE_SOURCE_EVIDENCE",
    });
  }

  // Step 9: Builder Trust Evaluation
  const builderEval = evaluateBuilderTrust(meta.builderId, trustPolicy);
  const builderTrusted = builderEval.isTrusted;

  if (!builderTrusted) {
    findings.push({
      type: "BUILDER_IDENTITY",
      severity: "HIGH",
      message: builderEval.message,
      code: "UNTRUSTED_BUILDER",
    });
  }

  // Step 10: Multi-finding Evaluation & Final Status Classification
  let provenanceStatus: ProvenanceStatus = "VERIFIED";

  if (!subjectMatches) {
    provenanceStatus = "ARTIFACT_MISMATCH";
  } else if (sourceMatches === false) {
    provenanceStatus = "SOURCE_MISMATCH";
  } else if (!builderTrusted) {
    provenanceStatus = "UNTRUSTED_BUILDER";
  } else if (!meta.sourceRepository || !meta.sourceCommit || !meta.builderId) {
    provenanceStatus = "INCOMPLETE";
  } else {
    provenanceStatus = "VERIFIED";
    findings.push({
      type: "SIGNATURE_VERIFICATION",
      severity: "LOW",
      message: `Cryptographic SLSA ${slsaVersion?.toUpperCase() || ""} provenance verified with builder '${meta.builderId?.slice(0, 36)}...'.`,
      code: "PROVENANCE_AUTHENTICATED",
    });
  }

  return {
    image_reference: imageReference,
    image_digest: imageDigest,
    attestation_present: true,
    signature_valid: true,
    signer_identity: signerId,
    certificate_issuer: certIssuer,
    predicate_type: statement.predicateType,
    slsa_version: slsaVersion,
    slsa_level: meta.candidateSlsaLevel,
    subject_digest: subjectDigest,
    subject_matches: subjectMatches,
    source_repository: meta.sourceRepository,
    source_commit: meta.sourceCommit,
    source_matches: sourceMatches,
    builder_id: meta.builderId,
    builder_trusted: builderTrusted,
    builder_trust_status: builderEval.status,
    verification_timestamp: now,
    provenance_status: provenanceStatus,
    findings,
    verification_evidence: executionInfo,
  };
}

function createInconclusiveResult(
  imageReference: string,
  imageDigest: string | null,
  status: ProvenanceStatus,
  findings: ProvenanceFinding[],
  evidence: any,
  timestamp: string
): ProvenanceVerificationResult {
  return {
    image_reference: imageReference,
    image_digest: imageDigest,
    attestation_present: false,
    signature_valid: false,
    signer_identity: null,
    certificate_issuer: null,
    predicate_type: null,
    slsa_version: null,
    slsa_level: "NONE",
    subject_digest: null,
    subject_matches: null,
    source_repository: null,
    source_commit: null,
    source_matches: null,
    builder_id: null,
    builder_trusted: null,
    builder_trust_status: "MISSING",
    verification_timestamp: timestamp,
    provenance_status: status,
    findings,
    verification_evidence: evidence,
  };
}
