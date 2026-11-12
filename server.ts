import express, { Request, Response } from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import { createServer as createViteServer } from "vite";
import crypto from "crypto";
import {
  verifySourceIdentity,
  resolveImageDigest,
  getPresetOciMetadata,
  SourceIdentityResult,
  IdentityStatus,
} from "./src/services/identityService.js";
import {
  verifyProvenanceAttestation,
  ProvenanceVerificationResult,
  ProvenanceStatus,
} from "./src/services/provenanceService.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;

app.use(cors());
app.use(express.json());

// ============================================================================
// In-Memory Database & Seed Data
// ============================================================================

interface ScanReport {
  id: number;
  scan_id: string;
  image: string;
  timestamp: string;
  risk_score: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  verdict: "TRUSTED" | "CAUTION" | "HIGH RISK";
  docker: {
    image: string;
    id: string;
    digest: string | null;
    created: string;
    size_bytes: number;
    size_mb: number;
    layers: number;
    architecture: string;
    os: string;
    config: Record<string, any>;
    oci_annotations?: Record<string, string | null>;
  };
  sbom: {
    status: string;
    package_count: number;
    packages: Array<{ name: string; version: string; type: string; license?: string }>;
  };
  vulnerabilities: {
    status: string;
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    vulnerabilities: Array<{ id: string; severity: string; message: string; package?: string; fixed_version?: string }>;
  };
  signature: {
    signed: boolean;
    verified: boolean;
    issuer?: string;
    subject?: string;
    error?: string | null;
  };
  identity: SourceIdentityResult;
  provenance: ProvenanceVerificationResult;
  ml: {
    features: Record<string, any>;
    random_forest: {
      prediction: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
      confidence: number;
      model_loaded: boolean;
    };
    anomaly_detection: {
      anomaly: boolean;
      anomaly_score: number;
      model_loaded: boolean;
    };
    final_ml_score: number;
    ml_confidence: number;
  };
  risk: {
    risk_score: number;
    severity: string;
    verdict: string;
    score_breakdown: {
      ml_base_score: number;
      critical_cve_penalty: number;
      high_cve_penalty: number;
      medium_cve_penalty: number;
      low_cve_penalty: number;
      signature_penalty: number;
      anomaly_penalty: number;
      identity_penalty: number;
      provenance_penalty: number;
    };
  };
  findings: Array<{ type: string; severity: string; message: string }>;
  ai_analysis: {
    security_decision: "TRUST" | "REVIEW" | "BLOCK";
    confidence: number;
    assessment: string;
    summary: string;
    risk_factors: string[];
    recommended_action: string;
    remediation_steps: string[];
    correlated_risks?: Array<{ title: string; detail: string; severity: string }>;
  };
}

// Risk Engine Logic (mirrors backend/app/risk/risk_engine.py)
function labelToScore(label: string): number {
  switch (label.toUpperCase()) {
    case "LOW":
      return 15;
    case "MEDIUM":
      return 45;
    case "HIGH":
      return 72;
    case "CRITICAL":
      return 92;
    default:
      return 50;
  }
}

function calculateRisk(
  vulnerabilities: { critical: number; high: number; medium: number; low: number },
  signature: { verified: boolean },
  mlResult: { prediction: string; confidence: number },
  anomalyResult: { anomaly: boolean },
  identityStatus: IdentityStatus = "NOT_VERIFIED"
) {
  const prediction = (mlResult.prediction || "UNKNOWN").toUpperCase();
  const mlScore = labelToScore(prediction);
  let score = mlScore;

  const criticalPenalty = Math.min(vulnerabilities.critical * 3, 12);
  const highPenalty = Math.min(vulnerabilities.high * 1.5, 8);
  const mediumPenalty = Math.min(vulnerabilities.medium * 0.5, 4);
  const lowPenalty = Math.min(vulnerabilities.low * 0.1, 2);

  score += criticalPenalty + highPenalty + mediumPenalty + lowPenalty;

  let signaturePenalty = 0;
  if (!signature.verified) {
    signaturePenalty = 8;
    score += signaturePenalty;
  }

  let anomalyPenalty = 0;
  if (anomalyResult.anomaly) {
    anomalyPenalty = 7;
    score += anomalyPenalty;
  }

  // Phase 1 Source-to-Container Identity risk weight
  // VERIFIED: 0 penalty (provenance verified against Git source)
  // CLAIMED: +1 (evidence limitation - declared but unverified)
  // MISMATCH: +8 (high-priority integrity violation - counterfeit/divergent revision)
  // MISSING: +3 (identity metadata absent)
  // NOT_VERIFIED: +2 (inconclusive verification)
  let identityPenalty = 0;
  if (identityStatus === "MISMATCH") {
    identityPenalty = 8;
  } else if (identityStatus === "MISSING") {
    identityPenalty = 3;
  } else if (identityStatus === "NOT_VERIFIED") {
    identityPenalty = 2;
  } else if (identityStatus === "CLAIMED") {
    identityPenalty = 1;
  } else {
    identityPenalty = 0; // VERIFIED
  }
  score += identityPenalty;

  score = Math.round(Math.max(0, Math.min(score, 100)));

  let severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  let verdict: "TRUSTED" | "CAUTION" | "HIGH RISK";

  if (score >= 75) {
    severity = "CRITICAL";
    verdict = "HIGH RISK";
  } else if (score >= 50) {
    severity = "HIGH";
    verdict = "HIGH RISK";
  } else if (score >= 25) {
    severity = "MEDIUM";
    verdict = "CAUTION";
  } else {
    severity = "LOW";
    verdict = "TRUSTED";
  }

  return {
    risk_score: score,
    severity,
    verdict,
    score_breakdown: {
      ml_base_score: mlScore,
      critical_cve_penalty: criticalPenalty,
      high_cve_penalty: highPenalty,
      medium_cve_penalty: mediumPenalty,
      low_cve_penalty: lowPenalty,
      signature_penalty: signaturePenalty,
      anomaly_penalty: anomalyPenalty,
      identity_penalty: identityPenalty,
    },
  };
}

// Preset and Dynamic Scanner Simulator
async function createScanResult(
  imageName: string,
  customOptions?: { sourceRepo?: string; commit?: string; mockCommitLookup?: any }
): Promise<ScanReport> {
  const cleanImage = imageName.trim();
  const lower = cleanImage.toLowerCase();
  const now = new Date();
  const timestamp = now.toISOString().replace("T", " ").substring(0, 19);

  // 1. Immutable Digest Resolution (digest-first identification)
  const digestRes = resolveImageDigest(cleanImage);
  const resolvedDigest = digestRes.image_digest;

  // 2. Extract standard OCI annotations & labels
  const presetLabels = getPresetOciMetadata(cleanImage);

  // 3. Independent Source-to-Container Identity Verification
  const identityResult = await verifySourceIdentity({
    imageReference: cleanImage,
    imageDigest: resolvedDigest,
    imageId: resolvedDigest,
    rawLabels: presetLabels,
    overrideSourceRepo: customOptions?.sourceRepo,
    overrideRevision: customOptions?.commit,
    mockCommitLookup: customOptions?.mockCommitLookup,
  });

  let cveCrit = 0;
  let cveHigh = 0;
  let cveMed = 0;
  let cveLow = 0;
  let pkgCount = 42;
  let sizeMb = 7.4;
  let isSigned = false;
  let isVerified = false;
  let cveList: Array<{ id: string; severity: string; message: string; package?: string; fixed_version?: string }> = [];
  let pkgList: Array<{ name: string; version: string; type: string; license?: string }> = [];

  if (lower.includes("juice-shop")) {
    cveCrit = 4;
    cveHigh = 11;
    cveMed = 18;
    cveLow = 6;
    pkgCount = 384;
    sizeMb = 412.0;
    isSigned = false;
    isVerified = false;
    cveList = [
      { id: "CVE-2026-38410", severity: "CRITICAL", message: "Remote Code Execution in unvalidated YAML parser buffer", package: "js-yaml", fixed_version: "4.1.1" },
      { id: "CVE-2026-29104", severity: "CRITICAL", message: "SQL Injection in legacy authentication routing handler", package: "sqlite3", fixed_version: "5.1.8" },
      { id: "CVE-2026-17482", severity: "CRITICAL", message: "Hardcoded JSON Web Key private signing secret vulnerability", package: "jsonwebtoken", fixed_version: "9.0.3" },
      { id: "CVE-2025-49211", severity: "CRITICAL", message: "Prototype Pollution leading to arbitrary property injection", package: "lodash", fixed_version: "4.17.22" },
      { id: "CVE-2025-33019", severity: "HIGH", message: "Cross-Site Scripting (XSS) in markdown viewer preview pipeline", package: "marked", fixed_version: "12.0.1" },
      { id: "CVE-2025-28109", severity: "HIGH", message: "Denial of Service through unbounded regular expression matching", package: "express", fixed_version: "4.21.2" },
      { id: "CVE-2025-19940", severity: "HIGH", message: "Path Traversal vulnerability allowing unauthorized directory read", package: "serve-static", fixed_version: "1.16.2" },
    ];
    pkgList = [
      { name: "express", version: "4.18.2", type: "npm", license: "MIT" },
      { name: "sqlite3", version: "5.0.8", type: "npm", license: "BSD-3-Clause" },
      { name: "jsonwebtoken", version: "8.5.1", type: "npm", license: "MIT" },
      { name: "lodash", version: "4.17.15", type: "npm", license: "MIT" },
      { name: "js-yaml", version: "3.13.1", type: "npm", license: "MIT" },
      { name: "body-parser", version: "1.19.0", type: "npm", license: "MIT" },
      { name: "cookie-parser", version: "1.4.5", type: "npm", license: "MIT" },
      { name: "multer", version: "1.4.4", type: "npm", license: "MIT" },
    ];
  } else if (lower.includes("nginx")) {
    cveCrit = 0;
    cveHigh = 1;
    cveMed = 2;
    cveLow = 1;
    pkgCount = 68;
    sizeMb = 23.5;
    isSigned = true;
    isVerified = true;
    cveList = [
      { id: "CVE-2026-85091", severity: "HIGH", message: "HTTP/2 Rapid Reset protocol violation resource exhaustion", package: "nginx", fixed_version: "1.25.4-alpine" },
      { id: "CVE-2025-99214", severity: "MEDIUM", message: "OpenSSL memory leak in TLS session renegotiation cipher handshakes", package: "libssl3", fixed_version: "3.1.5-r0" },
      { id: "CVE-2025-11029", severity: "MEDIUM", message: "Zlib boundary integer truncation under malformed chunk streams", package: "zlib", fixed_version: "1.3.1-r1" },
    ];
    pkgList = [
      { name: "nginx", version: "1.25.3", type: "apk", license: "BSD-2-Clause" },
      { name: "libssl3", version: "3.1.4-r0", type: "apk", license: "Apache-2.0" },
      { name: "zlib", version: "1.3.0-r0", type: "apk", license: "Zlib" },
      { name: "pcre2", version: "10.42-r1", type: "apk", license: "BSD-3-Clause" },
      { name: "musl", version: "1.2.4-r2", type: "apk", license: "MIT" },
    ];
  } else if (lower.includes("python")) {
    cveCrit = 0;
    cveHigh = 2;
    cveMed = 4;
    cveLow = 5;
    pkgCount = 114;
    sizeMb = 126.8;
    isSigned = true;
    isVerified = false;
    cveList = [
      { id: "CVE-2026-61022", severity: "HIGH", message: "Tarfile extraction arbitrary file overwrite via symlink dereferencing", package: "python3", fixed_version: "3.11.8" },
      { id: "CVE-2026-55910", severity: "HIGH", message: "Pip package verification hash collision vulnerability", package: "python3-pip", fixed_version: "24.0" },
      { id: "CVE-2025-41982", severity: "MEDIUM", message: "Urllib request header injection with raw carriage returns", package: "python3-urllib", fixed_version: "3.11.7" },
    ];
    pkgList = [
      { name: "python3", version: "3.11.5", type: "deb", license: "PSF-2.0" },
      { name: "pip", version: "23.3.1", type: "pip", license: "MIT" },
      { name: "setuptools", version: "68.2.2", type: "pip", license: "MIT" },
      { name: "wheel", version: "0.41.2", type: "pip", license: "MIT" },
      { name: "libsqlite3-0", version: "3.40.1-2", type: "deb", license: "Public Domain" },
    ];
  } else if (lower.includes("alpine")) {
    cveCrit = 0;
    cveHigh = 0;
    cveMed = 1;
    cveLow = 0;
    pkgCount = 17;
    sizeMb = 7.34;
    isSigned = true;
    isVerified = true;
    cveList = [
      { id: "CVE-2025-49210", severity: "MEDIUM", message: "Busybox wget component hostname verification weakness", package: "busybox", fixed_version: "1.36.1-r3" },
    ];
    pkgList = [
      { name: "alpine-baselayout", version: "3.4.3-r2", type: "apk", license: "GPL-2.0-only" },
      { name: "apk-tools", version: "2.14.0-r2", type: "apk", license: "GPL-2.0-only" },
      { name: "busybox", version: "1.36.1-r2", type: "apk", license: "GPL-2.0-only" },
      { name: "musl", version: "1.2.4-r2", type: "apk", license: "MIT" },
      { name: "ca-certificates-bundle", version: "20240224-r0", type: "apk", license: "MPL-2.0" },
    ];
  } else {
    // Deterministic simulation based on string hash for custom images
    const hash = crypto.createHash("md5").update(cleanImage).digest("hex");
    const num = parseInt(hash.substring(0, 4), 16);
    cveCrit = num % 3 === 0 ? (num % 2) + 1 : 0;
    cveHigh = (num % 4);
    cveMed = (num % 6) + 1;
    cveLow = (num % 5);
    pkgCount = 30 + (num % 180);
    sizeMb = 15 + (num % 250);
    isSigned = num % 2 === 0;
    isVerified = isSigned && num % 4 === 0;
    if (cveCrit > 0) {
      cveList.push({ id: `CVE-2026-${num % 9000 + 1000}`, severity: "CRITICAL", message: "Arbitrary command execution in embedded native library", package: "glibc", fixed_version: "2.38-r1" });
    }
    if (cveHigh > 0) {
      cveList.push({ id: `CVE-2025-${num % 9000 + 1000}`, severity: "HIGH", message: "Unauthenticated denial of service via memory exhaustion", package: "openssl", fixed_version: "3.2.1" });
    }
    if (cveMed > 0) {
      cveList.push({ id: `CVE-2025-${num % 9000 + 2000}`, severity: "MEDIUM", message: "Cryptographic weak nonce generation in key negotiation", package: "curl", fixed_version: "8.6.0" });
    }
    pkgList = [
      { name: "base-files", version: "1.0", type: "sys", license: "GPL-2.0" },
      { name: "musl", version: "1.2.4", type: "sys", license: "MIT" },
      { name: "curl", version: "8.5.0", type: "sys", license: "MIT" },
      { name: "openssl", version: "3.1.2", type: "sys", license: "Apache-2.0" },
    ];
  }

  const totalCve = cveCrit + cveHigh + cveMed + cveLow;

  // ML Random Forest
  let mlPrediction: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  let mlConfidence: number;
  let isAnomaly: boolean;

  if (cveCrit > 0 || (cveHigh >= 4 && !isVerified)) {
    mlPrediction = "CRITICAL";
    mlConfidence = 0.94;
    isAnomaly = pkgCount > 300 || !isSigned;
  } else if (cveHigh > 0 || totalCve > 5 || !isVerified) {
    mlPrediction = "HIGH";
    mlConfidence = 0.88;
    isAnomaly = pkgCount > 200;
  } else if (totalCve > 0) {
    mlPrediction = "MEDIUM";
    mlConfidence = 0.85;
    isAnomaly = false;
  } else {
    mlPrediction = "LOW";
    mlConfidence = 0.96;
    isAnomaly = false;
  }

  const anomalyScore = isAnomaly ? -0.28 : 0.65;

  const riskResult = calculateRisk(
    { critical: cveCrit, high: cveHigh, medium: cveMed, low: cveLow },
    { verified: isVerified },
    { prediction: mlPrediction, confidence: mlConfidence },
    { anomaly: isAnomaly },
    identityResult.identity_status
  );

  const findings: Array<{ type: string; severity: string; message: string }> = [];
  if (cveCrit > 0) {
    findings.push({ type: "VULNERABILITY", severity: "CRITICAL", message: `${cveCrit} critical vulnerabilities detected in base image packages.` });
  }
  if (cveHigh > 0) {
    findings.push({ type: "VULNERABILITY", severity: "HIGH", message: `${cveHigh} high vulnerabilities detected in software packages.` });
  }
  if (cveMed > 0) {
    findings.push({ type: "VULNERABILITY", severity: "MEDIUM", message: `${cveMed} medium vulnerabilities identified.` });
  }
  if (!isVerified) {
    findings.push({ type: "INTEGRITY", severity: "MEDIUM", message: "Container image digital signature could not be cryptographically verified with Cosign." });
  }
  if (isAnomaly) {
    findings.push({ type: "ANOMALY", severity: "MEDIUM", message: "Isolation Forest ML anomaly detector flagged unusual container package composition profile." });
  }

  // Phase 1: Incorporate Identity Findings
  for (const idf of identityResult.findings) {
    if (idf.severity === "CRITICAL" || idf.severity === "HIGH") {
      findings.push({
        type: "IDENTITY_MISMATCH",
        severity: idf.severity,
        message: idf.message,
      });
    } else if (idf.severity === "MEDIUM" && identityResult.identity_status === "MISSING") {
      findings.push({
        type: "METADATA_MISSING",
        severity: "MEDIUM",
        message: idf.message,
      });
    }
  }

  // AI Security Decision
  let decision: "TRUST" | "REVIEW" | "BLOCK";
  let assessment: string;
  let summary: string;
  let recommendedAction: string;
  const riskFactors: string[] = [];
  const remediationSteps: string[] = [];

  if (riskResult.severity === "CRITICAL" || cveCrit > 0 || identityResult.identity_status === "MISMATCH") {
    decision = "BLOCK";
    assessment = "CRITICAL RISK DETECTED — REJECT DEPLOYMENT";
    summary = `ChainProof AI Engine identified security violations in this workload (${identityResult.identity_status === "MISMATCH" ? "provenance mismatch" : `${cveCrit} critical CVEs`}). Automated CI/CD security gate recommends immediate blocking.`;
    recommendedAction = "Block deployment to Kubernetes clusters. Rebuild image using hardened minimal base and verifiable Git provenance.";
    if (cveCrit > 0) riskFactors.push(`${cveCrit} unmitigated Critical CVEs vulnerable to exploitation.`);
    if (identityResult.identity_status === "MISMATCH") {
      riskFactors.push("High-priority provenance mismatch: container claims a Git revision that conflicts with upstream repository history.");
      remediationSteps.push("Rebuild container artifact in automated CI/CD to align OCI revision annotation with verifiable Git commit SHA.");
    }
    if (!isVerified) riskFactors.push("Unverified cryptographic signature allows potential supply chain tampering.");
    if (isAnomaly) riskFactors.push("Anomalous package footprint suggests excessive build tool dependencies.");
    remediationSteps.push("Upgrade base image to an actively maintained distroless or minimal variant.");
    remediationSteps.push("Run 'cosign sign' in the release pipeline to establish verifiable SLSA provenance.");
    remediationSteps.push("Prune unnecessary package caches and compilers from final Dockerfile stages.");
  } else if (riskResult.severity === "HIGH" || cveHigh > 0 || !isVerified || identityResult.identity_status === "MISSING") {
    decision = "REVIEW";
    assessment = "HIGH RISK — CONDITIONAL APPROVAL WITH REMEDIATION REQUIRED";
    summary = `Container contains risk signals (${cveHigh > 0 ? `${cveHigh} high CVEs` : "identity metadata unverified"}). Supply-chain provenance requires manual security team review before production promotion.`;
    recommendedAction = "Permit in staging environments only. Enforce package patch roadmap and OCI metadata standard before production.";
    if (cveHigh > 0) riskFactors.push(`${cveHigh} High severity vulnerabilities identified.`);
    if (!isVerified) riskFactors.push("Digital signature absent or not recognized by internal trust roots.");
    if (identityResult.identity_status === "MISSING") {
      riskFactors.push("Missing standard OCI annotations (org.opencontainers.image.source / revision).");
      remediationSteps.push("Configure Dockerfile LABEL org.opencontainers.image.source and revision during build.");
    }
    remediationSteps.push("Apply latest security patches to packages flagged by Docker Scout.");
    remediationSteps.push("Sign artifact using organization Cosign private key.");
  } else {
    decision = "TRUST";
    assessment = "TRUSTED — MEETS ENTERPRISE SECURITY POLICIES";
    summary = "Zero critical or high vulnerabilities detected. Package composition is minimal and cryptographic integrity is verified.";
    recommendedAction = "Approve for automated deployment across all production clusters.";
    riskFactors.push("Clean vulnerability posture; minimal attack surface.");
    if (identityResult.identity_status === "VERIFIED") {
      riskFactors.push("Source repository and Git commit successfully verified against upstream remote.");
    }
    remediationSteps.push("Maintain automated nightly audits to detect newly published CVEs.");
  }

  const effectiveId = resolvedDigest || ("sha256:" + crypto.createHash("sha256").update(cleanImage).digest("hex"));

  return {
    id: Date.now(),
    scan_id: crypto.randomUUID(),
    image: cleanImage,
    timestamp,
    risk_score: riskResult.risk_score,
    severity: riskResult.severity,
    verdict: riskResult.verdict,
    docker: {
      image: cleanImage,
      id: effectiveId,
      digest: resolvedDigest,
      created: timestamp,
      size_bytes: Math.round(sizeMb * 1024 * 1024),
      size_mb: sizeMb,
      layers: Math.max(1, Math.round(sizeMb / 15)),
      architecture: "amd64",
      os: "linux",
      config: { Env: ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"] },
      oci_annotations: identityResult.oci_annotations,
    },
    identity: identityResult,
    sbom: {
      status: "SUCCESS",
      package_count: pkgCount,
      packages: pkgList,
    },
    vulnerabilities: {
      status: "PASS",
      total: totalCve,
      critical: cveCrit,
      high: cveHigh,
      medium: cveMed,
      low: cveLow,
      vulnerabilities: cveList,
    },
    signature: {
      signed: isSigned,
      verified: isVerified,
      issuer: isSigned ? "https://accounts.google.com" : undefined,
      subject: isSigned ? "release-pipeline@chainproof.security" : undefined,
      error: isVerified ? null : "Keyless signature attestation not present in Rekor transparency log",
    },
    ml: {
      features: {
        critical_cves: cveCrit,
        high_cves: cveHigh,
        medium_cves: cveMed,
        low_cves: cveLow,
        package_count: pkgCount,
        image_size_mb: sizeMb,
        is_signed: isSigned ? 1 : 0,
        is_verified: isVerified ? 1 : 0,
      },
      random_forest: {
        prediction: mlPrediction,
        confidence: mlConfidence,
        model_loaded: true,
      },
      anomaly_detection: {
        anomaly: isAnomaly,
        anomaly_score: anomalyScore,
        model_loaded: true,
      },
      final_ml_score: labelToScore(mlPrediction),
      ml_confidence: mlConfidence,
    },
    risk: riskResult,
    findings,
    ai_analysis: {
      security_decision: decision,
      confidence: mlConfidence,
      assessment,
      summary,
      risk_factors: riskFactors,
      recommended_action: recommendedAction,
      remediation_steps: remediationSteps,
      correlated_risks: [
        {
          title: "Source-to-Container Identity",
          detail: identityResult.identity_status === "VERIFIED"
            ? `Verified commit ${identityResult.claimed_source_commit?.slice(0, 10)} matches ${identityResult.source_repository}.`
            : identityResult.identity_status === "MISMATCH"
            ? `Provenance conflict detected: claimed commit does not match upstream ${identityResult.source_repository}.`
            : identityResult.identity_status === "MISSING"
            ? "Missing org.opencontainers.image.source / revision annotations."
            : `Status: ${identityResult.identity_status} (${identityResult.details?.error || "Inconclusive"})`,
          severity: identityResult.identity_status === "VERIFIED" ? "LOW" : identityResult.identity_status === "MISMATCH" ? "CRITICAL" : "MEDIUM",
        },
        {
          title: "Supply-Chain Integrity",
          detail: isVerified ? "Cryptographic Cosign signature verified in transparency log." : "Unsigned container image lacks verifiable provenance attestation.",
          severity: isVerified ? "LOW" : "HIGH",
        },
        {
          title: "Vulnerability Density",
          detail: `${totalCve} total CVEs (${cveCrit} Critical, ${cveHigh} High) across ${pkgCount} installed packages.`,
          severity: cveCrit > 0 ? "CRITICAL" : cveHigh > 0 ? "HIGH" : "LOW",
        },
        {
          title: "ML Anomaly Profile",
          detail: isAnomaly ? "Isolation forest detected anomalous package to size ratio." : "Container profile matches normal distribution of hardened base images.",
          severity: isAnomaly ? "MEDIUM" : "LOW",
        },
      ],
    },
  };
}

// Initial reports seed
const reportsStore: ScanReport[] = [
  await createScanResult("alpine:latest"),
  await createScanResult("nginx:alpine"),
  await createScanResult("python:3.11-slim"),
  await createScanResult("bkimminich/juice-shop:latest"),
];

// Initial Automations
const automationsStore = [
  {
    id: "auto-prod-nightly",
    name: "Production Nightly Vulnerability Audit",
    trigger: "SCHEDULE",
    schedule: "02:00",
    targets: ["alpine:latest", "nginx:alpine", "python:3.11-slim"],
    action: "SCAN_IMAGE",
    enabled: true,
    created_at: new Date(Date.now() - 86400000 * 7).toISOString(),
    run_count: 14,
    last_run: new Date(Date.now() - 3600000 * 2).toISOString(),
    tags: ["production", "nightly", "cve"],
  },
  {
    id: "auto-ghcr-webhook",
    name: "GHCR / Docker Hub Registry Push Listener",
    trigger: "NEW_IMAGE_VERSION",
    target: "ghcr.io/company/payments-api",
    targets: ["ghcr.io/company/payments-api:latest"],
    action: "SCAN_IMAGE",
    enabled: true,
    created_at: new Date(Date.now() - 86400000 * 14).toISOString(),
    run_count: 8,
    last_run: new Date(Date.now() - 3600000 * 12).toISOString(),
    tags: ["registry", "webhook", "cicd"],
  },
];

// Initial Jobs
const jobsStore = [
  {
    id: "job-d841c90a12",
    automation_id: "auto-prod-nightly",
    automation_name: "Production Nightly Vulnerability Audit",
    trigger: "SCHEDULE",
    target: "alpine:latest",
    status: "SUCCESS",
    started_at: new Date(Date.now() - 3600000 * 2).toISOString(),
    completed_at: new Date(Date.now() - 3600000 * 2 + 4500).toISOString(),
    risk_score: 15,
    severity: "LOW",
    decision: "TRUST",
    scan_id: crypto.randomUUID(),
    summary: "Audit completed with 0 Critical, 0 High, 1 Medium CVEs. Clean container posture.",
    error: null,
  },
  {
    id: "job-c732b10f88",
    automation_id: "auto-ghcr-webhook",
    automation_name: "GHCR Registry Push Listener",
    trigger: "WEBHOOK",
    target: "nginx:alpine",
    status: "SUCCESS",
    started_at: new Date(Date.now() - 3600000 * 12).toISOString(),
    completed_at: new Date(Date.now() - 3600000 * 12 + 5200).toISOString(),
    risk_score: 48,
    severity: "MEDIUM",
    decision: "REVIEW",
    scan_id: crypto.randomUUID(),
    summary: "Completed with 1 High CVE. Recommended patch upgrade to 1.25.4-alpine.",
    error: null,
  },
];

// Initial Notifications
const notificationsStore = [
  {
    id: "notif-01",
    title: "ChainProof Security Engine Online",
    message: "Multi-signal vulnerability correlation, Syft SBOM, and Cosign verification active.",
    severity: "INFO",
    channel: "SYSTEM",
    payload: {},
    timestamp: new Date().toISOString(),
    read: true,
  },
  {
    id: "notif-02",
    title: "Vulnerability Gate Alert: Juice Shop",
    message: "Critical CVE-2026-38410 detected with risk score 96. Deployment blocked.",
    severity: "CRITICAL",
    channel: "CI/CD",
    payload: { image: "bkimminich/juice-shop:latest" },
    timestamp: new Date(Date.now() - 3600000 * 4).toISOString(),
    read: false,
  },
];

// Initial Monitored Images
const monitoredStore = [
  {
    id: "mon-alpine",
    image: "alpine:latest",
    tags: ["latest", "3.20"],
    auto_scan: true,
    schedule: "02:00",
    last_scanned: new Date().toISOString(),
    risk_score: 15,
    severity: "LOW",
    decision: "TRUST",
    total_cves: 1,
    created_at: new Date(Date.now() - 86400000 * 10).toISOString(),
  },
  {
    id: "mon-nginx",
    image: "nginx:alpine",
    tags: ["alpine", "latest"],
    auto_scan: true,
    schedule: "03:00",
    last_scanned: new Date().toISOString(),
    risk_score: 48,
    severity: "MEDIUM",
    decision: "REVIEW",
    total_cves: 4,
    created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
];

// ============================================================================
// API Endpoints (/api/v1/*)
// ============================================================================

// Health check
app.get("/api/v1/health", (_req: Request, res: Response) => {
  res.json({
    status: "HEALTHY",
    version: "2.0.0",
    services: {
      docker: { connected: true, version: "24.0.7", os: "linux", arch: "x86_64", error: null },
      scout: { available: true, version: "1.0.9" },
      syft: { available: true, version: "0.105.0" },
      cosign: { available: true, version: "2.2.3" },
      ml_engine: { risk_model: "LOADED", anomaly_model: "LOADED", status: "READY" },
      ai_analyst: { provider: "gemini-flash", status: "ONLINE" },
    },
    timestamp: new Date().toISOString(),
  });
});

// Identity verification on demand
app.post("/api/v1/identity/verify", async (req: Request, res: Response) => {
  const { image, source_repo, commit } = req.body || {};
  if (!image || typeof image !== "string" || !image.trim()) {
    return res.status(400).json({ detail: "Container image reference is required" });
  }

  const clean = image.trim();
  const digestRes = resolveImageDigest(clean);
  const presetLabels = getPresetOciMetadata(clean);

  const result = await verifySourceIdentity({
    imageReference: clean,
    imageDigest: digestRes.image_digest,
    imageId: digestRes.image_digest,
    rawLabels: presetLabels,
    overrideSourceRepo: source_repo,
    overrideRevision: commit,
  });

  return res.json(result);
});

// Scan image
app.post("/api/v1/scan", async (req: Request, res: Response) => {
  const { image, source_repo, commit } = req.body || {};
  if (!image || typeof image !== "string" || !image.trim()) {
    return res.status(400).json({ detail: "Container image name is required" });
  }

  const clean = image.trim();
  if (/[;&|><$`\\]/.test(clean)) {
    return res.status(400).json({ detail: "Invalid characters detected in image name" });
  }

  const scanResult = await createScanResult(clean, { sourceRepo: source_repo, commit });
  // Add to front of history
  reportsStore.unshift(scanResult);

  // Auto record notification if critical
  if (scanResult.severity === "CRITICAL") {
    notificationsStore.unshift({
      id: `notif-${Date.now()}`,
      title: `Critical Alert: ${clean}`,
      message: `Container scan failed security policy with risk score ${scanResult.risk_score}/100.`,
      severity: "CRITICAL",
      channel: "SCANNER",
      payload: { image: clean, score: scanResult.risk_score },
      timestamp: new Date().toISOString(),
      read: false,
    });
  }

  return res.json(scanResult);
});

// Reports history
app.get("/api/v1/reports", (_req: Request, res: Response) => {
  res.json(reportsStore);
});

// Clear reports
app.delete("/api/v1/reports", (_req: Request, res: Response) => {
  reportsStore.length = 0;
  res.json({ message: "Scan report history cleared successfully", count: 0 });
});

// AI Analyze on demand
app.post(["/api/v1/analyze", "/api/v1/ai/analyze"], async (req: Request, res: Response) => {
  const scanData = req.body;
  if (!scanData || !scanData.image) {
    return res.status(400).json({ detail: "Valid scan payload required for analysis" });
  }

  const result = await createScanResult(scanData.image);
  return res.json(result.ai_analysis);
});

// Automations
app.get("/api/v1/automations", (_req: Request, res: Response) => {
  res.json(automationsStore);
});

app.post("/api/v1/automations/:id/run", async (req: Request, res: Response) => {
  const auto = automationsStore.find((a) => a.id === req.params.id);
  if (!auto) {
    return res.status(404).json({ detail: "Automation rule not found" });
  }

  auto.run_count += 1;
  auto.last_run = new Date().toISOString();

  const target = auto.targets?.[0] || auto.target || "alpine:latest";
  const scan = await createScanResult(target);
  reportsStore.unshift(scan);

  const job = {
    id: `job-${Date.now().toString(36)}`,
    automation_id: auto.id,
    automation_name: auto.name,
    trigger: "MANUAL",
    target,
    status: "SUCCESS",
    started_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
    risk_score: scan.risk_score,
    severity: scan.severity,
    decision: scan.ai_analysis.security_decision,
    scan_id: scan.scan_id,
    summary: `Executed on-demand scan of ${target}. Result: ${scan.verdict}.`,
    error: null,
  };
  jobsStore.unshift(job);

  return res.json({ status: "SUCCESS", message: "Automation executed successfully", job, scan });
});

// Jobs
app.get("/api/v1/jobs", (req: Request, res: Response) => {
  const limit = parseInt((req.query.limit as string) || "50");
  res.json(jobsStore.slice(0, limit));
});

// Notifications
app.get("/api/v1/notifications", (req: Request, res: Response) => {
  const limit = parseInt((req.query.limit as string) || "50");
  res.json(notificationsStore.slice(0, limit));
});

// Monitored Images
app.get("/api/v1/monitored-images", (_req: Request, res: Response) => {
  res.json(monitoredStore);
});

app.post("/api/v1/monitored-images", (req: Request, res: Response) => {
  const { image, tags, schedule } = req.body || {};
  if (!image) {
    return res.status(400).json({ detail: "Image reference is required" });
  }

  const newEntry = {
    id: `mon-${Date.now().toString(36)}`,
    image: image.trim(),
    tags: tags || ["latest"],
    auto_scan: true,
    schedule: schedule || "02:00",
    last_scanned: null,
    risk_score: null,
    severity: null,
    decision: null,
    total_cves: null,
    created_at: new Date().toISOString(),
  };

  monitoredStore.unshift(newEntry);
  res.json(newEntry);
});

app.delete("/api/v1/monitored-images/:id", (req: Request, res: Response) => {
  const id = req.params.id;
  const index = monitoredStore.findIndex((m) => m.id === id || m.image === id);
  if (index !== -1) {
    monitoredStore.splice(index, 1);
    return res.json({ success: true, message: "Monitored image removed" });
  }
  return res.status(404).json({ detail: "Monitored image not found" });
});

// Auth Login
app.post("/api/v1/auth/login", (req: Request, res: Response) => {
  const { username, password } = req.body || {};
  if (username === "admin" && (password === "admin123" || !password || password.length > 0)) {
    return res.json({
      access_token: "mock-jwt-token-chainproof-admin",
      token_type: "bearer",
      user: {
        id: "usr-admin-01",
        username: "admin",
        role: "ADMIN",
        full_name: "Security Administrator",
      },
    });
  }
  // Allow demo login for any credentials
  return res.json({
    access_token: "mock-jwt-token-chainproof-analyst",
    token_type: "bearer",
    user: {
      id: "usr-demo-01",
      username: username || "analyst",
      role: "ANALYST",
      full_name: username ? `${username} (Analyst)` : "Security Analyst",
    },
  });
});

// ============================================================================
// Server Bootstrap & Static / Vite Integration
// ============================================================================

async function startServer() {
  const isProduction = process.env.NODE_ENV === "production";

  if (isProduction) {
    app.use(express.static(path.resolve(__dirname, "dist")));
    app.get("*", (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, "dist", "index.html"));
    });
  } else {
    // Mount Vite middlewares in development
    const vite = await createViteServer({
      server: { middlewareMode: true, host: "0.0.0.0", port: PORT },
      appType: "spa",
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[ChainProof] Unified platform listening at http://0.0.0.0:${PORT}`);
  });
}

startServer();
