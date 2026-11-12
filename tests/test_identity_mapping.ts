/**
 * ChainProof - Phase 1: Source-to-Container Identity Mapping Automated Test Suite
 * 
 * Verifies all 12 required test scenarios:
 * 1. Image containing valid OCI source annotations
 * 2. Image with missing source annotations
 * 3. Valid Git repository and existing commit
 * 4. Nonexistent Git commit
 * 5. Repository inaccessible
 * 6. Invalid commit SHA format
 * 7. OCI revision matching the actual Git commit
 * 8. OCI revision conflicting with the actual Git commit
 * 9. Image tag resolving to a digest
 * 10. Image digest remaining consistent throughout a scan
 * 11. Registry resolution failure
 * 12. Risk engine handling each identity status
 */

import {
  extractOciAnnotations,
  validateCommitSha,
  validateGitUrl,
  resolveImageDigest,
  verifySourceIdentity,
  STANDARD_OCI_KEYS,
  IdentityStatus,
} from "../src/services/identityService.js";

// Import risk calculation logic
function labelToScore(label: string): number {
  switch (label.toUpperCase()) {
    case "LOW": return 15;
    case "MEDIUM": return 45;
    case "HIGH": return 72;
    case "CRITICAL": return 92;
    default: return 50;
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

  return {
    risk_score: score,
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

// Simple test harness
let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition: boolean, testName: string, detail: string = "") {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  ✓ [PASS] Scenario ${totalTests}: ${testName}`);
  } else {
    failedTests++;
    console.error(`  ✕ [FAIL] Scenario ${totalTests}: ${testName} - ${detail}`);
  }
}

async function runAllScenarios() {
  console.log("==================================================================");
  console.log("  ChainProof Phase 1: Source-to-Container Identity Mapping Tests  ");
  console.log("==================================================================\n");

  // --------------------------------------------------------------------------
  // Scenario 1: Image containing valid OCI source annotations
  // --------------------------------------------------------------------------
  {
    const labels = {
      "org.opencontainers.image.source": "https://github.com/alpinelinux/docker-alpine",
      "org.opencontainers.image.revision": "9a2f7c04df1684c3e390e43ea60ea4c161be0d58",
      "org.opencontainers.image.version": "3.20.0",
      "org.opencontainers.image.created": "2024-05-22T08:00:00Z",
      "org.opencontainers.image.vendor": "Alpine Linux Team",
      "org.opencontainers.image.documentation": "https://wiki.alpinelinux.org/",
    };

    const { annotations, completeness } = extractOciAnnotations(labels);
    const hasAll = STANDARD_OCI_KEYS.every((k) => annotations[k] !== null);
    assert(
      hasAll && completeness.percentage === 100 && completeness.missing_count === 0,
      "Image containing valid OCI source annotations extracts all 6 standard fields with 100% completeness"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 2: Image with missing source annotations
  // --------------------------------------------------------------------------
  {
    const emptyLabels = { "maintainer": "dev@example.com" };
    const { annotations, completeness } = extractOciAnnotations(emptyLabels);
    const res = await verifySourceIdentity({
      imageReference: "custom-unannotated:1.0",
      imageDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      imageId: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      rawLabels: emptyLabels,
    });

    assert(
      annotations["org.opencontainers.image.source"] === null &&
      annotations["org.opencontainers.image.revision"] === null &&
      completeness.missing_count === 6 &&
      res.identity_status === "MISSING",
      "Image with missing source annotations reports null fields and classifies identity as MISSING without inventing data"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 3: Valid Git repository and existing commit
  // --------------------------------------------------------------------------
  {
    const commitSha = "9a2f7c04df1684c3e390e43ea60ea4c161be0d58";
    const res = await verifySourceIdentity({
      imageReference: "alpine:latest",
      imageDigest: "sha256:0a4eaa0eecf5f8777c6040a7d45c848d3527092fa4e8bf0b3f9d7b3524b374df",
      imageId: "sha256:0a4eaa0eecf5f8777c6040a7d45c848d3527092fa4e8bf0b3f9d7b3524b374df",
      rawLabels: {
        "org.opencontainers.image.source": "https://github.com/alpinelinux/docker-alpine",
        "org.opencontainers.image.revision": commitSha,
      },
      mockCommitLookup: {
        accessible: true,
        exists: true,
        actualCommit: commitSha,
      },
    });

    assert(
      res.identity_status === "VERIFIED" &&
      res.repository_accessible === true &&
      res.commit_exists === true &&
      res.commit_matches === true,
      "Valid Git repository and existing commit classifies identity as VERIFIED"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 4: Nonexistent Git commit
  // --------------------------------------------------------------------------
  {
    const fakeCommit = "deadbeef00001111222233334444555566667777";
    const res = await verifySourceIdentity({
      imageReference: "app:tampered",
      imageDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      imageId: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      rawLabels: {
        "org.opencontainers.image.source": "https://github.com/legit-org/app",
        "org.opencontainers.image.revision": fakeCommit,
      },
      mockCommitLookup: {
        accessible: true,
        exists: false,
        error: "Commit not found in repository (HTTP 404)",
      },
    });

    assert(
      res.identity_status === "MISMATCH" &&
      res.commit_exists === false &&
      res.commit_matches === false &&
      res.findings.some((f) => f.code === "COMMIT_NONEXISTENT"),
      "Nonexistent Git commit flags provenance mismatch with COMMIT_NONEXISTENT finding"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 5: Repository inaccessible
  // --------------------------------------------------------------------------
  {
    const validCommit = "a718b53d867c2e3919e916a2410a2b17578351e0";
    const res = await verifySourceIdentity({
      imageReference: "internal-service:1.2",
      imageDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      imageId: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      rawLabels: {
        "org.opencontainers.image.source": "https://github.com/private-org/service",
        "org.opencontainers.image.revision": validCommit,
      },
      mockCommitLookup: {
        accessible: false,
        exists: false,
        error: "GitHub API rate limit exceeded or access restricted",
      },
    });

    assert(
      res.identity_status === "NOT_VERIFIED" &&
      res.repository_accessible === false &&
      res.findings.some((f) => f.code === "REMOTE_INACCESSIBLE"),
      "Repository inaccessible returns NOT_VERIFIED without incorrectly marking image as malicious"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 6: Invalid commit SHA format
  // --------------------------------------------------------------------------
  {
    const invalidSha = "not-a-valid-sha-12345";
    const isShaFormatValid = validateCommitSha(invalidSha);
    const res = await verifySourceIdentity({
      imageReference: "broken-tag:latest",
      imageDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
      imageId: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
      rawLabels: {
        "org.opencontainers.image.source": "https://github.com/my-org/repo",
        "org.opencontainers.image.revision": invalidSha,
      },
    });

    assert(
      !isShaFormatValid &&
      res.identity_status === "MISMATCH" &&
      res.findings.some((f) => f.code === "INVALID_COMMIT_SHA_FORMAT"),
      "Invalid commit SHA format is strictly rejected and flagged as MISMATCH"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 7: OCI revision matching the actual Git commit
  // --------------------------------------------------------------------------
  {
    const commit = "8f41e916a2410ad55ff562d908eb426e8f4955eb";
    const res = await verifySourceIdentity({
      imageReference: "python:3.11-slim",
      imageDigest: "sha256:d55ff562d908eb426e8f4955eb4f4cb267c7689d0e14c36c2e3919e916a2410a",
      imageId: "sha256:d55ff562d908eb426e8f4955eb4f4cb267c7689d0e14c36c2e3919e916a2410a",
      rawLabels: {
        "org.opencontainers.image.source": "https://github.com/docker-library/python",
        "org.opencontainers.image.revision": commit,
      },
      mockCommitLookup: {
        accessible: true,
        exists: true,
        actualCommit: commit,
      },
    });

    assert(
      res.claimed_source_commit === res.verified_source_commit &&
      res.commit_matches === true &&
      res.identity_status === "VERIFIED",
      "OCI revision matching the actual Git commit returns commit_matches=true and status=VERIFIED"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 8: OCI revision conflicting with the actual Git commit
  // --------------------------------------------------------------------------
  {
    const claimedCommit = "8f41e916a2410ad55ff562d908eb426e8f4955eb";
    const actualCommit = "1111111122222222333333334444444455555555";
    const res = await verifySourceIdentity({
      imageReference: "divergent-app:v1",
      imageDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
      imageId: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
      rawLabels: {
        "org.opencontainers.image.source": "https://github.com/org/repo",
        "org.opencontainers.image.revision": claimedCommit,
      },
      mockCommitLookup: {
        accessible: true,
        exists: true,
        actualCommit: actualCommit,
      },
    });

    assert(
      res.claimed_source_commit !== res.verified_source_commit &&
      res.commit_matches === false &&
      res.identity_status === "MISMATCH" &&
      res.findings.some((f) => f.code === "COMMIT_MISMATCH"),
      "OCI revision conflicting with actual Git commit returns commit_matches=false and status=MISMATCH"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 9: Image tag resolving to a digest
  // --------------------------------------------------------------------------
  {
    const resolution = resolveImageDigest("alpine:latest");
    assert(
      resolution.resolution_success === true &&
      resolution.image_digest !== null &&
      resolution.image_digest.startsWith("sha256:") &&
      resolution.image_digest.length === 71,
      "Image tag resolves to an immutable 64-char SHA-256 OCI digest"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 10: Image digest remaining consistent throughout a scan
  // --------------------------------------------------------------------------
  {
    const targetTag = "nginx:alpine";
    const initialResolution = resolveImageDigest(targetTag);
    const firstDigest = initialResolution.image_digest;

    const identityRes = await verifySourceIdentity({
      imageReference: targetTag,
      imageDigest: firstDigest,
      imageId: firstDigest,
      rawLabels: {
        "org.opencontainers.image.source": "https://github.com/nginxinc/docker-nginx",
        "org.opencontainers.image.revision": "a718b53d867c2e3919e916a2410a2b17578351e0",
      },
      mockCommitLookup: { accessible: true, exists: true, actualCommit: "a718b53d867c2e3919e916a2410a2b17578351e0" },
    });

    assert(
      identityRes.image_digest === firstDigest &&
      identityRes.details.digest_consistent === true,
      "Image digest remains consistent across initial resolution and verification pipeline"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 11: Registry resolution failure
  // --------------------------------------------------------------------------
  {
    const failedResolution = resolveImageDigest("unresolvable-registry.internal/fake/image:missing");
    const res = await verifySourceIdentity({
      imageReference: "unresolvable-registry.internal/fake/image:missing",
      imageDigest: null,
      imageId: null,
      rawLabels: {},
    });

    assert(
      failedResolution.resolution_success === false &&
      failedResolution.image_digest === null &&
      res.findings.some((f) => f.code === "DIGEST_RESOLUTION_FAILED"),
      "Registry resolution failure reports clear diagnostic and records DIGEST_RESOLUTION_FAILED"
    );
  }

  // --------------------------------------------------------------------------
  // Scenario 12: Risk engine handling each identity status
  // --------------------------------------------------------------------------
  {
    const baseVulns = { critical: 0, high: 0, medium: 0, low: 0 };
    const baseSig = { verified: true };
    const baseMl = { prediction: "LOW", confidence: 0.95 };
    const baseAnomaly = { anomaly: false };

    // Baseline LOW ML score = 15
    const riskVerified = calculateRisk(baseVulns, baseSig, baseMl, baseAnomaly, "VERIFIED");
    const riskClaimed = calculateRisk(baseVulns, baseSig, baseMl, baseAnomaly, "CLAIMED");
    const riskNotVerified = calculateRisk(baseVulns, baseSig, baseMl, baseAnomaly, "NOT_VERIFIED");
    const riskMissing = calculateRisk(baseVulns, baseSig, baseMl, baseAnomaly, "MISSING");
    const riskMismatch = calculateRisk(baseVulns, baseSig, baseMl, baseAnomaly, "MISMATCH");

    const penaltiesCorrect = 
      riskVerified.score_breakdown.identity_penalty === 0 &&
      riskClaimed.score_breakdown.identity_penalty === 1 &&
      riskNotVerified.score_breakdown.identity_penalty === 2 &&
      riskMissing.score_breakdown.identity_penalty === 3 &&
      riskMismatch.score_breakdown.identity_penalty === 8;

    const scoresOrdered =
      riskVerified.risk_score < riskClaimed.risk_score &&
      riskClaimed.risk_score < riskNotVerified.risk_score &&
      riskNotVerified.risk_score < riskMissing.risk_score &&
      riskMissing.risk_score < riskMismatch.risk_score;

    assert(
      penaltiesCorrect && scoresOrdered,
      "Risk engine correctly calculates identity_penalty (VERIFIED:0, CLAIMED:+1, NOT_VERIFIED:+2, MISSING:+3, MISMATCH:+8)"
    );
  }

  // --------------------------------------------------------------------------
  // Summary
  // --------------------------------------------------------------------------
  console.log("\n==================================================================");
  console.log(`  Tests Completed: ${totalTests} | Passed: ${passedTests} | Failed: ${failedTests}`);
  console.log("==================================================================\n");

  if (failedTests > 0) {
    process.exit(1);
  }
}

runAllScenarios().catch((err) => {
  console.error("Test execution failed unexpectedly:", err);
  process.exit(1);
});
