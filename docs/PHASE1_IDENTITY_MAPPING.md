# 🛡️ ChainProof — Phase 1: Source-to-Container Identity Mapping

## 1. Feature Description

Phase 1 establishes a verifiable cryptographic relationship between:
1. **Source Code Repository** (e.g., GitHub, GitLab, or generic Git remotes)
2. **Git Source Commit** (immutable SHA-1 or SHA-256 commit hash)
3. **OCI Container Image** (the user-specified container reference or tag)
4. **Immutable OCI Image Digest** (cryptographic SHA-256 manifest digest, e.g., `sha256:0a4eaa0e...`)

This capability enables DevSecOps teams to verify whether an inspected container workload genuinely originates from the source code repository and Git commit it claims to represent, catching counterfeit provenance, unsigned tag mutability attacks, and detached builds.

> **CRITICAL SECURITY NOTICE:**  
> OCI annotations (such as `org.opencontainers.image.source` and `org.opencontainers.image.revision`) are **claims** declared at build time. They are **not independently authenticated or cryptographically binding merely because they exist**. ChainProof independently audits these claims against upstream Git remotes and immutable OCI digests to detect discrepancies and provenance spoofing.

---

## 2. Identity Verification Workflow

```text
 1. User / CI initiates container scan with image reference (e.g., "alpine:latest")
                     ↓
 2. Immutable Digest Resolution (Digest-First Identification)
    - Resolve mutable image tag to immutable SHA-256 digest
    - Pin digest reference for all downstream scanners (Docker, Syft, Scout, Cosign)
                     ↓
 3. OCI Image Metadata Extraction
    - Extract standard org.opencontainers.image.* annotations
    - Compute Metadata Completeness ratio (declared vs missing fields)
    - If annotations absent, return null (never invent metadata)
                     ↓
 4. Claimed Provenance Validation
    - Validate claimed repository URL (prevent command injection & SSRF)
    - Validate claimed revision format (strict 40-hex or 64-hex SHA)
                     ↓
 5. Independent Git Remote Verification
    - Check repository accessibility (without arbitrary script execution)
    - Verify whether claimed commit exists in upstream history
    - Compare claimed revision vs verified commit
                     ↓
 6. Identity Status Classification
    - VERIFIED | CLAIMED | MISMATCH | MISSING | NOT_VERIFIED
                     ↓
 7. Risk Engine Integration
    - Evidence-based penalty: VERIFIED (0), CLAIMED (+1), MISMATCH (+8), MISSING (+3), NOT_VERIFIED (+2)
                     ↓
 8. Unified Intelligence Presentation
    - Dashboard metrics, interactive report cards, OCI annotation table, policy decision
```

---

## 3. Supported OCI Annotations

ChainProof inspects the standard Open Container Initiative (OCI) Image Specification annotations:

| OCI Annotation Key | Purpose | Required for Identity |
|---|---|---|
| `org.opencontainers.image.source` | URL of the upstream Git repository containing the source code | **Yes** |
| `org.opencontainers.image.revision` | Source control revision (Git commit SHA) from which the image was built | **Yes** |
| `org.opencontainers.image.version` | Release version of the packaged software artifact | Optional |
| `org.opencontainers.image.created` | ISO 8601 build timestamp | Optional |
| `org.opencontainers.image.vendor` | Name of the distributing entity or organization | Optional |
| `org.opencontainers.image.documentation` | URL to online documentation | Optional |

If any annotation is omitted in the image manifest or configuration labels, ChainProof returns `null` and logs it as missing in `metadata_completeness.missing_fields`.

---

## 4. Identity Status Definitions

| Status | Definition | Risk Engine Impact |
|---|---|---|
| `VERIFIED` | The source repository and commit have been independently checked, and the verified commit matches the claimed revision. | `0 penalty` (Clean Provenance) |
| `CLAIMED` | The image contains source identity metadata (source repo & commit), but independent verification has not been completed. | `+1 penalty` (Evidence Limitation) |
| `MISMATCH` | The independently verified source identity conflicts with the claimed identity, or the commit does not exist in the repository. | `+8 penalty` (High-Priority Integrity Finding, triggers `BLOCK`) |
| `MISSING` | Required source identity metadata (`source` or `revision`) is absent from the container image. | `+3 penalty` (Identity Warning, triggers `REVIEW`) |
| `NOT_VERIFIED` | Verification could not be completed because of access, network, rate limits, or other operational constraints. | `+2 penalty` (Verification Uncertainty) |

---

## 5. API Response Structure

### `POST /api/v1/identity/verify`
```json
{
  "image_reference": "alpine:latest",
  "image_digest": "sha256:0a4eaa0eecf5f8777c6040a7d45c848d3527092fa4e8bf0b3f9d7b3524b374df",
  "image_id": "sha256:0a4eaa0eecf5f8777c6040a7d45c848d3527092fa4e8bf0b3f9d7b3524b374df",
  "source_repository": "https://github.com/alpinelinux/docker-alpine",
  "claimed_source_commit": "9a2f7c04df1684c3e390e43ea60ea4c161be0d58",
  "verified_source_commit": "9a2f7c04df1684c3e390e43ea60ea4c161be0d58",
  "repository_accessible": true,
  "commit_exists": true,
  "commit_matches": true,
  "metadata_completeness": {
    "total_expected": 6,
    "present_count": 6,
    "missing_count": 0,
    "percentage": 100,
    "missing_fields": [],
    "present_fields": [
      "org.opencontainers.image.source",
      "org.opencontainers.image.revision",
      "org.opencontainers.image.version",
      "org.opencontainers.image.created",
      "org.opencontainers.image.vendor",
      "org.opencontainers.image.documentation"
    ]
  },
  "identity_status": "VERIFIED",
  "findings": [
    {
      "type": "DIGEST_RESOLUTION",
      "severity": "INFO",
      "message": "Image reference pinned to immutable digest: sha256:0a4eaa0eecf...",
      "code": "DIGEST_PINNED"
    },
    {
      "type": "IDENTITY_VERIFICATION",
      "severity": "INFO",
      "message": "Cryptographic identity confirmed: commit 9a2f7c04df exists in https://github.com/alpinelinux/docker-alpine and matches container revision.",
      "code": "COMMIT_VERIFIED"
    }
  ],
  "oci_annotations": {
    "org.opencontainers.image.source": "https://github.com/alpinelinux/docker-alpine",
    "org.opencontainers.image.revision": "9a2f7c04df1684c3e390e43ea60ea4c161be0d58",
    "org.opencontainers.image.version": "3.20.0",
    "org.opencontainers.image.created": "2024-05-22T08:00:00Z",
    "org.opencontainers.image.vendor": "Alpine Linux Development Team",
    "org.opencontainers.image.documentation": "https://wiki.alpinelinux.org/"
  },
  "verification_timestamp": "2026-11-12T00:53:20.123Z",
  "details": {
    "resolution_method": "docker_inspection",
    "repo_type": "github",
    "commit_url": "https://github.com/alpinelinux/docker-alpine/commit/9a2f7c04df1684c3e390e43ea60ea4c161be0d58",
    "repo_url": "https://github.com/alpinelinux/docker-alpine",
    "error": null,
    "digest_consistent": true
  }
}
```

---

## 6. Testing Instructions

To run the automated identity mapping test suite:

```bash
npm test
# or
npm run test:identity
```

The test runner will execute all 12 validation scenarios covering:
- Valid OCI annotations extraction
- Missing annotations handling
- Upstream Git commit verification
- Nonexistent Git commit detection (`MISMATCH`)
- Inaccessible Git repository handling (`NOT_VERIFIED`)
- Malformed commit SHA validation
- Commit match and conflict classification
- Digest resolution & consistency throughout scans
- Registry resolution timeout/failure reporting
- Evidence-based risk score calculations

---

## 7. Known Limitations

1. **Private Git Repositories**: Public repositories are verified out-of-the-box without authentication. Private repositories require an authenticated GitHub/GitLab personal access token (PAT) configured via environment variables. If a private repository is scanned without credentials, ChainProof safely reports `NOT_VERIFIED` rather than a false positive failure.
2. **Rate Limiting**: Public unauthenticated GitHub API endpoints have an IP rate limit (60 requests/hour). If rate limits are reached, the system marks the identity check as `NOT_VERIFIED` with a clear diagnostic message.
3. **Multi-Architecture Manifest Lists**: For fat manifests containing multiple platform architectures, digest resolution resolves the top-level manifest list digest unless a specific architecture digest is targeted.
