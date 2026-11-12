import { useState } from "react";
import { 
    ShieldCheckIcon, 
    ShieldAlertIcon, 
    ShieldIcon, 
    CheckCircleIcon, 
    XCircleIcon, 
    AlertTriangleIcon, 
    CopyIcon, 
    FileTextIcon, 
    KeyIcon,
    ChevronRightIcon
} from "./Icons";

export function getIdentityStatusBadge(status) {
    const s = (status || "NOT_VERIFIED").toUpperCase();
    switch (s) {
        case "VERIFIED":
            return {
                label: "VERIFIED IDENTITY",
                subtext: "Cryptographically verified against upstream Git repository",
                badgeClass: "identity-badge-verified",
                icon: ShieldCheckIcon,
                color: "#16a34a"
            };
        case "CLAIMED":
            return {
                label: "CLAIMED IDENTITY",
                subtext: "Source declared in OCI annotations, awaiting independent remote verification",
                badgeClass: "identity-badge-claimed",
                icon: FileTextIcon,
                color: "#0284c7"
            };
        case "MISMATCH":
            return {
                label: "IDENTITY MISMATCH",
                subtext: "Claimed revision does not match upstream Git repository commit",
                badgeClass: "identity-badge-mismatch",
                icon: ShieldAlertIcon,
                color: "#dc2626"
            };
        case "MISSING":
            return {
                label: "MISSING IDENTITY",
                subtext: "Required OCI source or revision annotations are absent",
                badgeClass: "identity-badge-missing",
                icon: AlertTriangleIcon,
                color: "#ea580c"
            };
        case "NOT_VERIFIED":
        default:
            return {
                label: "NOT VERIFIED",
                subtext: "Repository verification inconclusive due to network or access restrictions",
                badgeClass: "identity-badge-unverified",
                icon: ShieldIcon,
                color: "#64748b"
            };
    }
}

function SourceIdentityCard({ identityData, imageReference, className = "" }) {
    const [copiedKey, setCopiedKey] = useState(null);
    const [showAnnotations, setShowAnnotations] = useState(false);

    if (!identityData) {
        return (
            <div className={`result-card ${className}`}>
                <div className="card-header-with-badge">
                    <h2><KeyIcon size={18} /> Source-to-Container Identity</h2>
                    <span className="status-pill status-unverified">NOT AVAILABLE</span>
                </div>
                <p className="empty-state-text">No identity provenance telemetry available for this image.</p>
            </div>
        );
    }

    const {
        image_digest,
        source_repository,
        claimed_source_commit,
        verified_source_commit,
        repository_accessible,
        commit_exists,
        commit_matches,
        metadata_completeness,
        identity_status,
        findings = [],
        oci_annotations = {},
        verification_timestamp,
        details = {}
    } = identityData;

    const badgeInfo = getIdentityStatusBadge(identity_status);
    const BadgeIcon = badgeInfo.icon;

    const handleCopy = (text, key) => {
        if (!text) return;
        navigator.clipboard.writeText(text);
        setCopiedKey(key);
        setTimeout(() => setCopiedKey(null), 2000);
    };

    const renderShortCommit = (commitSha) => {
        if (!commitSha) return "None";
        if (commitSha.length > 12) {
            return `${commitSha.slice(0, 10)}...`;
        }
        return commitSha;
    };

    return (
        <div className={`source-identity-card result-card ${className}`}>
            {/* Header with Title and Identity Status Badge */}
            <div className="identity-card-header">
                <div>
                    <div className="identity-pre-title">
                        <KeyIcon size={14} />
                        <span>OCI SUPPLY-CHAIN PROVENANCE</span>
                    </div>
                    <h2 className="identity-main-title">Source-to-Container Identity Mapping</h2>
                </div>

                <div className={`identity-status-pill ${badgeInfo.badgeClass}`}>
                    <BadgeIcon size={16} />
                    <span className="status-pill-text">{badgeInfo.label}</span>
                </div>
            </div>

            <p className="identity-status-subtext">
                {badgeInfo.subtext}
            </p>

            {/* 4-Item Quick Stats Matrix */}
            <div className="identity-matrix-grid">
                <div className="identity-matrix-item">
                    <span className="matrix-label">Repository Accessibility</span>
                    <strong className={`matrix-value ${repository_accessible === true ? "text-pass" : repository_accessible === false ? "text-fail" : "text-muted"}`}>
                        {repository_accessible === true ? (
                            <><CheckCircleIcon size={14} /> Accessible</>
                        ) : repository_accessible === false ? (
                            <><XCircleIcon size={14} /> Inaccessible</>
                        ) : (
                            "Not Checked"
                        )}
                    </strong>
                </div>

                <div className="identity-matrix-item">
                    <span className="matrix-label">Commit Verification</span>
                    <strong className={`matrix-value ${commit_matches === true ? "text-pass" : commit_matches === false ? "text-fail" : "text-muted"}`}>
                        {commit_matches === true ? (
                            <><CheckCircleIcon size={14} /> Matched</>
                        ) : commit_matches === false ? (
                            <><XCircleIcon size={14} /> Conflict</>
                        ) : commit_exists === true ? (
                            "Exists (Claimed)"
                        ) : (
                            "Unverified"
                        )}
                    </strong>
                </div>

                <div className="identity-matrix-item">
                    <span className="matrix-label">OCI Metadata Completeness</span>
                    <strong className="matrix-value">
                        {metadata_completeness?.percentage ?? 0}% ({metadata_completeness?.present_count ?? 0}/{metadata_completeness?.total_expected ?? 6})
                    </strong>
                </div>

                <div className="identity-matrix-item">
                    <span className="matrix-label">Digest Pinning</span>
                    <strong className={`matrix-value ${image_digest ? "text-pass" : "text-fail"}`}>
                        {image_digest ? (
                            <><CheckCircleIcon size={14} /> Immutable Pinned</>
                        ) : (
                            <><XCircleIcon size={14} /> Tag Only</>
                        )}
                    </strong>
                </div>
            </div>

            {/* Structured Telemetry Table */}
            <div className="identity-telemetry-block">
                {/* Target Image & Digest */}
                <div className="identity-data-row">
                    <span className="row-field-name">Container Image Reference</span>
                    <div className="row-field-content">
                        <code className="code-token bold-token">{imageReference || identityData.image_reference}</code>
                    </div>
                </div>

                <div className="identity-data-row">
                    <span className="row-field-name">Immutable OCI Digest (SHA-256)</span>
                    <div className="row-field-content copyable-content">
                        {image_digest ? (
                            <>
                                <code className="code-token digest-token" title={image_digest}>
                                    {image_digest}
                                </code>
                                <button
                                    type="button"
                                    className="inline-copy-btn"
                                    onClick={() => handleCopy(image_digest, "digest")}
                                    title="Copy immutable image digest"
                                >
                                    <CopyIcon size={13} />
                                    <span>{copiedKey === "digest" ? "Copied" : "Copy"}</span>
                                </button>
                            </>
                        ) : (
                            <span className="text-warning-muted">Resolution Failed — Tag is mutable</span>
                        )}
                    </div>
                </div>

                {/* Source Repository */}
                <div className="identity-data-row">
                    <span className="row-field-name">Source Repository</span>
                    <div className="row-field-content">
                        {source_repository ? (
                            <div className="repo-link-wrap">
                                <a 
                                    href={source_repository} 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    className="external-repo-link"
                                >
                                    {source_repository}
                                </a>
                                {details?.repo_type && details.repo_type !== "unknown" && (
                                    <span className="repo-type-tag">{details.repo_type.toUpperCase()}</span>
                                )}
                            </div>
                        ) : (
                            <span className="badge-missing">null (Missing org.opencontainers.image.source)</span>
                        )}
                    </div>
                </div>

                {/* Claimed Git Commit */}
                <div className="identity-data-row">
                    <span className="row-field-name">Claimed Source Commit</span>
                    <div className="row-field-content copyable-content">
                        {claimed_source_commit ? (
                            <>
                                <code className="code-token commit-token" title={claimed_source_commit}>
                                    {claimed_source_commit}
                                </code>
                                <button
                                    type="button"
                                    className="inline-copy-btn"
                                    onClick={() => handleCopy(claimed_source_commit, "commit")}
                                    title="Copy full commit SHA"
                                >
                                    <CopyIcon size={13} />
                                    <span>{copiedKey === "commit" ? "Copied" : "Copy"}</span>
                                </button>
                                {details?.commit_url && (
                                    <a
                                        href={details.commit_url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="inline-link-btn"
                                    >
                                        View on Git
                                    </a>
                                )}
                            </>
                        ) : (
                            <span className="badge-missing">null (Missing org.opencontainers.image.revision)</span>
                        )}
                    </div>
                </div>

                {/* Verified Git Commit */}
                <div className="identity-data-row">
                    <span className="row-field-name">Verified Upstream Commit</span>
                    <div className="row-field-content">
                        {verified_source_commit ? (
                            <div className="verified-commit-wrap">
                                <code className="code-token verified-token">{verified_source_commit}</code>
                                {commit_matches ? (
                                    <span className="tag-match-pass">
                                        <CheckCircleIcon size={12} /> Matches Claimed
                                    </span>
                                ) : (
                                    <span className="tag-match-fail">
                                        <XCircleIcon size={12} /> Conflict Detected
                                    </span>
                                )}
                            </div>
                        ) : (
                            <span className="text-secondary-muted">
                                {identity_status === "MISSING" 
                                    ? "Not applicable (Missing metadata)"
                                    : identity_status === "CLAIMED"
                                    ? "Pending multi-factor attestation"
                                    : "Not independently verified"}
                            </span>
                        )}
                    </div>
                </div>

                {/* Verification Timestamp */}
                <div className="identity-data-row">
                    <span className="row-field-name">Verification Timestamp</span>
                    <div className="row-field-content">
                        <span className="timestamp-text">{verification_timestamp || "N/A"}</span>
                    </div>
                </div>
            </div>

            {/* Findings list if present */}
            {findings.length > 0 && (
                <div className="identity-findings-section">
                    <h4 className="findings-subheading">Identity &amp; Provenance Findings</h4>
                    <div className="identity-findings-list">
                        {findings.map((f, idx) => {
                            const isCrit = f.severity === "CRITICAL" || f.severity === "HIGH";
                            const isWarn = f.severity === "MEDIUM";
                            return (
                                <div key={idx} className={`identity-finding-item finding-${f.severity.toLowerCase()}`}>
                                    <span className="finding-icon">
                                        {isCrit ? <ShieldAlertIcon size={14} /> : isWarn ? <AlertTriangleIcon size={14} /> : <CheckCircleIcon size={14} />}
                                    </span>
                                    <div className="finding-body">
                                        <span className="finding-msg">{f.message}</span>
                                        {f.code && <span className="finding-code">[{f.code}]</span>}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {/* Collapsible Standard OCI Annotations Drawer */}
            <div className="oci-annotations-drawer">
                <button
                    type="button"
                    className="drawer-toggle-btn"
                    onClick={() => setShowAnnotations(!showAnnotations)}
                >
                    <span>Inspect Standard OCI Annotations ({metadata_completeness?.present_count ?? 0}/{metadata_completeness?.total_expected ?? 6} defined)</span>
                    <ChevronRightIcon size={16} className={`drawer-chevron ${showAnnotations ? "expanded" : ""}`} />
                </button>

                {showAnnotations && (
                    <div className="drawer-table-wrapper">
                        <table className="oci-annotations-table">
                            <thead>
                                <tr>
                                    <th>Standard OCI Key</th>
                                    <th>Extracted Value</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {[
                                    { key: "org.opencontainers.image.source", label: "Source Repository" },
                                    { key: "org.opencontainers.image.revision", label: "Source Git Revision" },
                                    { key: "org.opencontainers.image.version", label: "Image Version" },
                                    { key: "org.opencontainers.image.created", label: "Build Timestamp" },
                                    { key: "org.opencontainers.image.vendor", label: "Image Vendor" },
                                    { key: "org.opencontainers.image.documentation", label: "Documentation URL" }
                                ].map((item) => {
                                    const val = oci_annotations[item.key];
                                    const isPresent = val !== null && val !== undefined && val !== "";
                                    return (
                                        <tr key={item.key}>
                                            <td className="oci-key-cell">
                                                <code>{item.key}</code>
                                                <span className="oci-key-label">{item.label}</span>
                                            </td>
                                            <td className="oci-val-cell">
                                                {isPresent ? (
                                                    <code className="oci-val-code">{val}</code>
                                                ) : (
                                                    <span className="oci-null-val">null (Not Declared)</span>
                                                )}
                                            </td>
                                            <td>
                                                <span className={`oci-status-chip ${isPresent ? "chip-present" : "chip-missing"}`}>
                                                    {isPresent ? "Declared" : "Missing"}
                                                </span>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}

export default SourceIdentityCard;
