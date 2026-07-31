package com.example.securityutilitysuite.enums;

/**
 * Lifecycle / comparison state of a tracked file's integrity check.
 */
public enum IntegrityStatus {
    /** Baseline hash captured, no verification run yet. */
    BASELINE_ONLY,
    /** Latest check's hash matches the baseline. */
    UNCHANGED,
    /** Latest check's hash differs from the baseline. */
    MODIFIED,
    /** File existed when the baseline was taken but is no longer found. */
    MISSING
}
