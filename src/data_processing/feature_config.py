"""
Feature Configuration - Tiered feature taxonomy for SSH brute-force detection.

Features are organized into priority tiers based on their discriminative power
for distinguishing normal SSH behavior from brute-force attacks.

References:
- Liu et al. (2008). Isolation Forest. IEEE ICDM.
- Javed & Paxson (2013). Detecting Stealthy SSH Brute-Forcing. ACM CCS.
- Sperotto et al. (2010). Flow-Based Intrusion Detection. IEEE.
"""

# Tier 1: CRITICAL features (highest discriminative power)
# These alone achieve >80% of total detection capability
CRITICAL_FEATURES = [
    'session_duration_mean',      # #1 importance (5.50%) - Attack sessions are very short
    'min_inter_attempt_time',     # #2 importance (3.86%) - Automated tools have near-zero gaps
    'mean_inter_attempt_time',    # #3 importance (2.61%) - Avg timing reveals automation
    'fail_rate',                  # Core brute-force indicator: fail/(fail+success)
]

# Tier 2: IMPORTANT features (significant contribution)
IMPORTANT_FEATURES = [
    'std_inter_attempt_time',     # #4 importance (1.64%) - Bots are regular, humans irregular
    'unique_ports',               # #5 importance (1.42%) - Rapid reconnection = many ports
    'connection_count',           # #6 importance (1.16%) - Raw volume indicator
    'fail_count',                 # Direct count of failed attempts
    'success_count',              # Normal users succeed; attackers rarely do
]

# Tier 3: USEFUL features (moderate contribution)
USEFUL_FEATURES = [
    'unique_usernames',           # Credential stuffing uses many usernames
    'invalid_user_count',         # Attackers guess non-existent usernames
    'invalid_user_ratio',         # Proportion of invalid user guesses
]

# Tier 4: SUPPORTING features (supplementary signal)
SUPPORTING_FEATURES = [
    'pam_failure_escalation',     # PAM "N more auth failures" events
    'max_retries_exceeded',       # PAM max retries exceeded
]

# Combined ordered list (all 14 features)
ALL_FEATURES = (
    CRITICAL_FEATURES +
    IMPORTANT_FEATURES +
    USEFUL_FEATURES +
    SUPPORTING_FEATURES
)

# Feature names as used in feature extractor (original order)
FEATURE_NAMES = [
    'fail_count',
    'success_count',
    'fail_rate',
    'unique_usernames',
    'invalid_user_count',
    'invalid_user_ratio',
    'connection_count',
    'mean_inter_attempt_time',
    'std_inter_attempt_time',
    'min_inter_attempt_time',
    'unique_ports',
    'pam_failure_escalation',
    'max_retries_exceeded',
    'session_duration_mean',
]

# Priority features for anomaly detection (top-performing subset)
ANOMALY_DETECTION_PRIORITY = (
    CRITICAL_FEATURES +
    IMPORTANT_FEATURES
)

# Feature groups for analysis
FEATURE_GROUPS = {
    'timing': ['mean_inter_attempt_time', 'std_inter_attempt_time',
               'min_inter_attempt_time', 'session_duration_mean'],
    'attempt': ['fail_count', 'success_count', 'fail_rate'],
    'identity': ['unique_usernames', 'invalid_user_count', 'invalid_user_ratio'],
    'connection': ['connection_count', 'unique_ports'],
    'escalation': ['pam_failure_escalation', 'max_retries_exceeded'],
}
