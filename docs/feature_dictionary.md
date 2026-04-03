# Feature Dictionary / Từ điển đặc trưng

## Overview
14 features are extracted per source IP per 5-minute sliding window.
All features are numeric (float64) and compatible with Isolation Forest, LOF, and One-Class SVM.

## Feature Definitions

### 1. fail_count
- **Type**: Integer (as float)
- **Description**: Number of "Failed password" events in the window
- **Range**: [0, ∞)
- **Normal behavior**: 0-2 (occasional typos)
- **Attack indicator**: >5 (brute-force attempts)
- **Rationale**: Core indicator of brute-force activity. Normal users rarely fail more than 2-3 times. Reference: Hellemons et al. (2012)

### 2. success_count
- **Type**: Integer (as float)
- **Description**: Number of "Accepted password" events in the window
- **Range**: [0, ∞)
- **Normal behavior**: 1-3 (legitimate logins)
- **Attack indicator**: 0 (attackers rarely succeed) or >10 (compromised credentials)
- **Rationale**: Normal users succeed; attackers rarely do

### 3. fail_rate
- **Type**: Float
- **Formula**: fail_count / (fail_count + success_count + ε)
- **Range**: [0, 1]
- **Normal behavior**: 0-0.3
- **Attack indicator**: >0.8 (almost all attempts fail)
- **Rationale**: Normalized metric independent of total volume

### 4. unique_usernames
- **Type**: Integer (as float)
- **Description**: Number of distinct usernames attempted in the window
- **Range**: [1, ∞)
- **Normal behavior**: 1 (same user)
- **Attack indicator**: >3 (credential stuffing, dictionary attack)
- **Rationale**: Credential stuffing attacks try many different usernames

### 5. invalid_user_count
- **Type**: Integer (as float)
- **Description**: Count of "Invalid user" sshd events
- **Range**: [0, ∞)
- **Normal behavior**: 0
- **Attack indicator**: >1 (guessing non-existent usernames)
- **Rationale**: Normal users never trigger "Invalid user" (they know their username)

### 6. invalid_user_ratio
- **Type**: Float
- **Formula**: invalid_user_count / (total_attempts + ε)
- **Range**: [0, 1]
- **Normal behavior**: 0
- **Attack indicator**: >0.3 (username enumeration)
- **Rationale**: High ratio indicates scanner/dictionary attack behavior

### 7. connection_count
- **Type**: Integer (as float)
- **Description**: Total SSH connection events in the window
- **Range**: [1, ∞)
- **Normal behavior**: 1-5
- **Attack indicator**: >10 (rapid connection cycling)
- **Rationale**: Raw volume indicator; attackers establish many connections

### 8. mean_inter_attempt_time
- **Type**: Float (seconds)
- **Description**: Average time between consecutive authentication attempts
- **Range**: [0, 300] (300 = window size default)
- **Normal behavior**: >30 seconds
- **Attack indicator**: <5 seconds (automated tools)
- **Rationale**: Automated attack tools have near-zero gaps. Reference: Javed & Paxson (2013)

### 9. std_inter_attempt_time
- **Type**: Float (seconds)
- **Description**: Standard deviation of inter-attempt intervals
- **Range**: [0, ∞)
- **Normal behavior**: >10 (human irregular timing)
- **Attack indicator**: <2 (bot-like regular timing)
- **Rationale**: Bots are regular; humans are irregular

### 10. min_inter_attempt_time
- **Type**: Float (seconds)
- **Description**: Minimum gap between any two consecutive attempts
- **Range**: [0, 300]
- **Normal behavior**: >10 seconds
- **Attack indicator**: <1 second (scripted rapid-fire)
- **Importance**: **HIGHEST** (ranked #2 in permutation importance)
- **Rationale**: Catches the fastest burst within the window

### 11. unique_ports
- **Type**: Integer (as float)
- **Description**: Number of distinct source ports used
- **Range**: [1, ∞)
- **Normal behavior**: 1-3
- **Attack indicator**: >10 (each new connection = new ephemeral port)
- **Rationale**: Rapid connection cycling creates many unique ports

### 12. pam_failure_escalation
- **Type**: Integer (as float)
- **Description**: Count of "PAM N more authentication failures" events
- **Range**: [0, ∞)
- **Normal behavior**: 0
- **Attack indicator**: >0 (indicates sustained attack within single connection)
- **Rationale**: PAM escalation only triggers when multiple failures occur rapidly within one session

### 13. max_retries_exceeded
- **Type**: Integer (as float)
- **Description**: Count of "PAM service(sshd) ignoring max retries" events
- **Range**: [0, ∞)
- **Normal behavior**: 0
- **Attack indicator**: >0 (attackers hitting PAM retry limit)
- **Rationale**: Only triggered when attacker exceeds MaxAuthTries in sshd_config

### 14. session_duration_mean
- **Type**: Float (seconds)
- **Description**: Average duration of SSH sessions (by PID grouping)
- **Range**: [0, ∞)
- **Normal behavior**: >1 second (successful interactive sessions can last minutes)
- **Attack indicator**: <0.5 seconds (fail-fast pattern)
- **Importance**: **HIGHEST** (ranked #1 in permutation importance)
- **Rationale**: Attack sessions are extremely short (connect, fail, disconnect)

## Feature Importance Ranking (Isolation Forest)

Based on permutation importance analysis on test set:

| Rank | Feature | Importance | Category |
|------|---------|-----------|----------|
| 1 | session_duration_mean | 5.50% | Session |
| 2 | min_inter_attempt_time | 3.86% | Timing |
| 3 | mean_inter_attempt_time | 2.61% | Timing |
| 4 | std_inter_attempt_time | 1.64% | Timing |
| 5 | unique_ports | 1.42% | Connection |
| 6 | connection_count | 1.16% | Connection |
| 7 | success_count | 0.44% | Attempt |
| 8 | unique_usernames | 0.05% | Attempt |

## Preprocessing
- **Scaler**: RobustScaler (median + IQR based, resistant to outliers)
- **Missing values**: Filled with 0
- **Infinite values**: Replaced with NaN, then filled with 0
