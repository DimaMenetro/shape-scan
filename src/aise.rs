//! Axiomatic Intent Scoring Engine (AISE)
//!
//! TEM Module 4 — Trust-Abuse & Intent Pattern Detection
//!
//! Detects hostile INTENT by measuring byte-level patterns associated
//! with dangerous operations — WITHOUT reading or interpreting the code
//! as language.
//!
//! The Semantic Firewall constraint is maintained: we scan for numeric
//! byte sequences, not "code meaning." The engine outputs only numeric
//! scores and categorical flags.

use std::io;
use std::path::Path;

// ============================================================
// Anomaly flags
// ============================================================

pub const INTENT_NONE: u32 = 0x0000;
pub const INTENT_SHELL_EXECUTION: u32 = 0x0001;
pub const INTENT_CODE_EVALUATION: u32 = 0x0002;
pub const INTENT_DATA_DECODING: u32 = 0x0004;
pub const INTENT_NETWORK_COMMS: u32 = 0x0008;
pub const INTENT_FILE_MANIPULATION: u32 = 0x0010;
pub const INTENT_PROCESS_CONTROL: u32 = 0x0020;
pub const INTENT_CREDENTIAL_ACCESS: u32 = 0x0040;
pub const INTENT_OBFUSCATION: u32 = 0x0080;
pub const INTENT_PERSISTENCE: u32 = 0x0100;
pub const INTENT_INFO_GATHERING: u32 = 0x0200;
pub const INTENT_BACKDOOR_PATTERN: u32 = 0x0400;
pub const INTENT_DROPPER_PATTERN: u32 = 0x0800;
pub const INTENT_WEBSHELL_PATTERN: u32 = 0x1000;

// ============================================================
// Output type — strictly numeric
// ============================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct IntentProfile {
    pub file_size: usize,

    // Per-category scores (0.0-1.0 each)
    pub shell_execution_score: f64,
    pub code_evaluation_score: f64,
    pub data_decoding_score: f64,
    pub network_communication_score: f64,
    pub filesystem_manipulation_score: f64,
    pub process_control_score: f64,
    pub credential_access_score: f64,
    pub obfuscation_indicator_score: f64,
    pub persistence_mechanism_score: f64,
    pub information_gathering_score: f64,

    // Aggregate
    pub composite_intent_score: f64,
    pub intent_vector_count: usize,
    pub max_single_vector: f64,

    // Pattern density
    pub total_pattern_hits: usize,
    pub pattern_density: f64, // hits per KB
    pub unique_categories: usize,

    // Co-occurrence
    pub shell_plus_decode: bool,
    pub network_plus_filesystem: bool,
    pub eval_plus_obfuscation: bool,

    // Verdict
    pub intent_anomaly: bool,
    pub anomaly_flags: u32,
}

// ============================================================
// Category indices
// ============================================================

const CAT_SHELL: usize = 0;
const CAT_EVAL: usize = 1;
const CAT_DECODE: usize = 2;
const CAT_NETWORK: usize = 3;
const CAT_FILESYSTEM: usize = 4;
const CAT_PROCESS: usize = 5;
const CAT_CREDENTIAL: usize = 6;
const CAT_OBFUSCATION: usize = 7;
const CAT_PERSISTENCE: usize = 8;
const CAT_INFO_GATHER: usize = 9;
const NUM_CATEGORIES: usize = 10;

// Category weights for composite scoring
const CATEGORY_WEIGHTS: [f64; NUM_CATEGORIES] = [
    1.0, // CAT_SHELL — highest weight
    0.9, // CAT_EVAL
    0.6, // CAT_DECODE
    0.7, // CAT_NETWORK
    0.5, // CAT_FILESYSTEM
    0.9, // CAT_PROCESS
    0.9, // CAT_CREDENTIAL
    0.5, // CAT_OBFUSCATION
    0.8, // CAT_PERSISTENCE
    0.4, // CAT_INFO_GATHER
];

// ============================================================
// Signature database
// ============================================================

struct Signature {
    pattern: &'static [u8],
    category: usize,
    weight: f64,
}

// PHP/Script signatures
const SCRIPT_SIGNATURES: &[Signature] = &[
    // Shell execution
    Signature {
        pattern: b"shell_exec",
        category: CAT_SHELL,
        weight: 0.8,
    },
    Signature {
        pattern: b"system(",
        category: CAT_SHELL,
        weight: 0.7,
    },
    Signature {
        pattern: b"exec(",
        category: CAT_SHELL,
        weight: 0.6,
    },
    Signature {
        pattern: b"passthru(",
        category: CAT_SHELL,
        weight: 0.8,
    },
    Signature {
        pattern: b"popen(",
        category: CAT_SHELL,
        weight: 0.7,
    },
    Signature {
        pattern: b"proc_open",
        category: CAT_SHELL,
        weight: 0.9,
    },
    Signature {
        pattern: b"pcntl_exec",
        category: CAT_SHELL,
        weight: 0.9,
    },
    // Code evaluation
    Signature {
        pattern: b"eval(",
        category: CAT_EVAL,
        weight: 0.9,
    },
    Signature {
        pattern: b"assert(",
        category: CAT_EVAL,
        weight: 0.6,
    },
    Signature {
        pattern: b"preg_replace",
        category: CAT_EVAL,
        weight: 0.3,
    },
    Signature {
        pattern: b"create_function",
        category: CAT_EVAL,
        weight: 0.8,
    },
    Signature {
        pattern: b"call_user_func",
        category: CAT_EVAL,
        weight: 0.5,
    },
    Signature {
        pattern: b"ReflectionFunction",
        category: CAT_EVAL,
        weight: 0.7,
    },
    // Data decoding
    Signature {
        pattern: b"base64_decode",
        category: CAT_DECODE,
        weight: 0.7,
    },
    Signature {
        pattern: b"gzinflate",
        category: CAT_DECODE,
        weight: 0.8,
    },
    Signature {
        pattern: b"gzuncompress",
        category: CAT_DECODE,
        weight: 0.8,
    },
    Signature {
        pattern: b"gzdecode",
        category: CAT_DECODE,
        weight: 0.7,
    },
    Signature {
        pattern: b"str_rot13",
        category: CAT_DECODE,
        weight: 0.6,
    },
    Signature {
        pattern: b"convert_uudecode",
        category: CAT_DECODE,
        weight: 0.7,
    },
    Signature {
        pattern: b"rawurldecode",
        category: CAT_DECODE,
        weight: 0.3,
    },
    // Network
    Signature {
        pattern: b"fsockopen",
        category: CAT_NETWORK,
        weight: 0.8,
    },
    Signature {
        pattern: b"curl_exec",
        category: CAT_NETWORK,
        weight: 0.6,
    },
    Signature {
        pattern: b"curl_init",
        category: CAT_NETWORK,
        weight: 0.5,
    },
    Signature {
        pattern: b"file_get_contents",
        category: CAT_NETWORK,
        weight: 0.3,
    },
    Signature {
        pattern: b"stream_socket",
        category: CAT_NETWORK,
        weight: 0.7,
    },
    Signature {
        pattern: b"socket_create",
        category: CAT_NETWORK,
        weight: 0.8,
    },
    Signature {
        pattern: b"ftp_connect",
        category: CAT_NETWORK,
        weight: 0.6,
    },
    // Filesystem
    Signature {
        pattern: b"fwrite(",
        category: CAT_FILESYSTEM,
        weight: 0.4,
    },
    Signature {
        pattern: b"file_put_contents",
        category: CAT_FILESYSTEM,
        weight: 0.5,
    },
    Signature {
        pattern: b"chmod(",
        category: CAT_FILESYSTEM,
        weight: 0.6,
    },
    Signature {
        pattern: b"unlink(",
        category: CAT_FILESYSTEM,
        weight: 0.5,
    },
    Signature {
        pattern: b"rmdir(",
        category: CAT_FILESYSTEM,
        weight: 0.4,
    },
    Signature {
        pattern: b"rename(",
        category: CAT_FILESYSTEM,
        weight: 0.3,
    },
    Signature {
        pattern: b"copy(",
        category: CAT_FILESYSTEM,
        weight: 0.3,
    },
    Signature {
        pattern: b"mkdir(",
        category: CAT_FILESYSTEM,
        weight: 0.2,
    },
    // Process control
    Signature {
        pattern: b"proc_open",
        category: CAT_PROCESS,
        weight: 0.9,
    },
    Signature {
        pattern: b"proc_get_status",
        category: CAT_PROCESS,
        weight: 0.7,
    },
    Signature {
        pattern: b"pcntl_fork",
        category: CAT_PROCESS,
        weight: 0.8,
    },
    Signature {
        pattern: b"pcntl_exec",
        category: CAT_PROCESS,
        weight: 0.9,
    },
    // Credential access
    Signature {
        pattern: b"ssh2_connect",
        category: CAT_CREDENTIAL,
        weight: 0.9,
    },
    Signature {
        pattern: b"ssh2_auth",
        category: CAT_CREDENTIAL,
        weight: 0.9,
    },
    Signature {
        pattern: b"authorized_keys",
        category: CAT_CREDENTIAL,
        weight: 0.9,
    },
    Signature {
        pattern: b"id_rsa",
        category: CAT_CREDENTIAL,
        weight: 0.8,
    },
    Signature {
        pattern: b"/etc/passwd",
        category: CAT_CREDENTIAL,
        weight: 0.7,
    },
    Signature {
        pattern: b"/etc/shadow",
        category: CAT_CREDENTIAL,
        weight: 0.9,
    },
    Signature {
        pattern: b"mysql_connect",
        category: CAT_CREDENTIAL,
        weight: 0.5,
    },
    // Obfuscation
    Signature {
        pattern: b"chr(",
        category: CAT_OBFUSCATION,
        weight: 0.3,
    },
    Signature {
        pattern: b"pack(",
        category: CAT_OBFUSCATION,
        weight: 0.5,
    },
    Signature {
        pattern: b"hex2bin",
        category: CAT_OBFUSCATION,
        weight: 0.6,
    },
    Signature {
        pattern: b"str_replace",
        category: CAT_OBFUSCATION,
        weight: 0.1,
    },
    // Persistence
    Signature {
        pattern: b"crontab",
        category: CAT_PERSISTENCE,
        weight: 0.8,
    },
    Signature {
        pattern: b"@reboot",
        category: CAT_PERSISTENCE,
        weight: 0.9,
    },
    Signature {
        pattern: b"systemctl",
        category: CAT_PERSISTENCE,
        weight: 0.7,
    },
    Signature {
        pattern: b".bashrc",
        category: CAT_PERSISTENCE,
        weight: 0.6,
    },
    Signature {
        pattern: b".profile",
        category: CAT_PERSISTENCE,
        weight: 0.5,
    },
    // Info gathering
    Signature {
        pattern: b"phpinfo",
        category: CAT_INFO_GATHER,
        weight: 0.5,
    },
    Signature {
        pattern: b"whoami",
        category: CAT_INFO_GATHER,
        weight: 0.7,
    },
    Signature {
        pattern: b"uname -a",
        category: CAT_INFO_GATHER,
        weight: 0.7,
    },
    Signature {
        pattern: b"ifconfig",
        category: CAT_INFO_GATHER,
        weight: 0.5,
    },
    Signature {
        pattern: b"ip addr",
        category: CAT_INFO_GATHER,
        weight: 0.5,
    },
    Signature {
        pattern: b"cat /etc",
        category: CAT_INFO_GATHER,
        weight: 0.6,
    },
    Signature {
        pattern: b"getenv(",
        category: CAT_INFO_GATHER,
        weight: 0.3,
    },
];

// PE/Binary signatures
const BINARY_SIGNATURES: &[Signature] = &[
    // Shell execution
    Signature {
        pattern: b"WinExec",
        category: CAT_SHELL,
        weight: 0.7,
    },
    Signature {
        pattern: b"ShellExecute",
        category: CAT_SHELL,
        weight: 0.5,
    },
    Signature {
        pattern: b"CreateProcess",
        category: CAT_SHELL,
        weight: 0.5,
    },
    Signature {
        pattern: b"cmd.exe",
        category: CAT_SHELL,
        weight: 0.6,
    },
    Signature {
        pattern: b"powershell",
        category: CAT_SHELL,
        weight: 0.7,
    },
    Signature {
        pattern: b"wscript",
        category: CAT_SHELL,
        weight: 0.6,
    },
    Signature {
        pattern: b"cscript",
        category: CAT_SHELL,
        weight: 0.6,
    },
    Signature {
        pattern: b"mshta",
        category: CAT_SHELL,
        weight: 0.8,
    },
    // Code injection
    Signature {
        pattern: b"VirtualAllocEx",
        category: CAT_EVAL,
        weight: 0.9,
    },
    Signature {
        pattern: b"WriteProcessMemory",
        category: CAT_EVAL,
        weight: 0.9,
    },
    Signature {
        pattern: b"CreateRemoteThread",
        category: CAT_EVAL,
        weight: 0.9,
    },
    Signature {
        pattern: b"NtCreateThreadEx",
        category: CAT_EVAL,
        weight: 0.9,
    },
    Signature {
        pattern: b"QueueUserAPC",
        category: CAT_EVAL,
        weight: 0.8,
    },
    Signature {
        pattern: b"SetWindowsHookEx",
        category: CAT_EVAL,
        weight: 0.7,
    },
    // Network
    Signature {
        pattern: b"WSAStartup",
        category: CAT_NETWORK,
        weight: 0.4,
    },
    Signature {
        pattern: b"InternetOpen",
        category: CAT_NETWORK,
        weight: 0.5,
    },
    Signature {
        pattern: b"HttpSendRequest",
        category: CAT_NETWORK,
        weight: 0.6,
    },
    Signature {
        pattern: b"URLDownloadToFile",
        category: CAT_NETWORK,
        weight: 0.8,
    },
    // Filesystem
    Signature {
        pattern: b"DeleteFile",
        category: CAT_FILESYSTEM,
        weight: 0.4,
    },
    Signature {
        pattern: b"MoveFile",
        category: CAT_FILESYSTEM,
        weight: 0.3,
    },
    Signature {
        pattern: b"CopyFile",
        category: CAT_FILESYSTEM,
        weight: 0.3,
    },
    // Credential / privilege
    Signature {
        pattern: b"AdjustTokenPrivileges",
        category: CAT_CREDENTIAL,
        weight: 0.8,
    },
    Signature {
        pattern: b"LookupPrivilegeValue",
        category: CAT_CREDENTIAL,
        weight: 0.7,
    },
    Signature {
        pattern: b"LogonUser",
        category: CAT_CREDENTIAL,
        weight: 0.7,
    },
    Signature {
        pattern: b"SeDebugPrivilege",
        category: CAT_CREDENTIAL,
        weight: 0.9,
    },
    // Persistence
    Signature {
        pattern: b"RegSetValueEx",
        category: CAT_PERSISTENCE,
        weight: 0.6,
    },
    Signature {
        pattern: b"CurrentVersion\\Run",
        category: CAT_PERSISTENCE,
        weight: 0.9,
    },
    Signature {
        pattern: b"CreateService",
        category: CAT_PERSISTENCE,
        weight: 0.7,
    },
    Signature {
        pattern: b"schtasks",
        category: CAT_PERSISTENCE,
        weight: 0.8,
    },
    // Anti-analysis
    Signature {
        pattern: b"IsDebuggerPresent",
        category: CAT_OBFUSCATION,
        weight: 0.7,
    },
    Signature {
        pattern: b"CheckRemoteDebuggerPresent",
        category: CAT_OBFUSCATION,
        weight: 0.8,
    },
    Signature {
        pattern: b"NtQueryInformationProcess",
        category: CAT_OBFUSCATION,
        weight: 0.6,
    },
    Signature {
        pattern: b"GetTickCount",
        category: CAT_OBFUSCATION,
        weight: 0.3,
    },
    // Info gathering
    Signature {
        pattern: b"GetComputerName",
        category: CAT_INFO_GATHER,
        weight: 0.3,
    },
    Signature {
        pattern: b"GetUserName",
        category: CAT_INFO_GATHER,
        weight: 0.3,
    },
    Signature {
        pattern: b"GetSystemInfo",
        category: CAT_INFO_GATHER,
        weight: 0.3,
    },
    Signature {
        pattern: b"GetVersionEx",
        category: CAT_INFO_GATHER,
        weight: 0.2,
    },
];

// ============================================================
// Core engine
// ============================================================

/// Count occurrences of a byte pattern in data using a simple scan.
fn count_pattern(data: &[u8], pattern: &[u8]) -> usize {
    if pattern.is_empty() || data.len() < pattern.len() {
        return 0;
    }
    data.windows(pattern.len())
        .filter(|w| *w == pattern)
        .count()
}

/// Count all intent signatures and return per-category (count, weight) pairs.
fn count_signatures(data: &[u8], is_binary: bool) -> Vec<Vec<(usize, f64)>> {
    let mut results: Vec<Vec<(usize, f64)>> = (0..NUM_CATEGORIES).map(|_| Vec::new()).collect();

    // Always check both signature sets (mixed content)
    let sigs: Vec<&Signature> = if is_binary {
        BINARY_SIGNATURES.iter().collect()
    } else {
        SCRIPT_SIGNATURES
            .iter()
            .chain(BINARY_SIGNATURES.iter())
            .collect()
    };

    for sig in sigs {
        let count = count_pattern(data, sig.pattern);
        if count > 0 {
            results[sig.category].push((count, sig.weight));
        }
    }

    results
}

/// Compute per-category scores from signature match results.
fn compute_category_scores(
    results: &[Vec<(usize, f64)>],
    file_size: usize,
) -> [f64; NUM_CATEGORIES] {
    let mut scores = [0.0_f64; NUM_CATEGORIES];
    let size_factor = (file_size.max(1) as f64 / 1024.0).log2().max(1.0);

    for (cat, hits) in results.iter().enumerate() {
        if hits.is_empty() {
            continue;
        }
        let weighted_sum: f64 = hits.iter().map(|(c, w)| *c as f64 * w).sum();
        scores[cat] = (weighted_sum / (size_factor * 2.0)).min(1.0);
    }

    scores
}

// ============================================================
// Main analysis function
// ============================================================

/// Perform AISE analysis on raw bytes.
pub fn analyze_bytes(data: &[u8]) -> IntentProfile {
    let file_size = data.len();
    let is_binary = data.starts_with(b"MZ") || data.starts_with(b"\x7fELF");

    let results = count_signatures(data, is_binary);
    let scores = compute_category_scores(&results, file_size);

    // Co-occurrence detection
    let has_shell = !results[CAT_SHELL].is_empty();
    let has_decode = !results[CAT_DECODE].is_empty();
    let has_network = !results[CAT_NETWORK].is_empty();
    let has_filesystem = !results[CAT_FILESYSTEM].is_empty();
    let has_eval = !results[CAT_EVAL].is_empty();
    let has_obfuscation = !results[CAT_OBFUSCATION].is_empty();

    let shell_plus_decode = has_shell && has_decode;
    let network_plus_filesystem = has_network && has_filesystem;
    let eval_plus_obfuscation = has_eval && has_obfuscation;

    // Total pattern hits
    let total_hits: usize = results.iter().flat_map(|v| v.iter()).map(|(c, _)| c).sum();
    let pattern_density = (total_hits as f64 / file_size.max(1) as f64) * 1024.0;

    // Non-zero categories
    let unique_cats = scores.iter().filter(|&&s| s > 0.0).count();
    let intent_vector_count = unique_cats;

    // Composite intent score
    let weighted_scores: Vec<f64> = scores
        .iter()
        .enumerate()
        .map(|(i, &s)| s * CATEGORY_WEIGHTS[i])
        .collect();

    let mut composite = if intent_vector_count > 0 {
        weighted_scores.iter().sum::<f64>() / NUM_CATEGORIES as f64
    } else {
        0.0
    };

    // Co-occurrence amplifiers
    if shell_plus_decode {
        composite = (composite + 0.3).min(1.0);
    }
    if network_plus_filesystem {
        composite = (composite + 0.2).min(1.0);
    }
    if eval_plus_obfuscation {
        composite = (composite + 0.25).min(1.0);
    }

    // Multi-vector amplifier
    if unique_cats >= 5 {
        composite = (composite + 0.15).min(1.0);
    } else if unique_cats >= 4 {
        composite = (composite + 0.1).min(1.0);
    }

    let max_single = scores.iter().cloned().fold(0.0_f64, f64::max);

    // Anomaly flags
    let mut anomaly_flags: u32 = INTENT_NONE;

    if scores[CAT_SHELL] > 0.3 {
        anomaly_flags |= INTENT_SHELL_EXECUTION;
    }
    if scores[CAT_EVAL] > 0.3 {
        anomaly_flags |= INTENT_CODE_EVALUATION;
    }
    if scores[CAT_DECODE] > 0.3 {
        anomaly_flags |= INTENT_DATA_DECODING;
    }
    if scores[CAT_NETWORK] > 0.3 {
        anomaly_flags |= INTENT_NETWORK_COMMS;
    }
    if scores[CAT_FILESYSTEM] > 0.3 {
        anomaly_flags |= INTENT_FILE_MANIPULATION;
    }
    if scores[CAT_PROCESS] > 0.3 {
        anomaly_flags |= INTENT_PROCESS_CONTROL;
    }
    if scores[CAT_CREDENTIAL] > 0.3 {
        anomaly_flags |= INTENT_CREDENTIAL_ACCESS;
    }
    if scores[CAT_OBFUSCATION] > 0.3 {
        anomaly_flags |= INTENT_OBFUSCATION;
    }
    if scores[CAT_PERSISTENCE] > 0.3 {
        anomaly_flags |= INTENT_PERSISTENCE;
    }
    if scores[CAT_INFO_GATHER] > 0.3 {
        anomaly_flags |= INTENT_INFO_GATHERING;
    }
    if shell_plus_decode {
        anomaly_flags |= INTENT_BACKDOOR_PATTERN;
    }
    if network_plus_filesystem {
        anomaly_flags |= INTENT_DROPPER_PATTERN;
    }
    if eval_plus_obfuscation {
        anomaly_flags |= INTENT_WEBSHELL_PATTERN;
    }

    let intent_anomaly = anomaly_flags != INTENT_NONE;

    IntentProfile {
        file_size,
        shell_execution_score: scores[CAT_SHELL],
        code_evaluation_score: scores[CAT_EVAL],
        data_decoding_score: scores[CAT_DECODE],
        network_communication_score: scores[CAT_NETWORK],
        filesystem_manipulation_score: scores[CAT_FILESYSTEM],
        process_control_score: scores[CAT_PROCESS],
        credential_access_score: scores[CAT_CREDENTIAL],
        obfuscation_indicator_score: scores[CAT_OBFUSCATION],
        persistence_mechanism_score: scores[CAT_PERSISTENCE],
        information_gathering_score: scores[CAT_INFO_GATHER],
        composite_intent_score: composite.min(1.0),
        intent_vector_count,
        max_single_vector: max_single,
        total_pattern_hits: total_hits,
        pattern_density,
        unique_categories: unique_cats,
        shell_plus_decode,
        network_plus_filesystem,
        eval_plus_obfuscation,
        intent_anomaly,
        anomaly_flags,
    }
}

/// Perform AISE analysis on a file at the given path.
pub fn analyze(path: &Path) -> io::Result<IntentProfile> {
    let data = std::fs::read(path)?;
    Ok(analyze_bytes(&data))
}
