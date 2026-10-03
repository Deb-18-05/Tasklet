#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <chrono>

namespace unau {

enum class Severity {
    Safe = 0,
    Low,
    Medium,
    High,
    Critical
};

const wchar_t* severity_to_string(Severity s);

struct ThreatFinding {
    std::wstring rule_id;       // e.g. "UNAU-001-TEMP-EXEC"
    Severity severity;          // Critical, High, Medium, Low
    std::wstring description;   // Detailed forensic reason
    int score = 0;              // Weight contribution (0 - 60)
};

struct ProcessAudit {
    DWORD pid = 0;
    DWORD parent_pid = 0;
    std::wstring name;
    std::wstring path;
    std::wstring command_line;
    std::wstring user;
    std::wstring integrity;
    bool is_elevated = false;
    bool is_signed = false;
    bool is_microsoft = false;
    std::wstring signer_name;
    std::wstring sha256_hash;
    uint64_t memory_bytes = 0;
    double cpu_percent = 0.0;
    
    int threat_score = 0;       // 0 to 100
    Severity max_severity = Severity::Safe;
    bool is_unauthorized = false; // true if threat_score >= threshold or critical finding
    std::vector<ThreatFinding> findings;
};

struct DetectionStats {
    size_t total_scanned = 0;
    size_t unauthorized_count = 0;
    size_t critical_count = 0;
    size_t high_count = 0;
    size_t medium_count = 0;
    size_t low_count = 0;
    size_t whitelisted_count = 0;
    double scan_duration_ms = 0.0;
};

class UnauProcDetector {
public:
    UnauProcDetector();
    ~UnauProcDetector() = default;

    // Scan operations
    std::vector<ProcessAudit> scan_all(bool deep_signature_check = true);
    ProcessAudit audit_process(DWORD pid, bool deep_signature_check = true);

    // Whitelist management
    void add_whitelist_path(const std::wstring& path);
    void add_whitelist_name(const std::wstring& name);
    void add_whitelist_hash(const std::wstring& hash);
    bool is_whitelisted(const std::wstring& path, const std::wstring& name, const std::wstring& hash) const;
    void load_default_whitelist();

    // Enforcement & Remediation
    bool terminate_unauthorized(DWORD pid, DWORD* exit_code = nullptr);
    size_t auto_remediate_critical(std::vector<DWORD>& terminated_pids);

    // Heuristic & Verification helpers
    bool verify_authenticode(const std::wstring& path, std::wstring& out_signer, bool& out_is_ms);
    std::wstring compute_sha256(const std::wstring& path);
    
    // Reporting & Export
    std::string export_json(const std::vector<ProcessAudit>& results, const DetectionStats& stats) const;
    DetectionStats get_last_stats() const { return last_stats_; }

private:
    std::unordered_set<std::wstring> whitelisted_paths_;
    std::unordered_set<std::wstring> whitelisted_names_;
    std::unordered_set<std::wstring> whitelisted_hashes_;
    DetectionStats last_stats_;

    void evaluate_heuristics(ProcessAudit& audit, bool deep_check);
    bool is_known_system_binary(const std::wstring& name) const;
    bool is_valid_system_location(const std::wstring& path) const;
    bool is_suspicious_parent(const std::wstring& child_name, DWORD parent_pid, const std::wstring& parent_name) const;
    bool has_suspicious_command_line(const std::wstring& cmd_line, std::wstring& out_reason) const;
};

// Global singleton / convenience access
UnauProcDetector& get_detector();

} // namespace unau
