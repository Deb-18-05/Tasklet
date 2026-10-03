#include "unauprocdetect.h"

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <unordered_set>

namespace {

static std::string to_narrow(const std::wstring& w) {
    if (w.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";
    std::string s(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), size, nullptr, nullptr);
    return s;
}

void enable_ansi_terminal() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
}

void print_banner() {
    std::cout << "\033[1;36m";
    std::cout << "===============================================================================\n";
    std::cout << "  [ UNAUPROCDETECT // ADVANCED KERNEL PROCESS SENTINEL & DEFENSE ENGINE ]      \n";
    std::cout << "  Multi-Vector Unauthorized Execution Detection | Authenticode | Forensics     \n";
    std::cout << "===============================================================================\n";
    std::cout << "\033[0m";
}

void print_help() {
    std::cout << "\n\033[1mUSAGE:\033[0m\n";
    std::cout << "  unauprocdetect.exe [COMMAND] [OPTIONS]\n\n";
    std::cout << "\033[1mCOMMANDS:\033[0m\n";
    std::cout << "  --scan            Execute comprehensive audit on all running processes (Default)\n";
    std::cout << "  --monitor         Start continuous real-time kernel monitoring daemon\n";
    std::cout << "  --deep            Execute deep forensic audit including Authenticode & SHA-256\n";
    std::cout << "  --kill <pid>      Instantly terminate an unauthorized process by PID\n";
    std::cout << "  --auto-kill       Monitor continuously and auto-terminate CRITICAL threats\n";
    std::cout << "  --json            Output audit report in structured JSON format\n";
    std::cout << "  --whitelist <str> Whitelist a specific process name or executable directory\n";
    std::cout << "  --help, -h        Display this help information\n\n";
    std::cout << "\033[1mEXAMPLES:\033[0m\n";
    std::cout << "  unauprocdetect.exe --scan\n";
    std::cout << "  unauprocdetect.exe --deep\n";
    std::cout << "  unauprocdetect.exe --monitor\n";
    std::cout << "  unauprocdetect.exe --kill 4812\n";
    std::cout << "  unauprocdetect.exe --json > audit_report.json\n\n";
}

void print_audit_table(const std::vector<unau::ProcessAudit>& results, const unau::DetectionStats& stats) {
    std::cout << "\n\033[1;37mAUDIT SUMMARY:\033[0m\n";
    std::cout << "  Total Processes:  " << stats.total_scanned << "\n";
    std::cout << "  Unauthorized:     \033[1;" << (stats.unauthorized_count > 0 ? "31m" : "32m")
              << stats.unauthorized_count << "\033[0m\n";
    std::cout << "  Critical Alerts:  \033[1;" << (stats.critical_count > 0 ? "31m" : "37m")
              << stats.critical_count << "\033[0m\n";
    std::cout << "  High Risk:        \033[1;" << (stats.high_count > 0 ? "33m" : "37m")
              << stats.high_count << "\033[0m\n";
    std::cout << "  Whitelisted:      \033[36m" << stats.whitelisted_count << "\033[0m\n";
    std::cout << "  Scan Duration:    " << std::fixed << std::setprecision(1)
              << stats.scan_duration_ms << " ms\n\n";

    if (stats.unauthorized_count == 0) {
        std::cout << "\033[1;32m[+] DEFENSE SHIELD: NO UNAUTHORIZED PROCESSES DETECTED. SYSTEM STATE SECURE.\033[0m\n\n";
        return;
    }

    std::cout << "\033[1;31m[-] UNAUTHORIZED / SUSPICIOUS PROCESSES DETECTED:\033[0m\n";
    std::cout << "--------------------------------------------------------------------------------\n";
    std::cout << std::left
              << std::setw(8)  << "PID"
              << std::setw(24) << "PROCESS NAME"
              << std::setw(12) << "SEVERITY"
              << std::setw(8)  << "SCORE"
              << std::setw(12) << "AUTHENTICODE"
              << "PRIMARY REASON\n";
    std::cout << "--------------------------------------------------------------------------------\n";

    for (const auto& proc : results) {
        if (!proc.is_unauthorized && proc.findings.empty()) continue;

        std::string sevColor = "\033[32m";
        if (proc.max_severity == unau::Severity::Critical) sevColor = "\033[1;31m";
        else if (proc.max_severity == unau::Severity::High) sevColor = "\033[1;33m";
        else if (proc.max_severity == unau::Severity::Medium) sevColor = "\033[33m";
        else if (proc.max_severity == unau::Severity::Low) sevColor = "\033[36m";

        std::string primaryReason = "Unknown anomaly";
        if (!proc.findings.empty()) {
            primaryReason = to_narrow(proc.findings[0].description);
            if (primaryReason.length() > 36) {
                primaryReason = primaryReason.substr(0, 33) + "...";
            }
        }

        std::string narrowName = to_narrow(proc.name);
        if (narrowName.length() > 22) narrowName = narrowName.substr(0, 19) + "...";

        const wchar_t* wsev = unau::severity_to_string(proc.max_severity);
        std::string narrowSev = to_narrow(wsev ? wsev : L"SAFE");

        std::cout << std::left
                  << std::setw(8)  << proc.pid
                  << std::setw(24) << narrowName
                  << sevColor << std::setw(12) << narrowSev << "\033[0m"
                  << std::setw(8)  << proc.threat_score
                  << std::setw(12) << (proc.is_signed ? "Verified" : "Unsigned")
                  << primaryReason << "\n";

        // Print extra findings indented
        if (proc.findings.size() > 1) {
            for (size_t i = 1; i < proc.findings.size(); ++i) {
                std::string extraDesc = to_narrow(proc.findings[i].description);
                std::string ruleId = to_narrow(proc.findings[i].rule_id);
                std::cout << "         \033[90m↳ [" << ruleId << "] " << extraDesc << "\033[0m\n";
            }
        }
    }
    std::cout << "--------------------------------------------------------------------------------\n\n";
}

void run_monitor_daemon(bool auto_kill) {
    std::cout << "\033[1;36m[+] CONTINUOUS KERNEL PROCESS MONITOR ACTIVATED.\033[0m\n";
    if (auto_kill) {
        std::cout << "\033[1;31m[!] ACTIVE DEFENSE MODE: CRITICAL THREATS WILL BE AUTOMATICALLY TERMINATED!\033[0m\n";
    }
    std::cout << "Polling kernel process lifecycle events... (Press Ctrl+C to stop)\n\n";

    unau::UnauProcDetector detector;
    std::unordered_set<DWORD> known_pids;

    // Initial baseline
    auto initial_list = detector.scan_all(false);
    for (const auto& p : initial_list) {
        known_pids.insert(p.pid);
    }
    std::cout << "[+] Baseline established with " << known_pids.size() << " existing processes.\n";

    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        auto current_list = detector.scan_all(true);
        std::unordered_set<DWORD> current_pids;

        for (const auto& proc : current_list) {
            current_pids.insert(proc.pid);

            // New process detected
            if (known_pids.find(proc.pid) == known_pids.end()) {
                known_pids.insert(proc.pid);

                std::string nameStr = to_narrow(proc.name);
                if (proc.is_unauthorized) {
                    std::cout << "\033[1;31m[ALERT] UNAUTHORIZED PROCESS LAUNCHED: "
                              << nameStr << " (PID: " << proc.pid << ") [Threat Score: "
                              << proc.threat_score << "/100]\033[0m\n";

                    for (const auto& f : proc.findings) {
                        std::string desc = to_narrow(f.description);
                        std::string rule = to_narrow(f.rule_id);
                        std::cout << "        \033[33m- [" << rule << "] " << desc << "\033[0m\n";
                    }

                    if (auto_kill && proc.max_severity == unau::Severity::Critical) {
                        DWORD exitCode = 0;
                        if (detector.terminate_unauthorized(proc.pid, &exitCode)) {
                            std::cout << "\033[1;32m        [REMEDIATED] Terminated critical threat PID "
                                      << proc.pid << " successfully.\033[0m\n";
                        } else {
                            std::cout << "\033[1;31m        [FAIL] Unable to terminate PID "
                                      << proc.pid << " (insufficient privileges).\033[0m\n";
                        }
                    }
                } else {
                    std::cout << "\033[36m[KERNEL] Process started: " << nameStr
                              << " (PID: " << proc.pid << ") [Authorized]\033[0m\n";
                }
            }
        }

        // Clean up exited PIDs
        for (auto it = known_pids.begin(); it != known_pids.end();) {
            if (current_pids.find(*it) == current_pids.end()) {
                it = known_pids.erase(it);
            } else {
                ++it;
            }
        }
    }
}

} // namespace

int main(int argc, char* argv[]) {
    enable_ansi_terminal();

    bool json_mode = false;
    bool deep_mode = false;
    bool monitor_mode = false;
    bool auto_kill_mode = false;
    DWORD kill_pid = 0;
    std::wstring whitelist_entry;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_banner();
            print_help();
            return 0;
        } else if (arg == "--json") {
            json_mode = true;
        } else if (arg == "--deep") {
            deep_mode = true;
        } else if (arg == "--monitor") {
            monitor_mode = true;
        } else if (arg == "--auto-kill") {
            monitor_mode = true;
            auto_kill_mode = true;
        } else if (arg == "--kill" && i + 1 < argc) {
            kill_pid = static_cast<DWORD>(std::stoul(argv[++i]));
        } else if (arg == "--whitelist" && i + 1 < argc) {
            std::string val = argv[++i];
            whitelist_entry.assign(val.begin(), val.end());
        }
    }

    if (!json_mode) {
        print_banner();
    }

    unau::UnauProcDetector detector;

    if (!whitelist_entry.empty()) {
        detector.add_whitelist_name(whitelist_entry);
        detector.add_whitelist_path(whitelist_entry);
        std::wcout << L"[+] Added to temporary whitelist: " << whitelist_entry << L"\n";
    }

    if (kill_pid != 0) {
        std::cout << "[*] Attempting termination of PID " << kill_pid << "...\n";
        DWORD exitCode = 0;
        if (detector.terminate_unauthorized(kill_pid, &exitCode)) {
            std::cout << "\033[1;32m[+] Process PID " << kill_pid << " successfully terminated.\033[0m\n";
            return 0;
        } else {
            std::cerr << "\033[1;31m[-] Failed to terminate PID " << kill_pid
                      << ". Check PID existence or elevate to Administrator.\033[0m\n";
            return 1;
        }
    }

    if (monitor_mode) {
        run_monitor_daemon(auto_kill_mode);
        return 0;
    }

    // Standard scan mode
    auto results = detector.scan_all(deep_mode);
    auto stats = detector.get_last_stats();

    if (json_mode) {
        std::cout << detector.export_json(results, stats) << std::endl;
    } else {
        print_audit_table(results, stats);
    }

    return (stats.unauthorized_count > 0 ? 2 : 0);
}
