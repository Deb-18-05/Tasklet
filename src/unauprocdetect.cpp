#include "unauprocdetect.h"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <bcrypt.h>
#include <winternl.h>

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <sstream>
#include <unordered_map>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace unau {

namespace {

std::wstring to_lower(std::wstring s) {
    for (wchar_t& c : s) {
        c = static_cast<wchar_t>(towlower(c));
    }
    return s;
}

std::wstring query_process_path(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"";

    wchar_t buffer[32768]{};
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    std::wstring result;
    if (QueryFullProcessImageNameW(h, 0, buffer, &size)) {
        result.assign(buffer, size);
    }
    CloseHandle(h);
    return result;
}

std::wstring query_process_user(HANDLE hProcess, bool& out_elevated, std::wstring& out_integrity) {
    out_elevated = false;
    out_integrity = L"Unknown";

    HANDLE token = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &token)) {
        return L"Unknown";
    }

    TOKEN_ELEVATION elevation{};
    DWORD ret = 0;
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &ret)) {
        out_elevated = (elevation.TokenIsElevated != 0);
    }

    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::wstring username = L"Unknown";

    if (needed > 0) {
        std::vector<BYTE> buffer(needed);
        if (GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) {
            auto* tu = reinterpret_cast<TOKEN_USER*>(buffer.data());
            wchar_t name[256]{};
            wchar_t domain[256]{};
            DWORD nameSize = 256;
            DWORD domainSize = 256;
            SID_NAME_USE use{};
            if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nameSize, domain, &domainSize, &use)) {
                username = std::wstring(domain) + L"\\" + std::wstring(name);
            }
        }
    }

    needed = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &needed);
    if (needed > 0) {
        std::vector<BYTE> ilBuffer(needed);
        if (GetTokenInformation(token, TokenIntegrityLevel, ilBuffer.data(), needed, &needed)) {
            auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(ilBuffer.data());
            DWORD rid = *GetSidSubAuthority(til->Label.Sid, static_cast<DWORD>(*GetSidSubAuthorityCount(til->Label.Sid) - 1));
            if (rid >= SECURITY_MANDATORY_SYSTEM_RID)
                out_integrity = L"System";
            else if (rid >= SECURITY_MANDATORY_HIGH_RID)
                out_integrity = L"High";
            else if (rid >= SECURITY_MANDATORY_MEDIUM_RID)
                out_integrity = L"Medium";
            else if (rid >= SECURITY_MANDATORY_LOW_RID)
                out_integrity = L"Low";
            else
                out_integrity = L"Untrusted";
        }
    }

    CloseHandle(token);
    return username;
}

// Function pointer for NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

std::wstring query_process_command_line(HANDLE hProcess) {
    static pfnNtQueryInformationProcess NtQueryInfoProcess = nullptr;
    static bool resolved = false;
    if (!resolved) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            NtQueryInfoProcess = reinterpret_cast<pfnNtQueryInformationProcess>(
                GetProcAddress(hNtdll, "NtQueryInformationProcess"));
        }
        resolved = true;
    }

    if (!NtQueryInfoProcess) return L"";

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryInfoProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0 || !pbi.PebBaseAddress) return L"";

    // Read PEB ProcessParameters
    SIZE_T bytesRead = 0;
    PEB peb{};
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) return L"";

    RTL_USER_PROCESS_PARAMETERS params{};
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead)) return L"";

    if (params.CommandLine.Length == 0 || params.CommandLine.Buffer == nullptr) return L"";

    USHORT len = params.CommandLine.Length / sizeof(wchar_t);
    if (len > 8192) len = 8192; // Clamp maximum length
    std::vector<wchar_t> cmdLineBuffer(len + 1, L'\0');
    if (ReadProcessMemory(hProcess, params.CommandLine.Buffer, cmdLineBuffer.data(), len * sizeof(wchar_t), &bytesRead)) {
        return std::wstring(cmdLineBuffer.data());
    }

    return L"";
}

} // namespace

const wchar_t* severity_to_string(Severity s) {
    switch (s) {
        case Severity::Critical: return L"CRITICAL";
        case Severity::High:     return L"HIGH";
        case Severity::Medium:   return L"MEDIUM";
        case Severity::Low:      return L"LOW";
        case Severity::Safe:
        default:                 return L"SAFE";
    }
}

UnauProcDetector::UnauProcDetector() {
    load_default_whitelist();
}

UnauProcDetector& get_detector() {
    static UnauProcDetector detector;
    return detector;
}

void UnauProcDetector::load_default_whitelist() {
    whitelisted_names_ = {
        L"system",
        L"registry",
        L"smss.exe",
        L"csrss.exe",
        L"wininit.exe",
        L"services.exe",
        L"lsass.exe",
        L"svchost.exe",
        L"fontdrvhost.exe",
        L"winlogon.exe",
        L"dwm.exe",
        L"explorer.exe",
        L"sihost.exe",
        L"taskhostw.exe",
        L"runtimebroker.exe",
        L"shellexperiencehost.exe",
        L"searchapp.exe",
        L"startmenuexperiencehost.exe",
        L"tasklet.exe",
        L"unauprocdetect.exe",
        L"tasklet_protocol_tests.exe",
        L"ctest.exe",
        L"cmake.exe",
        L"msbuild.exe",
        L"devenv.exe"
    };

    whitelisted_paths_ = {
        L"c:\\windows\\system32\\",
        L"c:\\windows\\syswow64\\",
        L"c:\\windows\\systemapps\\",
        L"c:\\windows\\",
        L"c:\\program files\\",
        L"c:\\program files (x86)\\"
    };
}

void UnauProcDetector::add_whitelist_name(const std::wstring& name) {
    whitelisted_names_.insert(to_lower(name));
}

void UnauProcDetector::add_whitelist_path(const std::wstring& path) {
    whitelisted_paths_.insert(to_lower(path));
}

void UnauProcDetector::add_whitelist_hash(const std::wstring& hash) {
    whitelisted_hashes_.insert(to_lower(hash));
}

bool UnauProcDetector::is_whitelisted(const std::wstring& path, const std::wstring& name, const std::wstring& hash) const {
    std::wstring lname = to_lower(name);
    std::wstring lpath = to_lower(path);
    std::wstring lhash = to_lower(hash);

    if (!lhash.empty() && whitelisted_hashes_.find(lhash) != whitelisted_hashes_.end()) {
        return true;
    }

    if (whitelisted_names_.find(lname) != whitelisted_names_.end()) {
        // If it's a critical system process, ensure it is in a valid system location
        if (is_known_system_binary(lname)) {
            return is_valid_system_location(lpath);
        }
        return true;
    }

    for (const auto& wp : whitelisted_paths_) {
        if (!lpath.empty() && lpath.rfind(wp, 0) == 0) {
            return true;
        }
    }

    return false;
}

bool UnauProcDetector::is_known_system_binary(const std::wstring& name) const {
    static const std::unordered_set<std::wstring> sys_binaries = {
        L"svchost.exe", L"csrss.exe", L"smss.exe", L"lsass.exe", L"services.exe",
        L"wininit.exe", L"winlogon.exe", L"explorer.exe", L"taskhostw.exe",
        L"runtimebroker.exe", L"sihost.exe", L"spoolsv.exe", L"dwm.exe",
        L"ctfmon.exe", L"conhost.exe"
    };
    return sys_binaries.find(to_lower(name)) != sys_binaries.end();
}

bool UnauProcDetector::is_valid_system_location(const std::wstring& path) const {
    if (path.empty()) return false;
    std::wstring lpath = to_lower(path);
    return (lpath.rfind(L"c:\\windows\\system32\\", 0) == 0 ||
            lpath.rfind(L"c:\\windows\\syswow64\\", 0) == 0 ||
            lpath.rfind(L"c:\\windows\\systemapps\\", 0) == 0 ||
            lpath == L"c:\\windows\\explorer.exe");
}

bool UnauProcDetector::is_suspicious_parent(const std::wstring& child_name, DWORD parent_pid, const std::wstring& parent_name) const {
    if (parent_pid == 0) return false;
    std::wstring lchild = to_lower(child_name);
    std::wstring lparent = to_lower(parent_name);

    // Office apps or Adobe spawning shells/scripts
    if (lparent == L"winword.exe" || lparent == L"excel.exe" || lparent == L"powerpnt.exe" ||
        lparent == L"outlook.exe" || lparent == L"acrord32.exe" || lparent == L"acrobat.exe") {
        if (lchild == L"powershell.exe" || lchild == L"cmd.exe" || lchild == L"wscript.exe" ||
            lchild == L"cscript.exe" || lchild == L"mshta.exe" || lchild == L"certutil.exe" ||
            lchild == L"bash.exe" || lchild == L"curl.exe") {
            return true;
        }
    }

    // svchost must only be spawned by services.exe
    if (lchild == L"svchost.exe" && !lparent.empty() && lparent != L"services.exe") {
        return true;
    }

    // lsass must only be spawned by wininit.exe
    if (lchild == L"lsass.exe" && !lparent.empty() && lparent != L"wininit.exe") {
        return true;
    }

    // Web servers or SQL spawning cmd / powershell
    if (lparent == L"w3wp.exe" || lparent == L"httpd.exe" || lparent == L"nginx.exe" || lparent == L"sqlservr.exe") {
        if (lchild == L"cmd.exe" || lchild == L"powershell.exe" || lchild == L"pwsh.exe") {
            return true;
        }
    }

    return false;
}

bool UnauProcDetector::has_suspicious_command_line(const std::wstring& cmd_line, std::wstring& out_reason) const {
    if (cmd_line.empty()) return false;
    std::wstring lcmd = to_lower(cmd_line);

    if (lcmd.find(L"-enc ") != std::wstring::npos || lcmd.find(L"-encodedcommand") != std::wstring::npos) {
        out_reason = L"Encoded PowerShell payload execution (-enc/-EncodedCommand)";
        return true;
    }
    if (lcmd.find(L"downloadstring") != std::wstring::npos || lcmd.find(L"invoke-webrequest") != std::wstring::npos) {
        out_reason = L"Web cradle / remote payload download (DownloadString / IWR)";
        return true;
    }
    if (lcmd.find(L"bypass") != std::wstring::npos && lcmd.find(L"executionpolicy") != std::wstring::npos) {
        out_reason = L"Execution policy bypass flag";
        return true;
    }
    if (lcmd.find(L"vssadmin delete shadows") != std::wstring::npos || lcmd.find(L"wmic shadowcopy delete") != std::wstring::npos) {
        out_reason = L"Ransomware behavior: shadow copy deletion attempt";
        return true;
    }
    if (lcmd.find(L"certutil -urlcache") != std::wstring::npos) {
        out_reason = L"Living-off-the-land download technique (certutil -urlcache)";
        return true;
    }

    return false;
}

bool UnauProcDetector::verify_authenticode(const std::wstring& path, std::wstring& out_signer, bool& out_is_ms) {
    out_signer = L"Unsigned / Untrusted";
    out_is_ms = false;
    if (path.empty()) return false;

    // Check catalog signature first for Windows system components
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        HCATADMIN hCatAdmin = NULL;
        if (CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
            DWORD hashSize = 32;
            BYTE hash[32]{};
            if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash, 0)) {
                CATALOG_INFO catInfo{};
                catInfo.cbStruct = sizeof(catInfo);
                HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, NULL);
                if (hCatInfo) {
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                    CryptCATAdminReleaseContext(hCatAdmin, 0);
                    CloseHandle(hFile);
                    out_signer = L"Microsoft Windows Catalog Signature";
                    out_is_ms = true;
                    return true;
                }
            }
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
        CloseHandle(hFile);
    }

    // Direct Authenticode verification via WinVerifyTrust
    WINTRUST_FILE_INFO fileData{};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wtData{};
    wtData.cbStruct = sizeof(WINTRUST_DATA);
    wtData.dwUIChoice = WTD_UI_NONE;
    wtData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtData.dwUnionChoice = WTD_CHOICE_FILE;
    wtData.dwStateAction = WTD_STATEACTION_VERIFY;
    wtData.pFile = &fileData;
    wtData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    LONG status = WinVerifyTrust(NULL, &action, &wtData);
    bool verified = (status == ERROR_SUCCESS);

    if (verified && wtData.hWVTStateData) {
        CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(wtData.hWVTStateData);
        if (provData) {
            CRYPT_PROVIDER_SGNR* provSigner = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
            if (provSigner && provSigner->pasCertChain && provSigner->csCertChain > 0) {
                PCCERT_CONTEXT cert = provSigner->pasCertChain[0].pCert;
                if (cert) {
                    wchar_t nameBuf[256]{};
                    if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nameBuf, 256)) {
                        out_signer = nameBuf;
                        std::wstring lSigner = to_lower(out_signer);
                        if (lSigner.find(L"microsoft") != std::wstring::npos) {
                            out_is_ms = true;
                        }
                    }
                }
            }
        }
    }

    // Cleanup state
    wtData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wtData);

    return verified;
}

std::wstring UnauProcDetector::compute_sha256(const std::wstring& path) {
    if (path.empty()) return L"";

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return L"";

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::wstring hashString;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        DWORD hashObjSize = 0, dataLen = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjSize), sizeof(DWORD), &dataLen, 0);
        std::vector<UCHAR> hashObj(hashObjSize);

        if (BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, nullptr, 0, 0) == 0) {
            BYTE buffer[16384];
            DWORD bytesRead = 0;
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
                BCryptHashData(hHash, buffer, bytesRead, 0);
            }

            BYTE hashVal[32]{};
            if (BCryptFinishHash(hHash, hashVal, sizeof(hashVal), 0) == 0) {
                std::wstringstream ss;
                for (int i = 0; i < 32; ++i) {
                    ss << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(hashVal[i]);
                }
                hashString = ss.str();
            }
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    CloseHandle(hFile);
    return hashString;
}

void UnauProcDetector::evaluate_heuristics(ProcessAudit& audit, bool deep_check) {
    audit.findings.clear();
    audit.threat_score = 0;
    audit.max_severity = Severity::Safe;

    std::wstring lname = to_lower(audit.name);
    std::wstring lpath = to_lower(audit.path);

    // Rule 1: Suspicious Path Execution
    if (lpath.find(L"\\temp\\") != std::wstring::npos ||
        lpath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos ||
        lpath.find(L"\\downloads\\") != std::wstring::npos ||
        lpath.find(L"\\appdata\\local\\packages\\") != std::wstring::npos ||
        lpath.find(L"\\$recycle.bin\\") != std::wstring::npos ||
        lpath.find(L"\\perflogs\\") != std::wstring::npos) {
        audit.findings.push_back({
            L"UNAU-001-TEMP-EXEC",
            Severity::High,
            L"Binary is executing from an unauthorized volatile staging path (Temp / Downloads / Recycle Bin)",
            35
        });
    }

    // Rule 2: Critical System Process Masquerading
    if (is_known_system_binary(lname)) {
        if (!is_valid_system_location(lpath) && !lpath.empty()) {
            audit.findings.push_back({
                L"UNAU-002-SYS32-MASQUERADE",
                Severity::Critical,
                L"Critical Windows core system process name running outside legitimate System32 directory (Process Masquerade)",
                55
            });
        }
    }

    // Rule 3: Typosquatting Mimicry
    static const std::unordered_set<std::wstring> typosquats = {
        L"svch0st.exe", L"scvhost.exe", L"lsasss.exe", L"csrsss.exe",
        L"taskhost.exe", L"explorerr.exe", L"conh0st.exe", L"rundll322.exe",
        L"taskmgrr.exe", L"winlog0n.exe", L"smsss.exe"
    };
    if (typosquats.find(lname) != typosquats.end()) {
        audit.findings.push_back({
            L"UNAU-003-TYPOSQUAT",
            Severity::Critical,
            L"Process name matches a known deceptive typosquat of a Windows system service",
            50
        });
    }

    // Rule 4: Digital Signature Check
    if (deep_check && !lpath.empty()) {
        audit.is_signed = verify_authenticode(audit.path, audit.signer_name, audit.is_microsoft);
        if (!audit.is_signed) {
            if (audit.is_elevated || audit.integrity == L"System" || audit.integrity == L"High") {
                audit.findings.push_back({
                    L"UNAU-004-UNSIGNED-PRIVILEGED",
                    Severity::High,
                    L"High-privilege executable lacks valid digital signature (Unsigned Administrative Binary)",
                    35
                });
            } else if (!is_whitelisted(audit.path, audit.name, audit.sha256_hash)) {
                audit.findings.push_back({
                    L"UNAU-004-UNSIGNED-BINARY",
                    Severity::Medium,
                    L"Binary lacks valid Authenticode digital signature or catalog verification",
                    20
                });
            }
        }
    }

    // Rule 5: Suspicious Command Line
    std::wstring cmdReason;
    if (has_suspicious_command_line(audit.command_line, cmdReason)) {
        audit.findings.push_back({
            L"UNAU-005-CMDLINE-INJECTION",
            Severity::High,
            cmdReason,
            40
        });
    }

    // Compute total score and determine max severity
    for (const auto& f : audit.findings) {
        audit.threat_score += f.score;
        if (static_cast<int>(f.severity) > static_cast<int>(audit.max_severity)) {
            audit.max_severity = f.severity;
        }
    }

    if (audit.threat_score > 100) audit.threat_score = 100;

    // Check if whitelisted
    if (is_whitelisted(audit.path, audit.name, audit.sha256_hash)) {
        audit.is_unauthorized = false;
        // Keep informational findings but lower score if whitelisted
        if (audit.threat_score > 25) audit.threat_score = 15;
        if (audit.max_severity > Severity::Low) audit.max_severity = Severity::Low;
    } else {
        audit.is_unauthorized = (audit.threat_score >= 40 || audit.max_severity >= Severity::High);
    }
}

ProcessAudit UnauProcDetector::audit_process(DWORD pid, bool deep_signature_check) {
    ProcessAudit audit{};
    audit.pid = pid;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );

    if (hProcess) {
        audit.path = query_process_path(pid);
        audit.command_line = query_process_command_line(hProcess);
        audit.user = query_process_user(hProcess, audit.is_elevated, audit.integrity);

        PROCESS_MEMORY_COUNTERS pmc{};
        pmc.cb = sizeof(pmc);
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            audit.memory_bytes = pmc.WorkingSetSize;
        }

        if (deep_signature_check && !audit.path.empty()) {
            audit.sha256_hash = compute_sha256(audit.path);
        }

        CloseHandle(hProcess);
    } else {
        audit.path = query_process_path(pid);
        audit.integrity = L"Protected";
    }

    // Extract filename from path if name is empty
    if (audit.name.empty() && !audit.path.empty()) {
        size_t last_slash = audit.path.find_last_of(L"\\/");
        if (last_slash != std::wstring::npos) {
            audit.name = audit.path.substr(last_slash + 1);
        }
    }

    evaluate_heuristics(audit, deep_signature_check);
    return audit;
}

std::vector<ProcessAudit> UnauProcDetector::scan_all(bool deep_signature_check) {
    auto startTime = std::chrono::high_resolution_clock::now();
    std::vector<ProcessAudit> results;
    std::unordered_map<DWORD, std::wstring> pid_to_name;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return results;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe)) {
        do {
            ProcessAudit audit{};
            audit.pid = pe.th32ProcessID;
            audit.parent_pid = pe.th32ParentProcessID;
            audit.name = pe.szExeFile;
            pid_to_name[audit.pid] = audit.name;
            results.push_back(std::move(audit));
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);

    // Deep audit each collected process
    DetectionStats stats{};
    stats.total_scanned = results.size();

    for (auto& p : results) {
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            p.pid
        );

        if (hProcess) {
            p.path = query_process_path(p.pid);
            p.command_line = query_process_command_line(hProcess);
            p.user = query_process_user(hProcess, p.is_elevated, p.integrity);

            PROCESS_MEMORY_COUNTERS pmc{};
            pmc.cb = sizeof(pmc);
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                p.memory_bytes = pmc.WorkingSetSize;
            }

            if (deep_signature_check && !p.path.empty()) {
                p.sha256_hash = compute_sha256(p.path);
            }

            CloseHandle(hProcess);
        } else {
            p.path = query_process_path(p.pid);
            p.integrity = (p.pid == 0 || p.pid == 4) ? L"System" : L"Restricted/Protected";
        }

        // Parent process analysis
        std::wstring parentName = L"";
        auto itParent = pid_to_name.find(p.parent_pid);
        if (itParent != pid_to_name.end()) {
            parentName = itParent->second;
        }

        if (is_suspicious_parent(p.name, p.parent_pid, parentName)) {
            p.findings.push_back({
                L"UNAU-006-SPAWN-ANOMALY",
                Severity::Critical,
                L"Anomalous parent-child spawn lineage: " + parentName + L" (PID " +
                    std::to_wstring(p.parent_pid) + L") spawned " + p.name,
                50
            });
        }

        evaluate_heuristics(p, deep_signature_check);

        // Update statistics
        if (p.is_unauthorized) {
            ++stats.unauthorized_count;
        }
        if (is_whitelisted(p.path, p.name, p.sha256_hash)) {
            ++stats.whitelisted_count;
        }

        switch (p.max_severity) {
            case Severity::Critical: ++stats.critical_count; break;
            case Severity::High:     ++stats.high_count; break;
            case Severity::Medium:   ++stats.medium_count; break;
            case Severity::Low:      ++stats.low_count; break;
            default: break;
        }
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    stats.scan_duration_ms = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    last_stats_ = stats;

    // Sort by threat score descending
    std::sort(results.begin(), results.end(), [](const ProcessAudit& a, const ProcessAudit& b) {
        if (a.is_unauthorized != b.is_unauthorized) return a.is_unauthorized > b.is_unauthorized;
        if (a.threat_score != b.threat_score) return a.threat_score > b.threat_score;
        return a.pid < b.pid;
    });

    return results;
}

bool UnauProcDetector::terminate_unauthorized(DWORD pid, DWORD* exit_code) {
    if (pid == 0 || pid == 4) return false; // Prevent killing System / Idle

    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) return false;

    BOOL ok = TerminateProcess(h, 9);
    if (ok && exit_code) {
        *exit_code = 9;
    }
    CloseHandle(h);
    return ok != FALSE;
}

size_t UnauProcDetector::auto_remediate_critical(std::vector<DWORD>& terminated_pids) {
    terminated_pids.clear();
    auto list = scan_all(false);
    for (const auto& proc : list) {
        if (proc.is_unauthorized && proc.max_severity == Severity::Critical) {
            if (terminate_unauthorized(proc.pid)) {
                terminated_pids.push_back(proc.pid);
            }
        }
    }
    return terminated_pids.size();
}

std::string UnauProcDetector::export_json(const std::vector<ProcessAudit>& results, const DetectionStats& stats) const {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"engine\": \"Unauprocdetect v2.0 // Kernel Process Sentinel\",\n";
    ss << "  \"timestamp_epoch\": " << time(nullptr) << ",\n";
    ss << "  \"stats\": {\n";
    ss << "    \"total_scanned\": " << stats.total_scanned << ",\n";
    ss << "    \"unauthorized_count\": " << stats.unauthorized_count << ",\n";
    ss << "    \"critical_count\": " << stats.critical_count << ",\n";
    ss << "    \"high_count\": " << stats.high_count << ",\n";
    ss << "    \"medium_count\": " << stats.medium_count << ",\n";
    ss << "    \"whitelisted_count\": " << stats.whitelisted_count << ",\n";
    ss << "    \"scan_duration_ms\": " << std::fixed << std::setprecision(2) << stats.scan_duration_ms << "\n";
    ss << "  },\n";
    ss << "  \"detections\": [\n";

    bool first = true;
    for (const auto& proc : results) {
        if (!proc.is_unauthorized && proc.findings.empty()) continue;

        if (!first) ss << ",\n";
        first = false;

        auto escape_str = [](const std::wstring& w) -> std::string {
            std::string s;
            for (wchar_t c : w) {
                if (c == L'\\') s += "\\\\";
                else if (c == L'\"') s += "\\\"";
                else if (c == L'\n') s += "\\n";
                else if (c == L'\r') s += "\\r";
                else if (c == L'\t') s += "\\t";
                else if (c < 128) s += static_cast<char>(c);
                else s += '?';
            }
            return s;
        };

        ss << "    {\n";
        ss << "      \"pid\": " << proc.pid << ",\n";
        ss << "      \"parent_pid\": " << proc.parent_pid << ",\n";
        ss << "      \"name\": \"" << escape_str(proc.name) << "\",\n";
        ss << "      \"path\": \"" << escape_str(proc.path) << "\",\n";
        ss << "      \"threat_score\": " << proc.threat_score << ",\n";
        ss << "      \"severity\": \"" << escape_str(severity_to_string(proc.max_severity)) << "\",\n";
        ss << "      \"is_unauthorized\": " << (proc.is_unauthorized ? "true" : "false") << ",\n";
        ss << "      \"is_signed\": " << (proc.is_signed ? "true" : "false") << ",\n";
        ss << "      \"signer\": \"" << escape_str(proc.signer_name) << "\",\n";
        ss << "      \"sha256\": \"" << escape_str(proc.sha256_hash) << "\",\n";
        ss << "      \"user\": \"" << escape_str(proc.user) << "\",\n";
        ss << "      \"integrity\": \"" << escape_str(proc.integrity) << "\",\n";
        ss << "      \"findings\": [\n";

        for (size_t i = 0; i < proc.findings.size(); ++i) {
            const auto& f = proc.findings[i];
            ss << "        {\n";
            ss << "          \"rule_id\": \"" << escape_str(f.rule_id) << "\",\n";
            ss << "          \"severity\": \"" << escape_str(severity_to_string(f.severity)) << "\",\n";
            ss << "          \"description\": \"" << escape_str(f.description) << "\",\n";
            ss << "          \"score\": " << f.score << "\n";
            ss << "        }" << (i + 1 < proc.findings.size() ? "," : "") << "\n";
        }
        ss << "      ]\n";
        ss << "    }";
    }
    ss << "\n  ]\n";
    ss << "}\n";

    return ss.str();
}

} // namespace unau
