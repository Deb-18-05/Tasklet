#include "unauprocdetect.h"

#include <iostream>
#include <cassert>

namespace {

bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "[FAIL] " << message << '\n';
        return false;
    }
    return true;
}

} // namespace

int main() {
    bool passed = true;
    unau::UnauProcDetector detector;

    std::cout << "[*] Running Unauprocdetect unit tests...\n";

    // Test 1: Scan all processes
    auto processes = detector.scan_all(false);
    passed &= expect(!processes.empty(), "Process scan returned empty list");

    // Test 2: Current process should be in the list
    DWORD currentPid = GetCurrentProcessId();
    bool foundSelf = false;
    for (const auto& p : processes) {
        if (p.pid == currentPid) {
            foundSelf = true;
            break;
        }
    }
    passed &= expect(foundSelf, "Current process PID not discovered in scan");

    // Test 3: Whitelist testing
    detector.add_whitelist_name(L"custom_safe_app.exe");
    detector.add_whitelist_path(L"c:\\safe_folder\\");
    passed &= expect(
        detector.is_whitelisted(L"c:\\safe_folder\\app.exe", L"app.exe", L""),
        "Path whitelist lookup failed");
    passed &= expect(
        detector.is_whitelisted(L"c:\\random\\custom_safe_app.exe", L"custom_safe_app.exe", L""),
        "Name whitelist lookup failed");

    // Test 4: JSON export
    auto stats = detector.get_last_stats();
    std::string json = detector.export_json(processes, stats);
    passed &= expect(json.find("\"engine\": \"Unauprocdetect") != std::string::npos, "JSON output missing engine header");
    passed &= expect(json.find("\"detections\":") != std::string::npos, "JSON output missing detections array");

    if (passed) {
        std::cout << "[+] All Unauprocdetect tests PASSED!\n";
        return 0;
    } else {
        std::cerr << "[-] Some tests FAILED!\n";
        return 1;
    }
}
