#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <cstdint>
#include <string>
#include <vector>

struct ProcessInfo {
    uint32_t pid = 0;
    uint32_t parent_pid = 0;
    uint64_t memory_bytes = 0;
    uint64_t cpu_time_100ns = 0;
    double cpu_percent = 0.0;
    std::string state;
    std::string name;
};

std::vector<ProcessInfo> enumerate_processes();
bool terminate_process(uint32_t pid);
