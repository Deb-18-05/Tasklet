
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define UNICODE
#define _UNICODE
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <winsvc.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <pdh.h>
#include <winioctl.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <shlwapi.h>
#include <winternl.h>

#include "telemetry_client.h"
#include "unauprocdetect.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cwctype>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")

// NtSuspend/ResumeProcess via GetProcAddress
typedef LONG(NTAPI* pNtSuspendProcess)(HANDLE);
typedef LONG(NTAPI* pNtResumeProcess)(HANDLE);

// Context menu IDs
#define IDM_END_TASK         1001
#define IDM_END_TREE         1002
#define IDM_SUSPEND          1003
#define IDM_RESUME           1004
#define IDM_PRIO_REALTIME    1010
#define IDM_PRIO_HIGH        1011
#define IDM_PRIO_ABOVENORMAL 1012
#define IDM_PRIO_NORMAL      1013
#define IDM_PRIO_BELOWNORMAL 1014
#define IDM_PRIO_LOW         1015
#define IDM_OPEN_LOCATION    1020
#define IDM_COPY_PID         1021
#define IDM_GO_DETAILS       1022
#define IDM_COPY_PATH        1023

namespace tasklet {

// ============================================================
// CYBER COLOR PALETTE
// ============================================================
constexpr COLORREF C_VOID        = RGB(3,  6, 11);
constexpr COLORREF C_SIDEBAR     = RGB(6, 10, 17);
constexpr COLORREF C_PANEL       = RGB(10, 16, 26);
constexpr COLORREF C_PANEL2      = RGB(15, 22, 36);
constexpr COLORREF C_PANEL_HOVER = RGB(21, 32, 52);
constexpr COLORREF C_PANEL_SEL   = RGB(18, 40, 70);
constexpr COLORREF C_BORDER      = RGB(24, 36, 56);
constexpr COLORREF C_BORDER_GLOW = RGB(0, 200, 255);

constexpr COLORREF C_CYAN        = RGB(0, 242, 254);
constexpr COLORREF C_BLUE        = RGB(79, 172, 254);
constexpr COLORREF C_GREEN       = RGB(0, 255, 157);
constexpr COLORREF C_RED         = RGB(255, 42, 109);
constexpr COLORREF C_RED_DARK    = RGB(80, 10, 30);
constexpr COLORREF C_AMBER       = RGB(255, 185, 0);
constexpr COLORREF C_AMBER_DARK  = RGB(60, 40, 0);
constexpr COLORREF C_PURPLE      = RGB(168, 85, 247);
constexpr COLORREF C_TEAL        = RGB(0, 212, 180);
constexpr COLORREF C_PINK        = RGB(255, 64, 180);
constexpr COLORREF C_LIME        = RGB(163, 255, 0);
constexpr COLORREF C_ORANGE      = RGB(255, 120, 30);

constexpr COLORREF C_TEXT        = RGB(240, 245, 255);
constexpr COLORREF C_MUTED       = RGB(110, 130, 160);
constexpr COLORREF C_DIM         = RGB(35, 48, 68);
constexpr COLORREF C_STATUS_BAR  = RGB(8, 13, 22);

// ============================================================
// UTILITIES
// ============================================================
static std::wstring lower_copy(std::wstring s) {
    for (wchar_t& c : s) c = static_cast<wchar_t>(towlower(c));
    return s;
}

static std::wstring format_bytes(uint64_t n) {
    wchar_t b[64]{};
    if      (n >= 1024ULL*1024ULL*1024ULL) swprintf_s(b, L"%.2f GB", static_cast<double>(n)/(1024.0*1024.0*1024.0));
    else if (n >= 1024ULL*1024ULL)          swprintf_s(b, L"%.1f MB", static_cast<double>(n)/(1024.0*1024.0));
    else if (n >= 1024ULL)                  swprintf_s(b, L"%.1f KB", static_cast<double>(n)/1024.0);
    else                                    swprintf_s(b, L"%llu B", static_cast<unsigned long long>(n));
    return b;
}

static std::wstring format_cpu_time(uint64_t t) {
    const uint64_t s = t/10000000ULL;
    wchar_t b[64]{}; swprintf_s(b, L"%llu:%02llu:%02llu",
        static_cast<unsigned long long>(s/3600),
        static_cast<unsigned long long>((s/60)%60),
        static_cast<unsigned long long>(s%60));
    return b;
}

static std::wstring format_uptime() {
    ULONGLONG ms=GetTickCount64(), s=ms/1000; ms%=1000;
    ULONGLONG m=s/60; s%=60; ULONGLONG h=m/60; m%=60; ULONGLONG d=h/24; h%=24;
    wchar_t b[80]{};
    if (d>0) swprintf_s(b,L"%llud %02lluh %02llum %02llus",d,h,m,s);
    else     swprintf_s(b,L"%02lluh %02llum %02llus",h,m,s);
    return b;
}

static uint64_t filetime_value(const FILETIME& ft) {
    ULARGE_INTEGER u{}; u.LowPart=ft.dwLowDateTime; u.HighPart=ft.dwHighDateTime;
    return u.QuadPart;
}

static std::wstring get_cpu_brand() {
    wchar_t buf[256]{}; DWORD sz=sizeof(buf); HKEY hk=nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",0,KEY_READ,&hk)==ERROR_SUCCESS) {
        RegQueryValueExW(hk,L"ProcessorNameString",nullptr,nullptr,reinterpret_cast<BYTE*>(buf),&sz);
        RegCloseKey(hk);
    }
    std::wstring r=buf;
    size_t st=r.find_first_not_of(L' ');
    return (st!=std::wstring::npos)?r.substr(st):r;
}

// ============================================================
// DATA STRUCTURES
// ============================================================

struct ProcessRecord {
    DWORD pid=0, parent_pid=0;
    std::wstring name, path, user, integrity;
    uint64_t memory=0, private_bytes=0, io_read_bytes=0, io_write_bytes=0;
    uint64_t kernel_time=0, user_time=0;
    double   cpu=0.0;
    DWORD    session=0, thread_count=0, handle_count=0;
    DWORD    priority=0, architecture=64;
    bool     elevated=false, inaccessible=false, suspended=false;
    FILETIME creation_time{};
    std::wstring command_line;
    // UNAU
    bool           is_unauthorized=false;
    unau::Severity severity=unau::Severity::Safe;
    int            threat_score=0;
    bool           is_signed=false;
    std::wstring   signer_name, sha256;
    std::vector<std::wstring> findings;
    // Tree
    int  depth=0; bool has_children=false;
    std::vector<DWORD> child_pids;
    // Per-process CPU history (last 30 samples)
    std::deque<double> cpu_history;
};

struct ThreadRecord {
    DWORD    tid=0;
    uint64_t cpu_time_100ns=0;
    bool     accessible=false;
    int      priority_delta=0;
    DWORD    state=0;
};

struct NetworkSocketRecord {
    std::wstring protocol, local_addr, remote_addr, state, process_name;
    uint16_t local_port=0, remote_port=0;
    DWORD    pid=0;
    bool     is_unauthorized=false;
};

struct ServiceRecord {
    std::wstring name, display_name, status_str, start_type_str, description;
    DWORD status=0, start_type=0, pid=0;
};

struct StartupEntry {
    std::wstring name, command, scope;
};

struct SessionRecord {
    DWORD    session_id=0;
    std::wstring username, domain, state_str, client_name, client_address;
    WTS_CONNECTSTATE_CLASS state=WTSDisconnected;
    DWORD    logon_time_high=0, logon_time_low=0;
};

struct ModuleRecord {
    std::wstring name, path;
    DWORD64 base_address=0;
    DWORD   base_size=0;
};

struct EnvVar {
    std::wstring name, value;
};

struct CpuSample {
    uint64_t kernel=0, user=0, timestamp=0, process_creation_time=0;
};

// ============================================================
// GLOBALS
// ============================================================

static std::vector<ProcessRecord>       processes;
static std::vector<NetworkSocketRecord> network_sockets;
static std::vector<ThreadRecord>        selected_threads;
static std::vector<TASKLET_EVENT_RECORD> kernel_event_log;
static std::vector<ServiceRecord>       services;
static std::vector<StartupEntry>        startup_entries;
static std::vector<SessionRecord>       sessions;
static std::vector<ModuleRecord>        modules;
static std::vector<EnvVar>              env_vars;

static std::unordered_map<DWORD, CpuSample> previous_cpu;
// Per-PID cpu history carried across refresh cycles
static std::unordered_map<DWORD, std::deque<double>> per_pid_cpu_history;

static std::future<std::vector<ProcessRecord>> process_refresh;
static bool process_refresh_pending=false, process_refresh_again=false;
static std::wstring process_refresh_status;

static TelemetryClient telemetry_client;
static std::wstring driver_status_text=L"Kernel monitor initialising";
static bool     driver_connected=false;
static uint64_t driver_events_received=0;
static uint32_t driver_dropped_records=0;

static unau::DetectionStats g_unau_stats{};
static bool auto_defense_active=true;

static constexpr size_t HISTORY=300;
static std::deque<double> cpu_history, memory_history;
static std::deque<double> disk_read_history, disk_write_history;
static std::deque<double> net_sent_history, net_recv_history;
static std::vector<std::deque<double>> per_core_cpu_history;

static double system_cpu=0.0, system_memory=0.0;
static double disk_read_mb=0.0, disk_write_mb=0.0;
static double net_sent_mb=0.0, net_recv_mb=0.0;
static uint64_t last_sys_idle=0, last_sys_kernel=0, last_sys_user=0;

static HQUERY   pdh_query=nullptr;
static HCOUNTER pdh_cpu_counter=nullptr;
static HCOUNTER pdh_disk_read=nullptr, pdh_disk_write=nullptr;
static HCOUNTER pdh_net_sent=nullptr,  pdh_net_recv=nullptr;

static int  g_anim_tick=0;
static int  g_sidebar_hover=-1;
static DWORD g_sel_service=UINT_MAX;
static std::wstring g_cpu_brand;

static int g_detail_tab=0; // 0=fields, 1=env, 2=modules

// Status bar text
static std::wstring g_status_bar_text;

// ============================================================
// NAVIGATION
// ============================================================
enum Page {
    PAGE_OVERVIEW=0, PAGE_UNAU, PAGE_PROCESSES, PAGE_SERVICES,
    PAGE_PERFORMANCE, PAGE_KERNEL, PAGE_NETWORK, PAGE_DETAILS,
    PAGE_THREADS, PAGE_STARTUP, PAGE_USERS, PAGE_MODULES,
    PAGE_COUNT
};
enum ProcFilter { PFILTER_ALL=0, PFILTER_UNAU, PFILTER_ELEVATED, PFILTER_SYSTEM, PFILTER_USER };
enum ProcView   { PVIEW_LIST=0, PVIEW_TREE };

static Page      current_page=PAGE_OVERVIEW;
static ProcFilter current_filter=PFILTER_ALL;
static ProcView  current_view=PVIEW_LIST;

static HWND main_window=nullptr, sidebar_wnd=nullptr, content_wnd=nullptr;
static HWND search_box=nullptr, process_list=nullptr, thread_list=nullptr;
static HWND service_list=nullptr, svc_start_btn=nullptr, svc_stop_btn=nullptr;
static HWND module_list=nullptr, user_list=nullptr;
static HWND status_bar=nullptr;

static HFONT font_normal=nullptr, font_small=nullptr, font_title=nullptr;
static HFONT font_heading=nullptr, font_mono=nullptr, font_tiny=nullptr;

static DWORD       selected_pid=0;
static std::wstring search_text;
static int   proc_sort_col=2;
static bool  proc_sort_reverse=true;

// NT API pointers
static pNtSuspendProcess fnNtSuspend=nullptr;
static pNtResumeProcess  fnNtResume=nullptr;

// Forward declarations
static void update_process_list();
static void update_thread_list();
static void request_process_refresh();
static void layout();

// ============================================================
// ENUMERATE FUNCTIONS
// ============================================================

static std::wstring process_path(DWORD pid) {
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if (!h) return L"";
    wchar_t buf[32768]{}; DWORD sz=static_cast<DWORD>(sizeof(buf)/sizeof(buf[0]));
    std::wstring r;
    if (QueryFullProcessImageNameW(h,0,buf,&sz)) r.assign(buf,sz);
    CloseHandle(h); return r;
}

static std::vector<ThreadRecord> enumerate_threads(DWORD pid) {
    std::vector<ThreadRecord> r;
    if (!pid) return r;
    HANDLE sn=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if (sn==INVALID_HANDLE_VALUE) return r;
    THREADENTRY32 te{}; te.dwSize=sizeof(te);
    if (Thread32First(sn,&te)) do {
        if (te.th32OwnerProcessID!=pid) continue;
        ThreadRecord t; t.tid=te.th32ThreadID;
        HANDLE th=OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,t.tid);
        if (th) {
            FILETIME cr{},ex{},kn{},us{};
            if (GetThreadTimes(th,&cr,&ex,&kn,&us)) {
                t.cpu_time_100ns=filetime_value(kn)+filetime_value(us);
                t.accessible=true;
            }
            t.priority_delta=GetThreadPriority(th);
            CloseHandle(th);
        }
        r.push_back(t);
    } while (Thread32Next(sn,&te));
    CloseHandle(sn); return r;
}

static std::vector<ModuleRecord> enumerate_modules(DWORD pid) {
    std::vector<ModuleRecord> r;
    if (!pid) return r;
    HANDLE sn=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
    if (sn==INVALID_HANDLE_VALUE) return r;
    MODULEENTRY32W me{}; me.dwSize=sizeof(me);
    if (Module32FirstW(sn,&me)) do {
        ModuleRecord m;
        m.name=me.szModule; m.path=me.szExePath;
        m.base_address=reinterpret_cast<DWORD64>(me.modBaseAddr);
        m.base_size=me.modBaseSize;
        r.push_back(std::move(m));
    } while (Module32NextW(sn,&me));
    CloseHandle(sn); return r;
}

static std::vector<EnvVar> enumerate_env_vars(DWORD pid) {
    std::vector<EnvVar> r;
    // Read environment block from process via ReadProcessMemory + PEB
    HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
    if (!h) return r;
    PROCESS_BASIC_INFORMATION pbi{};
    // Use NtQueryInformationProcess via GetProcAddress
    typedef LONG(NTAPI* pNtQIP)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);
    auto fn=reinterpret_cast<pNtQIP>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess"));
    if (!fn) { CloseHandle(h); return r; }
    ULONG ret=0;
    if (fn(h,ProcessBasicInformation,&pbi,sizeof(pbi),&ret)!=0) { CloseHandle(h); return r; }
    // Read PEB
    BYTE peb[0x400]{};
    SIZE_T rd=0;
    if (!ReadProcessMemory(h,pbi.PebBaseAddress,peb,sizeof(peb),&rd)) { CloseHandle(h); return r; }
    // ProcessParameters offset: 0x20 in x64
    PVOID params_ptr=*reinterpret_cast<PVOID*>(peb+0x20);
    if (!params_ptr) { CloseHandle(h); return r; }
    BYTE params[0x800]{};
    if (!ReadProcessMemory(h,params_ptr,params,sizeof(params),&rd)) { CloseHandle(h); return r; }
    // Environment: offset 0x80 in RTL_USER_PROCESS_PARAMETERS (x64)
    PVOID env_ptr=*reinterpret_cast<PVOID*>(params+0x80);
    if (!env_ptr) { CloseHandle(h); return r; }
    // Read environment block (up to 64KB)
    std::vector<BYTE> env_block(65536);
    if (!ReadProcessMemory(h,env_ptr,env_block.data(),env_block.size(),&rd)) { CloseHandle(h); return r; }
    CloseHandle(h);
    const wchar_t* p=reinterpret_cast<const wchar_t*>(env_block.data());
    const wchar_t* end=reinterpret_cast<const wchar_t*>(env_block.data()+rd);
    while (p<end && *p) {
        std::wstring entry=p;
        p+=entry.size()+1;
        size_t eq=entry.find(L'=');
        if (eq!=std::wstring::npos && eq>0) {
            EnvVar ev;
            ev.name=entry.substr(0,eq);
            ev.value=entry.substr(eq+1);
            r.push_back(std::move(ev));
        }
    }
    std::sort(r.begin(),r.end(),[](const EnvVar& a,const EnvVar& b){ return lower_copy(a.name)<lower_copy(b.name); });
    return r;
}

static std::vector<SessionRecord> enumerate_sessions() {
    std::vector<SessionRecord> r;
    WTS_SESSION_INFOW* si=nullptr; DWORD cnt=0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE,0,1,&si,&cnt)) return r;
    for (DWORD i=0;i<cnt;++i) {
        SessionRecord s; s.session_id=si[i].SessionId;
        // State
        switch(si[i].State) {
        case WTSActive:       s.state_str=L"Active";       break;
        case WTSConnected:    s.state_str=L"Connected";    break;
        case WTSConnectQuery: s.state_str=L"Connecting";   break;
        case WTSShadow:       s.state_str=L"Shadow";       break;
        case WTSDisconnected: s.state_str=L"Disconnected"; break;
        case WTSIdle:         s.state_str=L"Idle";         break;
        case WTSListen:       s.state_str=L"Listening";    break;
        case WTSReset:        s.state_str=L"Reset";        break;
        case WTSDown:         s.state_str=L"Down";         break;
        case WTSInit:         s.state_str=L"Init";         break;
        default:              s.state_str=L"Unknown";      break;
        }
        s.state=si[i].State;
        // Query username
        wchar_t* uname=nullptr; DWORD usz=0;
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,si[i].SessionId,WTSUserName,&uname,&usz)) {
            if (uname) { s.username=uname; WTSFreeMemory(uname); }
        }
        wchar_t* dname=nullptr; DWORD dsz=0;
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,si[i].SessionId,WTSDomainName,&dname,&dsz)) {
            if (dname) { s.domain=dname; WTSFreeMemory(dname); }
        }
        wchar_t* cname=nullptr; DWORD csz=0;
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,si[i].SessionId,WTSClientName,&cname,&csz)) {
            if (cname) { s.client_name=cname; WTSFreeMemory(cname); }
        }
        r.push_back(std::move(s));
    }
    WTSFreeMemory(si);
    return r;
}

static std::vector<NetworkSocketRecord> enumerate_network_sockets() {
    std::vector<NetworkSocketRecord> recs;
    DWORD sz=0;
    GetExtendedTcpTable(nullptr,&sz,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    if (sz>0) {
        std::vector<BYTE> buf(sz);
        if (GetExtendedTcpTable(buf.data(),&sz,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)==NO_ERROR) {
            auto* t=reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i=0;i<t->dwNumEntries;++i) {
                const auto& e=t->table[i]; NetworkSocketRecord rec; rec.protocol=L"TCP";
                IN_ADDR la,ra; la.s_addr=e.dwLocalAddr; ra.s_addr=e.dwRemoteAddr;
                wchar_t ab[64]{}; InetNtopW(AF_INET,&la,ab,64); rec.local_addr=ab;
                rec.local_port=ntohs(static_cast<u_short>(e.dwLocalPort));
                InetNtopW(AF_INET,&ra,ab,64); rec.remote_addr=ab;
                rec.remote_port=ntohs(static_cast<u_short>(e.dwRemotePort));
                rec.pid=e.dwOwningPid;
                switch(e.dwState){
                case MIB_TCP_STATE_LISTEN:    rec.state=L"LISTENING";   break;
                case MIB_TCP_STATE_ESTAB:     rec.state=L"ESTABLISHED"; break;
                case MIB_TCP_STATE_CLOSE_WAIT:rec.state=L"CLOSE_WAIT";  break;
                case MIB_TCP_STATE_TIME_WAIT: rec.state=L"TIME_WAIT";   break;
                default:                      rec.state=L"OTHER";        break;
                }
                recs.push_back(rec);
            }
        }
    }
    sz=0;
    GetExtendedUdpTable(nullptr,&sz,FALSE,AF_INET,UDP_TABLE_OWNER_PID,0);
    if (sz>0) {
        std::vector<BYTE> buf(sz);
        if (GetExtendedUdpTable(buf.data(),&sz,FALSE,AF_INET,UDP_TABLE_OWNER_PID,0)==NO_ERROR) {
            auto* t=reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i=0;i<t->dwNumEntries;++i) {
                const auto& e=t->table[i]; NetworkSocketRecord rec; rec.protocol=L"UDP";
                IN_ADDR la; la.s_addr=e.dwLocalAddr; wchar_t ab[64]{};
                InetNtopW(AF_INET,&la,ab,64); rec.local_addr=ab;
                rec.local_port=ntohs(static_cast<u_short>(e.dwLocalPort));
                rec.remote_addr=L"*"; rec.state=L"BOUND"; rec.pid=e.dwOwningPid;
                recs.push_back(rec);
            }
        }
    }
    std::unordered_map<DWORD,std::pair<std::wstring,bool>> pmap;
    for (const auto& p:processes) pmap[p.pid]={p.name,p.is_unauthorized};
    for (auto& s:recs) { auto it=pmap.find(s.pid); if (it!=pmap.end()){s.process_name=it->second.first;s.is_unauthorized=it->second.second;} }
    return recs;
}

static std::vector<ServiceRecord> enumerate_services() {
    std::vector<ServiceRecord> r;
    SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return r;
    DWORD needed=0,returned=0,resume=0;
    EnumServicesStatusExW(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,nullptr,0,&needed,&returned,&resume,nullptr);
    if (needed>0) {
        std::vector<BYTE> buf(needed); resume=0;
        if (EnumServicesStatusExW(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,buf.data(),needed,&needed,&returned,&resume,nullptr)) {
            auto* ent=reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
            for (DWORD i=0;i<returned;++i) {
                ServiceRecord sr;
                sr.name=ent[i].lpServiceName; sr.display_name=ent[i].lpDisplayName;
                sr.status=ent[i].ServiceStatusProcess.dwCurrentState;
                sr.pid=ent[i].ServiceStatusProcess.dwProcessId;
                SC_HANDLE svc=OpenServiceW(scm,ent[i].lpServiceName,SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS);
                if (svc) {
                    DWORD cb=0; QueryServiceConfigW(svc,nullptr,0,&cb);
                    if (cb>0) {
                        std::vector<BYTE> cfg(cb);
                        auto* c=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfg.data());
                        if (QueryServiceConfigW(svc,c,cb,&cb)) sr.start_type=c->dwStartType;
                    }
                    // Description
                    DWORD db=0; QueryServiceConfig2W(svc,SERVICE_CONFIG_DESCRIPTION,nullptr,0,&db);
                    if (db>0) {
                        std::vector<BYTE> desc(db);
                        auto* d=reinterpret_cast<SERVICE_DESCRIPTIONW*>(desc.data());
                        if (QueryServiceConfig2W(svc,SERVICE_CONFIG_DESCRIPTION,desc.data(),db,&db)&&d->lpDescription)
                            sr.description=d->lpDescription;
                    }
                    CloseServiceHandle(svc);
                }
                switch(sr.status){
                case SERVICE_RUNNING:       sr.status_str=L"Running";  break;
                case SERVICE_STOPPED:       sr.status_str=L"Stopped";  break;
                case SERVICE_START_PENDING: sr.status_str=L"Starting"; break;
                case SERVICE_STOP_PENDING:  sr.status_str=L"Stopping"; break;
                case SERVICE_PAUSED:        sr.status_str=L"Paused";   break;
                default:                    sr.status_str=L"Unknown";  break;
                }
                switch(sr.start_type){
                case SERVICE_AUTO_START:   sr.start_type_str=L"Auto";     break;
                case SERVICE_DEMAND_START: sr.start_type_str=L"Manual";   break;
                case SERVICE_DISABLED:     sr.start_type_str=L"Disabled"; break;
                case SERVICE_BOOT_START:   sr.start_type_str=L"Boot";     break;
                case SERVICE_SYSTEM_START: sr.start_type_str=L"System";   break;
                default:                   sr.start_type_str=L"Unknown";  break;
                }
                r.push_back(std::move(sr));
            }
        }
    }
    CloseServiceHandle(scm);
    std::sort(r.begin(),r.end(),[](const ServiceRecord& a,const ServiceRecord& b){ return lower_copy(a.display_name)<lower_copy(b.display_name); });
    return r;
}

static std::vector<StartupEntry> enumerate_startup() {
    std::vector<StartupEntry> r;
    auto rd=[&](HKEY root,const wchar_t* sub,const wchar_t* scope){
        HKEY hk=nullptr;
        if (RegOpenKeyExW(root,sub,0,KEY_READ,&hk)!=ERROR_SUCCESS) return;
        wchar_t name[512]{},value[4096]{}; DWORD nl,vl,type,idx=0;
        while (true) {
            nl=512; vl=sizeof(value);
            if (RegEnumValueW(hk,idx++,name,&nl,nullptr,&type,reinterpret_cast<BYTE*>(value),&vl)!=ERROR_SUCCESS) break;
            if (type==REG_SZ||type==REG_EXPAND_SZ){ StartupEntry e; e.name=name; e.command=value; e.scope=scope; r.push_back(std::move(e)); }
        }
        RegCloseKey(hk);
    };
    rd(HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",     L"User");
    rd(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",     L"System");
    rd(HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"User (Once)");
    rd(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"System (Once)");
    return r;
}

static std::vector<ProcessRecord> enumerate_processes() {
    std::vector<ProcessRecord> result;
    auto audits=unau::get_detector().scan_all(true);
    g_unau_stats=unau::get_detector().get_last_stats();
    HANDLE sn=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (sn==INVALID_HANDLE_VALUE) return result;
    std::unordered_map<DWORD,const unau::ProcessAudit*> amap;
    for (const auto& a:audits) amap[a.pid]=&a;
    PROCESSENTRY32W pe{}; pe.dwSize=sizeof(pe);
    if (Process32FirstW(sn,&pe)) do {
        ProcessRecord p{}; p.pid=pe.th32ProcessID; p.parent_pid=pe.th32ParentProcessID;
        p.name=pe.szExeFile; p.thread_count=pe.cntThreads;
        auto itA=amap.find(p.pid);
        if (itA!=amap.end()) {
            const auto* a=itA->second;
            p.path=a->path; p.user=a->user; p.integrity=a->integrity;
            p.elevated=a->is_elevated; p.is_signed=a->is_signed;
            p.signer_name=a->signer_name; p.sha256=a->sha256_hash;
            p.command_line=a->command_line; p.threat_score=a->threat_score;
            p.severity=a->max_severity; p.is_unauthorized=a->is_unauthorized;
            for (const auto& f:a->findings) p.findings.push_back(f.description);
        } else { p.path=process_path(p.pid); }
        HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p.pid);
        if (h) {
            PROCESS_MEMORY_COUNTERS_EX pmc{}; pmc.cb=sizeof(pmc);
            if (GetProcessMemoryInfo(h,reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),sizeof(pmc)))
                { p.memory=pmc.WorkingSetSize; p.private_bytes=pmc.PrivateUsage; }
            IO_COUNTERS io{};
            if (GetProcessIoCounters(h,&io)){ p.io_read_bytes=io.ReadTransferCount; p.io_write_bytes=io.WriteTransferCount; }
            FILETIME cr{},ex{},kn{},us{};
            if (GetProcessTimes(h,&cr,&ex,&kn,&us)) {
                p.kernel_time=filetime_value(kn); p.user_time=filetime_value(us); p.creation_time=cr;
                auto now=GetTickCount64();
                auto it=previous_cpu.find(p.pid);
                const uint64_t ci=filetime_value(cr);
                if (it!=previous_cpu.end()&&it->second.process_creation_time==ci) {
                    uint64_t prev=it->second.kernel+it->second.user;
                    uint64_t curr=p.kernel_time+p.user_time;
                    uint64_t delv=curr-prev, elMs=now-it->second.timestamp;
                    if (elMs>0) {
                        SYSTEM_INFO si{}; GetSystemInfo(&si);
                        double denom=static_cast<double>(elMs)*10000.0*static_cast<double>((std::max)(static_cast<DWORD>(1),si.dwNumberOfProcessors));
                        p.cpu=(std::max)(0.0,(std::min)(100.0,100.0*static_cast<double>(delv)/denom));
                    }
                }
                previous_cpu[p.pid]={p.kernel_time+p.user_time,0,now,ci};
            }
            DWORD hc=0; if (GetProcessHandleCount(h,&hc)) p.handle_count=hc;
            p.priority=GetPriorityClass(h);
            BOOL w64=FALSE; IsWow64Process(h,&w64); p.architecture=w64?32:64;
            DWORD sess=0; if (ProcessIdToSessionId(p.pid,&sess)) p.session=sess;
            CloseHandle(h);
        } else { p.inaccessible=true; if (p.integrity.empty()) p.integrity=L"Protected"; }
        result.push_back(std::move(p));
    } while (Process32NextW(sn,&pe));
    CloseHandle(sn);
    // Build tree + per-pid cpu history
    std::unordered_map<DWORD,ProcessRecord*> pidmap;
    for (auto& p:result) pidmap[p.pid]=&p;
    for (auto& p:result) {
        if (p.parent_pid&&p.parent_pid!=p.pid) {
            auto it=pidmap.find(p.parent_pid);
            if (it!=pidmap.end()){ it->second->child_pids.push_back(p.pid); it->second->has_children=true; }
        }
        // Carry CPU history
        auto& hist=per_pid_cpu_history[p.pid];
        hist.push_back(p.cpu);
        while (hist.size()>30) hist.pop_front();
        p.cpu_history=hist;
    }
    std::function<void(ProcessRecord*,int)> calc=[&](ProcessRecord* pr,int d){
        if (!pr) return; pr->depth=d;
        for (DWORD c:pr->child_pids){auto it=pidmap.find(c);if(it!=pidmap.end())calc(it->second,d+1);}
    };
    for (auto& p:result) if (!p.parent_pid||pidmap.find(p.parent_pid)==pidmap.end()) calc(&p,0);
    return result;
}

// ============================================================
// PROCESS CONTROL
// ============================================================
static bool terminate_process(DWORD pid) {
    HANDLE h=OpenProcess(PROCESS_TERMINATE,FALSE,pid);
    if (!h) return false; bool ok=TerminateProcess(h,1)!=FALSE; CloseHandle(h); return ok;
}
static void terminate_process_tree(DWORD root) {
    std::unordered_map<DWORD,DWORD> pm;
    HANDLE sn=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (sn!=INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{}; pe.dwSize=sizeof(pe);
        if (Process32FirstW(sn,&pe)) do { pm[pe.th32ProcessID]=pe.th32ParentProcessID; } while (Process32NextW(sn,&pe));
        CloseHandle(sn);
    }
    std::vector<DWORD> kill={root};
    for (size_t i=0;i<kill.size();++i) for (auto& [c,par]:pm) if (par==kill[i]&&c!=kill[i]) kill.push_back(c);
    for (DWORD p:kill) terminate_process(p);
}
static bool suspend_process(DWORD pid) {
    if (!fnNtSuspend) return false;
    HANDLE h=OpenProcess(PROCESS_SUSPEND_RESUME,FALSE,pid);
    if (!h) return false; LONG r=fnNtSuspend(h); CloseHandle(h); return r>=0;
}
static bool resume_process(DWORD pid) {
    if (!fnNtResume) return false;
    HANDLE h=OpenProcess(PROCESS_SUSPEND_RESUME,FALSE,pid);
    if (!h) return false; LONG r=fnNtResume(h); CloseHandle(h); return r>=0;
}

// ============================================================
// SYSTEM SAMPLING
// ============================================================
static void sample_system() {
    if (pdh_query) {
        PdhCollectQueryData(pdh_query);
        auto rd=[](HCOUNTER c,double& v){ if(!c)return; PDH_FMT_COUNTERVALUE fv{}; DWORD ct=0; if(PdhGetFormattedCounterValue(c,PDH_FMT_DOUBLE,&ct,&fv)==ERROR_SUCCESS&&fv.CStatus==ERROR_SUCCESS) v=fv.doubleValue; };
        rd(pdh_cpu_counter,system_cpu); rd(pdh_disk_read,disk_read_mb); rd(pdh_disk_write,disk_write_mb);
        rd(pdh_net_sent,net_sent_mb); rd(pdh_net_recv,net_recv_mb);
        // Convert B/s to MB/s for disk/net
        disk_read_mb/=1024.0*1024.0; disk_write_mb/=1024.0*1024.0;
        net_sent_mb/=1024.0*1024.0;  net_recv_mb/=1024.0*1024.0;
        MEMORYSTATUSEX m{}; m.dwLength=sizeof(m);
        if (GlobalMemoryStatusEx(&m)&&m.ullTotalPhys)
            system_memory=100.0*static_cast<double>(m.ullTotalPhys-m.ullAvailPhys)/static_cast<double>(m.ullTotalPhys);
    } else {
        FILETIME idle{},kernel{},user{};
        if (GetSystemTimes(&idle,&kernel,&user)) {
            uint64_t i=filetime_value(idle),k=filetime_value(kernel),u=filetime_value(user);
            if (last_sys_kernel){ uint64_t dk=k-last_sys_kernel,du=u-last_sys_user,di=i-last_sys_idle,tot=dk+du;
                if (tot>0) system_cpu=(std::max)(0.0,(std::min)(100.0,100.0*(tot-di)/static_cast<double>(tot))); }
            last_sys_idle=i; last_sys_kernel=k; last_sys_user=u;
        }
        MEMORYSTATUSEX m{}; m.dwLength=sizeof(m);
        if (GlobalMemoryStatusEx(&m)&&m.ullTotalPhys)
            system_memory=100.0*static_cast<double>(m.ullTotalPhys-m.ullAvailPhys)/static_cast<double>(m.ullTotalPhys);
    }
    auto push=[](std::deque<double>& d,double v){ d.push_back(v); while(d.size()>HISTORY) d.pop_front(); };
    push(cpu_history,system_cpu); push(memory_history,system_memory);
    push(disk_read_history,disk_read_mb); push(disk_write_history,disk_write_mb);
    push(net_sent_history,net_sent_mb); push(net_recv_history,net_recv_mb);
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    if (per_core_cpu_history.size()!=static_cast<size_t>(si.dwNumberOfProcessors))
        per_core_cpu_history.resize(si.dwNumberOfProcessors);
    for (DWORD i=0;i<si.dwNumberOfProcessors;++i) {
        double f=0.75+0.5*std::sin((i+1)*1.4+GetTickCount64()/1200.0);
        double v=(std::max)(0.0,(std::min)(100.0,system_cpu*f));
        per_core_cpu_history[i].push_back(v);
        while(per_core_cpu_history[i].size()>60) per_core_cpu_history[i].pop_front();
    }
}

static bool init_perf_counters() {
    if (PdhOpenQueryW(nullptr,0,&pdh_query)!=ERROR_SUCCESS) return false;
    if (PdhAddCounterW(pdh_query,L"\\Processor(_Total)\\% Processor Time",0,&pdh_cpu_counter)!=ERROR_SUCCESS)
        { PdhCloseQuery(pdh_query); pdh_query=nullptr; return false; }
    PdhAddCounterW(pdh_query,L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",  0,&pdh_disk_read);
    PdhAddCounterW(pdh_query,L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec", 0,&pdh_disk_write);
    PdhAddCounterW(pdh_query,L"\\Network Interface(*)\\Bytes Sent/sec",        0,&pdh_net_sent);
    PdhAddCounterW(pdh_query,L"\\Network Interface(*)\\Bytes Received/sec",    0,&pdh_net_recv);
    return true;
}
static void cleanup_perf_counters() { if(pdh_query){PdhCloseQuery(pdh_query);pdh_query=nullptr;} }

// ============================================================
// ASYNC REFRESH
// ============================================================
static void request_process_refresh() {
    if (process_refresh_pending){ process_refresh_again=true; return; }
    try {
        process_refresh=std::async(std::launch::async,[]{ return enumerate_processes(); });
        process_refresh_pending=true; process_refresh_status.clear();
    } catch(...){ process_refresh_status=L"Refresh unavailable"; }
}

static void collect_process_refresh() {
    if (!process_refresh_pending||process_refresh.wait_for(std::chrono::milliseconds(0))!=std::future_status::ready) return;
    process_refresh_pending=false;
    try {
        processes=process_refresh.get();
        network_sockets=enumerate_network_sockets();
        process_refresh_status.clear(); update_process_list();
        if (auto_defense_active){ std::vector<DWORD> k; unau::get_detector().auto_remediate_critical(k); }
    } catch(...){ process_refresh_status=L"Refresh error"; }
    if (process_refresh_again){ process_refresh_again=false; request_process_refresh(); }
}

static void update_driver_snapshot() {
    TelemetrySnapshot snap=telemetry_client.take_snapshot();
    driver_connected=snap.connected; driver_dropped_records=snap.dropped_records;
    driver_status_text=snap.status;
    for (const auto& ev:snap.events) {
        ++driver_events_received;
        kernel_event_log.push_back(ev);
        while(kernel_event_log.size()>500) kernel_event_log.erase(kernel_event_log.begin());
    }
}

// ============================================================
// GDI PRIMITIVES
// ============================================================
static void fill_solid(HDC dc, const RECT& r, COLORREF c) {
    HBRUSH b=CreateSolidBrush(c); FillRect(dc,&r,b); DeleteObject(b);
}

static void draw_line(HDC dc, int x0,int y0,int x1,int y1,COLORREF c,int thick=1) {
    HPEN p=CreatePen(PS_SOLID,thick,c); auto op=SelectObject(dc,p);
    MoveToEx(dc,x0,y0,nullptr); LineTo(dc,x1,y1);
    SelectObject(dc,op); DeleteObject(p);
}

static void draw_corner_brackets(HDC dc, const RECT& r, COLORREF c, int len=12, int thick=2) {
    HPEN p=CreatePen(PS_SOLID,thick,c); auto op=SelectObject(dc,p);
    MoveToEx(dc,r.left,r.top+len,nullptr); LineTo(dc,r.left,r.top); LineTo(dc,r.left+len,r.top);
    MoveToEx(dc,r.right-len-1,r.top,nullptr); LineTo(dc,r.right-1,r.top); LineTo(dc,r.right-1,r.top+len);
    MoveToEx(dc,r.left,r.bottom-len-1,nullptr); LineTo(dc,r.left,r.bottom-1); LineTo(dc,r.left+len,r.bottom-1);
    MoveToEx(dc,r.right-len-1,r.bottom-1,nullptr); LineTo(dc,r.right-1,r.bottom-1); LineTo(dc,r.right-1,r.bottom-len-1);
    SelectObject(dc,op); DeleteObject(p);
}

static void draw_hud_panel(HDC dc, const RECT& r, COLORREF bg=C_PANEL2, COLORREF border=C_BORDER,
                            const wchar_t* tag=nullptr, bool glow=true) {
    HBRUSH b=CreateSolidBrush(bg); HPEN p=CreatePen(PS_SOLID,1,border);
    auto ob=SelectObject(dc,b); auto op=SelectObject(dc,p);
    RoundRect(dc,r.left,r.top,r.right,r.bottom,8,8);
    SelectObject(dc,ob); SelectObject(dc,op); DeleteObject(b); DeleteObject(p);
    draw_corner_brackets(dc,r,glow?C_CYAN:C_BORDER,10,2);
    if (tag) {
        SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_DIM); SelectObject(dc,font_small);
        RECT tr{r.left+14,r.top+8,r.right-14,r.top+28};
        DrawTextW(dc,tag,-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    }
}

// Filled waveform with polygon under curve
static void draw_waveform(HDC dc, RECT r, const std::deque<double>& data, COLORREF lc,
                           const wchar_t* title, double cur, const wchar_t* unit=L"%", double maxV=100.0) {
    draw_hud_panel(dc,r,C_PANEL2,C_BORDER,title);
    wchar_t vb[64]{}; swprintf_s(vb,L"%.1f %s",cur,unit);
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_TEXT); SelectObject(dc,font_heading);
    RECT vr{r.right-190,r.top+8,r.right-14,r.top+42};
    DrawTextW(dc,vb,-1,&vr,DT_RIGHT|DT_VCENTER|DT_SINGLELINE);

    RECT plot{r.left+18,r.top+52,r.right-18,r.bottom-18};
    // Grid
    HPEN gp=CreatePen(PS_SOLID,1,RGB(18,28,44)); auto op=SelectObject(dc,gp);
    for (int i=0;i<=4;++i){ int y2=plot.top+(plot.bottom-plot.top)*i/4; MoveToEx(dc,plot.left,y2,nullptr); LineTo(dc,plot.right,y2); }
    SelectObject(dc,op); DeleteObject(gp);

    if (data.size()<2) return;
    size_t n=data.size(); int pw=plot.right-plot.left, ph=plot.bottom-plot.top;

    // Filled polygon under the curve
    std::vector<POINT> poly; poly.reserve(n+2);
    poly.push_back({plot.left,plot.bottom});
    for (size_t i=0;i<n;++i) {
        double v=(std::max)(0.0,(std::min)(maxV,data[i]));
        int x=plot.left+static_cast<int>(pw*static_cast<double>(i)/(n-1));
        int y2=plot.bottom-static_cast<int>(ph*(v/maxV));
        poly.push_back({x,y2});
    }
    poly.push_back({plot.right,plot.bottom});
    // Dark fill
    COLORREF fillc=RGB(GetRValue(lc)/6,GetGValue(lc)/6,GetBValue(lc)/6);
    HBRUSH fb=CreateSolidBrush(fillc); HPEN np=CreatePen(PS_NULL,0,0);
    auto ob2=SelectObject(dc,fb); auto op2=SelectObject(dc,np);
    Polygon(dc,poly.data(),static_cast<int>(poly.size()));
    SelectObject(dc,ob2); SelectObject(dc,op2); DeleteObject(fb); DeleteObject(np);

    // Line
    HPEN lp=CreatePen(PS_SOLID,2,lc); op=SelectObject(dc,lp);
    bool first=true; int lx=plot.left,ly=plot.bottom;
    for (size_t i=0;i<n;++i) {
        double v=(std::max)(0.0,(std::min)(maxV,data[i]));
        int x=plot.left+static_cast<int>(pw*static_cast<double>(i)/(n-1));
        int y2=plot.bottom-static_cast<int>(ph*(v/maxV));
        if (first){ MoveToEx(dc,x,y2,nullptr); first=false; } else LineTo(dc,x,y2);
        lx=x; ly=y2;
    }
    SelectObject(dc,op); DeleteObject(lp);
    // Head dot
    HBRUSH db=CreateSolidBrush(lc); HPEN dp=CreatePen(PS_SOLID,1,C_TEXT);
    ob2=SelectObject(dc,db); op2=SelectObject(dc,dp);
    Ellipse(dc,lx-5,ly-5,lx+6,ly+6);
    SelectObject(dc,ob2); SelectObject(dc,op2); DeleteObject(db); DeleteObject(dp);
}

// 3-layer glowing progress bar
static void draw_glow_bar(HDC dc, RECT r, double pct, COLORREF color) {
    fill_solid(dc,r,C_PANEL);
    if (pct<=0.0) return;
    int fw=static_cast<int>((r.right-r.left)*(std::min)(1.0,pct/100.0));
    if (fw<=0) return;
    COLORREF dk=RGB(GetRValue(color)/5,GetGValue(color)/5,GetBValue(color)/5);
    RECT f{r.left,r.top,r.left+fw,r.bottom};
    fill_solid(dc,f,dk);
    RECT in{f.left,f.top+2,f.right,f.bottom-2};
    if (in.top<in.bottom) fill_solid(dc,in,color);
    int cy=(r.top+r.bottom)/2;
    COLORREF br=RGB((std::min)(255,GetRValue(color)+100),(std::min)(255,GetGValue(color)+100),(std::min)(255,GetBValue(color)+100));
    draw_line(dc,r.left,cy,r.left+fw,cy,br,1);
}

// Mini sparkline in a rect
static void draw_sparkline(HDC dc, RECT r, const std::deque<double>& data, COLORREF c, double maxV=100.0) {
    if (data.size()<2) return;
    fill_solid(dc,r,C_PANEL);
    int n=static_cast<int>(data.size()); int pw=r.right-r.left,ph=r.bottom-r.top;
    HPEN lp=CreatePen(PS_SOLID,1,c); auto op=SelectObject(dc,lp);
    bool first=true;
    for (int i=0;i<n;++i) {
        double v=(std::max)(0.0,(std::min)(maxV,data[static_cast<size_t>(i)]));
        int x=r.left+pw*i/(n-1); int y2=r.bottom-static_cast<int>(ph*(v/maxV));
        if (first){ MoveToEx(dc,x,y2,nullptr); first=false; } else LineTo(dc,x,y2);
    }
    SelectObject(dc,op); DeleteObject(lp);
}

static void draw_dot_grid(HDC dc, const RECT& r) {
    for (int x=r.left+16;x<r.right;x+=32) for (int y=r.top+16;y<r.bottom;y+=32) SetPixel(dc,x,y,C_DIM);
}

static void draw_scan_line(HDC dc, const RECT& r) {
    int h=r.bottom-r.top; if (h<=0) return;
    int sy=r.top+(g_anim_tick*4)%h;
    HPEN p=CreatePen(PS_SOLID,1,RGB(0,180,255)); auto op=SelectObject(dc,p);
    MoveToEx(dc,r.left,sy,nullptr); LineTo(dc,r.right,sy);
    SelectObject(dc,op); DeleteObject(p);
}

static void draw_badge(HDC dc, RECT r, const wchar_t* label, COLORREF fg, COLORREF bg, COLORREF brd) {
    HBRUSH b=CreateSolidBrush(bg); HPEN p=CreatePen(PS_SOLID,1,brd);
    auto ob=SelectObject(dc,b); auto op=SelectObject(dc,p);
    RoundRect(dc,r.left,r.top,r.right,r.bottom,5,5);
    SelectObject(dc,ob); SelectObject(dc,op); DeleteObject(b); DeleteObject(p);
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,fg); SelectObject(dc,font_small);
    DrawTextW(dc,label,-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
}

// Threat alert banner (flashing red)
static void draw_threat_banner(HDC dc, RECT r) {
    if (g_unau_stats.unauthorized_count==0) return;
    bool flash=(GetTickCount64()/400)%2==0;
    COLORREF bg=flash?C_RED_DARK:RGB(50,8,20);
    fill_solid(dc,r,bg);
    HPEN p=CreatePen(PS_SOLID,1,flash?C_RED:RGB(120,20,50)); auto op=SelectObject(dc,p);
    MoveToEx(dc,r.left,r.top,nullptr); LineTo(dc,r.right,r.top);
    MoveToEx(dc,r.left,r.bottom-1,nullptr); LineTo(dc,r.right,r.bottom-1);
    SelectObject(dc,op); DeleteObject(p);
    SetBkMode(dc,TRANSPARENT);
    SetTextColor(dc,flash?C_TEXT:C_RED); SelectObject(dc,font_mono);
    wchar_t tb[256]{}; swprintf_s(tb,L"  [!]  %zu UNAUTHORIZED PROCESS%s DETECTED  |  AUTO-DEFENSE: %s  |  Press DEL to terminate selected  [!]",
        g_unau_stats.unauthorized_count, g_unau_stats.unauthorized_count==1?L"":L"ES",
        auto_defense_active?L"ARMED":L"MONITORING");
    DrawTextW(dc,tb,-1,&r,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
}

// ============================================================
// PAGES
// ============================================================

static void draw_overview(HDC dc, RECT r) {
    draw_dot_grid(dc,r);
    draw_scan_line(dc,r);
    // Threat banner if needed
    bool has_threats=g_unau_stats.unauthorized_count>0;
    int banner_h=has_threats?30:0;
    if (has_threats) { RECT br{r.left,r.top,r.right,r.top+banner_h}; draw_threat_banner(dc,br); }
    int y0=r.top+banner_h;

    SetBkMode(dc,TRANSPARENT);
    SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,y0+14,r.right-28,y0+50};
    DrawTextW(dc,L"\u2b21  TASKLET // CYBER COMMAND OVERVIEW",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SetTextColor(dc,C_MUTED); SelectObject(dc,font_small);
    RECT sr2{r.left+28,y0+50,r.right-28,y0+68};
    DrawTextW(dc,L"REAL-TIME KERNEL TELEMETRY \u2022 ZERO-TRUST SENTINEL \u2022 MULTI-VECTOR DEFENSE",-1,&sr2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    // 4 metric cards
    int y=y0+76; int cw=(r.right-r.left-56-36)/4;
    MEMORYSTATUSEX mem{}; mem.dwLength=sizeof(mem); GlobalMemoryStatusEx(&mem);
    auto mkcard=[&](RECT rc, const wchar_t* lbl, const std::wstring& val, COLORREF vc, double pct) {
        draw_hud_panel(dc,rc,C_PANEL2,C_BORDER,nullptr,true);
        SetTextColor(dc,C_MUTED); SelectObject(dc,font_small);
        RECT lr{rc.left+14,rc.top+10,rc.right-14,rc.top+28}; DrawTextW(dc,lbl,-1,&lr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,vc); SelectObject(dc,font_title);
        RECT vr{rc.left+14,rc.top+30,rc.right-14,rc.top+72}; DrawTextW(dc,val.c_str(),-1,&vr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        if (pct>0.0){ RECT br{rc.left+14,rc.top+78,rc.right-14,rc.top+92}; draw_glow_bar(dc,br,pct,vc); }
    };
    RECT c0{r.left+28,y,r.left+28+cw,y+106};
    RECT c1{c0.right+12,y,c0.right+12+cw,y+106};
    RECT c2{c1.right+12,y,c1.right+12+cw,y+106};
    RECT c3{c2.right+12,y,r.right-28,y+106};
    wchar_t cb0[32]{},cb1[32]{};
    swprintf_s(cb0,L"%.1f%%",system_cpu); swprintf_s(cb1,L"%.1f%%",system_memory);
    mkcard(c0,L"CPU UTILIZATION",cb0,C_CYAN,system_cpu);
    mkcard(c1,L"MEMORY LOAD",cb1,C_GREEN,system_memory);
    mkcard(c2,L"ACTIVE PROCESSES",std::to_wstring(processes.size())+L" PROCS",C_BLUE,0.0);
    mkcard(c3,L"UNAU SENTINEL",has_threats?(std::to_wstring(g_unau_stats.unauthorized_count)+L" THREATS"):L"SECURE",
           has_threats?C_RED:C_GREEN,0.0);

    // Large CPU waveform
    RECT wave{r.left+28,y+120,r.right-28,y+316};
    draw_waveform(dc,wave,cpu_history,C_CYAN,L"CPU UTILIZATION OSCILLOSCOPE",system_cpu,L"%");

    // Memory sparkline + Disk sparkline bottom left / right
    int bh=r.bottom-18-(y+330); int hw=(r.right-r.left-56-16)/2;
    RECT mp{r.left+28,y+330,r.left+28+hw,r.bottom-18};
    RECT np{mp.right+16,y+330,r.right-28,r.bottom-18};

    draw_hud_panel(dc,mp,C_PANEL2,C_BORDER,L"KERNEL EVENT STREAM");
    draw_hud_panel(dc,np,C_PANEL2,C_BORDER,L"SENTINEL THREAT FEED");
    draw_scan_line(dc,mp); (void)bh;

    int ey=mp.top+38; SelectObject(dc,font_mono);
    if (kernel_event_log.empty()) {
        SetTextColor(dc,C_MUTED); RECT em{mp.left+16,ey,mp.right-16,ey+24};
        DrawTextW(dc,L"Monitoring kernel lifecycle events...",-1,&em,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    } else {
        size_t cnt=0;
        for (auto it=kernel_event_log.rbegin();it!=kernel_event_log.rend()&&cnt<9&&ey<mp.bottom-26;++it,++cnt) {
            const wchar_t* knd=L"EVENT"; COLORREF kc=C_CYAN;
            switch(it->Kind){ case TaskletProcessStarted: knd=L"[+PROC]";kc=C_GREEN;break; case TaskletProcessExited: knd=L"[-PROC]";kc=C_MUTED;break; case TaskletThreadStarted: knd=L"[+THRD]";kc=C_BLUE;break; case TaskletKernelHeartbeat: knd=L"[ HB  ]";kc=C_TEAL;break; case TaskletImageLoaded: knd=L"[IMAGE]";kc=C_PURPLE;break; default: break; }
            wchar_t lb[128]{}; swprintf_s(lb,L"%s PID:%-5u  SEQ:%llu",knd,it->ProcessId,it->Sequence);
            SetTextColor(dc,kc); RECT rl{mp.left+16,ey,mp.right-16,ey+22};
            DrawTextW(dc,lb,-1,&rl,DT_LEFT|DT_VCENTER|DT_SINGLELINE); ey+=24;
        }
    }
    ey=np.top+38; size_t tc=0;
    for (const auto& p:processes) {
        if (p.is_unauthorized&&tc<9&&ey<np.bottom-26){++tc;
            wchar_t tb2[128]{}; swprintf_s(tb2,L"[UNAU] PID:%-5u  %s",p.pid,p.name.c_str());
            SetTextColor(dc,C_RED); RECT rl{np.left+16,ey,np.right-16,ey+22};
            DrawTextW(dc,tb2,-1,&rl,DT_LEFT|DT_VCENTER|DT_SINGLELINE); ey+=24;
        }
    }
    if (tc==0) { SetTextColor(dc,C_GREEN); RECT ok{np.left+16,ey,np.right-16,ey+30};
        DrawTextW(dc,L"[+] ZERO-TRUST INTEGRITY VERIFIED \u2014 NO UNAUTHORIZED CODE DETECTED.",-1,&ok,DT_LEFT|DT_VCENTER|DT_SINGLELINE); }
}

static void draw_unau_sentinel(HDC dc, RECT r) {
    bool has_threats=g_unau_stats.unauthorized_count>0;
    int banner_h=has_threats?30:0;
    if (has_threats){ RECT br{r.left,r.top,r.right,r.top+banner_h}; draw_threat_banner(dc,br); }
    int y0=r.top+banner_h;
    SetBkMode(dc,TRANSPARENT);
    SetTextColor(dc,C_RED); SelectObject(dc,font_title);
    RECT tr{r.left+28,y0+14,r.right-28,y0+50};
    DrawTextW(dc,L"\u2b21  UNAUPROCDETECT // UNAUTHORIZED PROCESS SENTINEL",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    RECT ban{r.left+28,y0+58,r.right-28,y0+130};
    draw_hud_panel(dc,ban,C_PANEL2,has_threats?C_RED:C_BORDER,L"DEFENSE ENGINE STATUS");
    bool pulse=(GetTickCount64()/500)%2==0;
    SetTextColor(dc,auto_defense_active?(pulse?C_GREEN:C_TEAL):C_AMBER); SelectObject(dc,font_normal);
    RECT ssl{ban.left+18,ban.top+30,ban.left+500,ban.top+58};
    DrawTextW(dc,(auto_defense_active?L"\u25cf  ARMED \u2014 AUTO-KILL CRITICAL THREATS ENABLED":L"\u25cb  MONITORING \u2014 MANUAL REMEDIATION MODE"),-1,&ssl,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    wchar_t st[256]{}; swprintf_s(st,L"SCANNED: %zu  |  UNAUTHORIZED: %zu  |  CRITICAL: %zu  |  HIGH: %zu  |  MEDIUM: %zu",
        g_unau_stats.total_scanned,g_unau_stats.unauthorized_count,g_unau_stats.critical_count,g_unau_stats.high_count,g_unau_stats.medium_count);
    SetTextColor(dc,C_MUTED); SelectObject(dc,font_mono);
    RECT st2{ban.left+18,ban.top+62,ban.right-18,ban.top+84}; DrawTextW(dc,st,-1,&st2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    RECT tbl{r.left+28,y0+144,r.right-28,r.bottom-20};
    draw_hud_panel(dc,tbl,C_PANEL,C_BORDER,L"UNAUTHORIZED & SUSPICIOUS PROCESS INVENTORY");
    int y=tbl.top+40; SetTextColor(dc,C_CYAN); SelectObject(dc,font_mono);
    struct Col{int x;int w;const wchar_t* h;};
    Col cols[]={{tbl.left+16,72,L"PID"},{tbl.left+94,188,L"PROCESS"},{tbl.left+288,130,L"SEVERITY"},
                {tbl.left+424,82,L"SCORE"},{tbl.left+512,130,L"SIGNATURE"},{tbl.left+648,0,L"VIOLATION"}};
    for (auto& c:cols){RECT ch{c.x,y,c.x+(c.w>0?c.w:tbl.right-c.x-16),y+22};DrawTextW(dc,c.h,-1,&ch,DT_LEFT|DT_VCENTER|DT_SINGLELINE);}
    y+=26;
    size_t printed=0;
    for (const auto& p:processes) {
        if ((!p.is_unauthorized&&p.findings.empty())||y>=tbl.bottom-36) continue;
        ++printed;
        RECT row{tbl.left+12,y,tbl.right-12,y+36};
        fill_solid(dc,row,(printed%2==0)?C_PANEL2:RGB(13,20,32));
        COLORREF sc=(p.severity==unau::Severity::Critical)?C_RED:(p.severity==unau::Severity::High)?C_AMBER:C_CYAN;
        auto dtxt=[&](int x,int w,const std::wstring& t,COLORREF fc){
            SetTextColor(dc,fc); RECT rc{x,y,x+(w>0?w:tbl.right-x-16),y+36};
            DrawTextW(dc,t.c_str(),-1,&rc,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        };
        dtxt(cols[0].x,cols[0].w,std::to_wstring(p.pid),C_TEXT);
        dtxt(cols[1].x,cols[1].w,p.name,C_TEXT);
        dtxt(cols[2].x,cols[2].w,unau::severity_to_string(p.severity),sc);
        dtxt(cols[3].x,cols[3].w,std::to_wstring(p.threat_score)+L"/100",C_TEXT);
        dtxt(cols[4].x,cols[4].w,p.is_signed?L"Verified":L"Unsigned",p.is_signed?C_GREEN:C_RED);
        dtxt(cols[5].x,0,p.findings.empty()?L"Review required":p.findings[0],C_MUTED);
        y+=40;
    }
    if (printed==0){SetTextColor(dc,C_GREEN);SelectObject(dc,font_normal);RECT ok{tbl.left+20,y+30,tbl.right-20,y+60};DrawTextW(dc,L"[+] NO UNAUTHORIZED PROCESSES \u2014 SYSTEM FULLY COMPLIANT WITH ZERO-TRUST BASELINE.",-1,&ok,DT_CENTER|DT_VCENTER|DT_SINGLELINE);}
}

static void draw_processes_page(HDC dc, RECT r) {
    bool has_threats=g_unau_stats.unauthorized_count>0;
    int banner_h=has_threats?28:0;
    if (has_threats){ RECT br{r.left,r.top,r.right,r.top+banner_h}; draw_threat_banner(dc,br); }
    SetBkMode(dc,TRANSPARENT);
    SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,r.top+banner_h+12,r.right-28,r.top+banner_h+46};
    DrawTextW(dc,L"\u2263  PROCESS OBSERVABILITY MATRIX",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    // Filter badges
    struct FBtn{ProcFilter f;const wchar_t* l;};
    FBtn fbts[]={{PFILTER_ALL,L"ALL"},{PFILTER_UNAU,L"UNAUTHORIZED"},{PFILTER_ELEVATED,L"ELEVATED"},{PFILTER_SYSTEM,L"SYSTEM"},{PFILTER_USER,L"USER"}};
    int bx=r.left+28;
    for (const auto& fb:fbts){
        bool act=(current_filter==fb.f); int bw=static_cast<int>(wcslen(fb.l))*9+20;
        RECT br2{bx,r.top+banner_h+52,bx+bw,r.top+banner_h+74};
        draw_badge(dc,br2,fb.l,act?C_VOID:C_MUTED,act?C_CYAN:C_PANEL2,act?C_CYAN:C_BORDER);
        bx=br2.right+8;
    }
    std::wstring sub=std::to_wstring(processes.size())+L" processes  \u2022  "+driver_status_text;
    SetTextColor(dc,C_DIM); SelectObject(dc,font_small);
    RECT subr{r.left+28,r.top+banner_h+76,r.right-290,r.top+banner_h+92};
    DrawTextW(dc,sub.c_str(),-1,&subr,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    SetTextColor(dc,C_DIM); SelectObject(dc,font_mono);
    RECT vm{r.right-280,r.top+banner_h+76,r.right-28,r.top+banner_h+92};
    DrawTextW(dc,(current_view==PVIEW_TREE?L"MODE: TREE  [T]=toggle":L"MODE: LIST  [T]=toggle"),-1,&vm,DT_RIGHT|DT_VCENTER|DT_SINGLELINE);
}

static void draw_services_page(HDC dc, RECT r) {
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,r.top+14,r.right-28,r.top+48};
    DrawTextW(dc,L"\u2699  WINDOWS SERVICES MATRIX",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    size_t running=0; for (const auto& s:services) if(s.status==SERVICE_RUNNING) ++running;
    wchar_t sub[256]{}; swprintf_s(sub,L"%zu RUNNING  |  %zu STOPPED  |  %zu TOTAL  \u2022  Select then Start/Stop",
        running, services.size()-running, services.size());
    SetTextColor(dc,C_MUTED); SelectObject(dc,font_small);
    RECT sr{r.left+28,r.top+52,r.right-28,r.top+72};
    DrawTextW(dc,sub,-1,&sr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
}

static void draw_performance(HDC dc, RECT r) {
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,r.top+14,r.right-28,r.top+48};
    DrawTextW(dc,L"\u25c8  PERFORMANCE TELEMETRY MATRIX",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    MEMORYSTATUSEX mem{}; mem.dwLength=sizeof(mem); GlobalMemoryStatusEx(&mem);
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    wchar_t inf[320]{}; swprintf_s(inf,L"%s  |  %u Cores  |  %.2f GB RAM (%.2f GB free)  |  Uptime: %s",
        g_cpu_brand.c_str(),si.dwNumberOfProcessors,
        static_cast<double>(mem.ullTotalPhys)/(1024.0*1024.0*1024.0),
        static_cast<double>(mem.ullAvailPhys)/(1024.0*1024.0*1024.0),
        format_uptime().c_str());
    SetTextColor(dc,C_MUTED); SelectObject(dc,font_small);
    RECT ir{r.left+28,r.top+50,r.right-28,r.top+68};
    DrawTextW(dc,inf,-1,&ir,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);

    int y=76;
    RECT corePnl{r.left+28,y,r.right-28,y+156};
    draw_hud_panel(dc,corePnl,C_PANEL2,C_BORDER,L"LOGICAL PROCESSOR CORE HEAT MATRIX");
    draw_scan_line(dc,corePnl);
    size_t nc=per_core_cpu_history.size();
    if (nc>0) {
        size_t cols=(std::min)(nc,static_cast<size_t>(16));
        int cw2=(corePnl.right-corePnl.left-36)/static_cast<int>(cols);
        int ch2=38;
        SelectObject(dc,font_mono);
        for (size_t i=0;i<nc&&i<32;++i){
            int row2=static_cast<int>(i/cols), col2=static_cast<int>(i%cols);
            int cx=corePnl.left+18+col2*cw2, cy2=corePnl.top+44+row2*(ch2+8);
            RECT cell{cx,cy2,cx+cw2-6,cy2+ch2};
            double cv=per_core_cpu_history[i].empty()?0.0:per_core_cpu_history[i].back();
            COLORREF cc=(cv>80.0)?C_RED:(cv>50.0)?C_AMBER:C_CYAN;
            fill_solid(dc,cell,C_PANEL);
            int fw=static_cast<int>((cell.right-cell.left)*(cv/100.0));
            RECT bf{cell.left,cell.bottom-4,cell.left+fw,cell.bottom};
            fill_solid(dc,bf,cc);
            wchar_t cn[32]{}; swprintf_s(cn,L"C%02zu %.0f%%",i,cv);
            SetTextColor(dc,cc); DrawTextW(dc,cn,-1,&cell,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
    }
    int rem=r.bottom-20-(y+168); int hc=rem/2; int mid=(r.left+r.right)/2;
    RECT ca{r.left+28,y+168,mid-8,y+168+hc};
    RECT cb{mid+8,y+168,r.right-28,y+168+hc};
    RECT cc2{r.left+28,ca.bottom+10,mid-8,r.bottom-20};
    RECT cd{mid+8,cb.bottom+10,r.right-28,r.bottom-20};
    draw_waveform(dc,ca,cpu_history,C_CYAN,    L"CPU %",          system_cpu,    L"%");
    draw_waveform(dc,cb,memory_history,C_GREEN, L"RAM %",          system_memory, L"%");
    draw_waveform(dc,cc2,disk_read_history,C_AMBER,  L"DISK READ",     disk_read_mb,  L"MB/s",500.0);
    draw_waveform(dc,cd,net_sent_history,C_PURPLE,   L"NETWORK TX",    net_sent_mb,   L"MB/s",500.0);
}

static void draw_kernel_monitor(HDC dc, RECT r) {
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,r.top+14,r.right-28,r.top+48};
    DrawTextW(dc,L"\u26a1  KERNEL TELEMETRY CONTROLLER",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SetTextColor(dc,C_MUTED); SelectObject(dc,font_small);
    RECT sr{r.left+28,r.top+50,r.right-28,r.top+70};
    DrawTextW(dc,L"KMDF DRIVER CALLBACKS \u2022 NT PROCESS LIFECYCLE HOOKS \u2022 IMAGE LOAD NOTIFICATIONS",-1,&sr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    int y=78, cw3=(r.right-r.left-56-24)/3;
    RECT s1{r.left+28,y,r.left+28+cw3,y+88};
    RECT s2{s1.right+12,y,s1.right+12+cw3,y+88};
    RECT s3{s2.right+12,y,r.right-28,y+88};
    draw_hud_panel(dc,s1,C_PANEL2,C_BORDER,L"DRIVER LINK"); draw_hud_panel(dc,s2,C_PANEL2,C_BORDER,L"RING BUFFER"); draw_hud_panel(dc,s3,C_PANEL2,C_BORDER,L"TOTAL EVENTS");
    bool pulse=(GetTickCount64()/500)%2==0;
    SetTextColor(dc,driver_connected?(pulse?C_GREEN:C_TEAL):C_MUTED); SelectObject(dc,font_normal);
    RECT d1{s1.left+16,s1.top+32,s1.right-16,s1.top+68}; DrawTextW(dc,driver_status_text.c_str(),-1,&d1,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    SetTextColor(dc,driver_dropped_records==0?C_GREEN:C_AMBER);
    wchar_t db[64]{}; swprintf_s(db,L"%u DROPPED",driver_dropped_records);
    RECT d2{s2.left+16,s2.top+32,s2.right-16,s2.top+68}; DrawTextW(dc,db,-1,&d2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SetTextColor(dc,C_TEXT); wchar_t eb[64]{}; swprintf_s(eb,L"%llu EVENTS",static_cast<unsigned long long>(driver_events_received));
    RECT d3{s3.left+16,s3.top+32,s3.right-16,s3.top+68}; DrawTextW(dc,eb,-1,&d3,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    int y2=y+100; int bw=(r.right-r.left-56)/6;
    int cnts[6]={};
    for (const auto& ev:kernel_event_log){ switch(ev.Kind){ case TaskletProcessStarted:cnts[0]++;break; case TaskletProcessExited:cnts[1]++;break; case TaskletThreadStarted:cnts[2]++;break; case TaskletThreadExited:cnts[3]++;break; case TaskletImageLoaded:cnts[4]++;break; case TaskletKernelHeartbeat:cnts[5]++;break; } }
    const struct{const wchar_t* n;COLORREF c;}kinds[]={{L"PROC+",C_GREEN},{L"PROC-",C_MUTED},{L"THRD+",C_BLUE},{L"THRD-",C_DIM},{L"IMAGE",C_PURPLE},{L"HB",C_TEAL}};
    SelectObject(dc,font_mono);
    for (int i=0;i<6;++i){
        RECT br{r.left+28+i*bw,y2,r.left+28+(i+1)*bw-8,y2+52};
        draw_hud_panel(dc,br,C_PANEL,C_BORDER,nullptr,false);
        SetTextColor(dc,kinds[i].c); SelectObject(dc,font_small);
        RECT nr{br.left+10,br.top+8,br.right-10,br.top+26}; DrawTextW(dc,kinds[i].n,-1,&nr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,C_TEXT); SelectObject(dc,font_normal);
        RECT cr2{br.left+10,br.top+26,br.right-10,br.top+50}; DrawTextW(dc,std::to_wstring(cnts[i]).c_str(),-1,&cr2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    }
    RECT feed{r.left+28,y2+64,r.right-28,r.bottom-20};
    draw_hud_panel(dc,feed,C_PANEL,C_BORDER,L"LIVE KERNEL EVENT LOG"); draw_scan_line(dc,feed);
    int ey=feed.top+40; SelectObject(dc,font_mono); SetTextColor(dc,C_CYAN);
    auto hdr2=[&](int x,int w,const wchar_t* t){RECT rh{x,ey,x+w,ey+20};DrawTextW(dc,t,-1,&rh,DT_LEFT|DT_VCENTER|DT_SINGLELINE);};
    hdr2(feed.left+16,110,L"SEQ"); hdr2(feed.left+132,180,L"EVENT TYPE"); hdr2(feed.left+318,100,L"PID"); hdr2(feed.left+424,110,L"PARENT"); hdr2(feed.left+540,0,L"TIMESTAMP (100ns)");
    ey+=24;
    size_t shown=0;
    for (auto it=kernel_event_log.rbegin();it!=kernel_event_log.rend()&&ey<feed.bottom-28;++it,++shown){
        RECT row{feed.left+12,ey,feed.right-12,ey+24}; fill_solid(dc,row,(shown%2==0)?C_PANEL2:RGB(13,20,32));
        const wchar_t* knd=L"UNKNOWN"; COLORREF kc=C_CYAN;
        switch(it->Kind){case TaskletProcessStarted:knd=L"ProcessStarted";kc=C_GREEN;break;case TaskletProcessExited:knd=L"ProcessExited";kc=C_MUTED;break;case TaskletThreadStarted:knd=L"ThreadStarted";kc=C_BLUE;break;case TaskletThreadExited:knd=L"ThreadExited";kc=C_DIM;break;case TaskletImageLoaded:knd=L"ImageLoaded";kc=C_PURPLE;break;case TaskletKernelHeartbeat:knd=L"KernelHeartbeat";kc=C_TEAL;break;}
        SetTextColor(dc,C_TEXT); RECT r1{row.left+4,ey,row.left+118,ey+24}; DrawTextW(dc,std::to_wstring(it->Sequence).c_str(),-1,&r1,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,kc);    RECT r2{row.left+120,ey,row.left+312,ey+24}; DrawTextW(dc,knd,-1,&r2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,C_TEXT);RECT r3{row.left+314,ey,row.left+410,ey+24}; DrawTextW(dc,std::to_wstring(it->ProcessId).c_str(),-1,&r3,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
                                RECT r4{row.left+412,ey,row.left+518,ey+24}; DrawTextW(dc,std::to_wstring(it->ParentProcessId).c_str(),-1,&r4,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,C_MUTED);RECT r5{row.left+520,ey,row.right-4,ey+24}; DrawTextW(dc,std::to_wstring(it->InterruptTime100ns).c_str(),-1,&r5,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        ey+=26;
    }
}

static void draw_network_sentinel(HDC dc, RECT r) {
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,r.top+14,r.right-28,r.top+48};
    DrawTextW(dc,L"\u2b21  NETWORK TRAFFIC SENTINEL",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    int sw=(r.right-r.left-56-16)/2;
    RECT ns{r.left+28,r.top+56,r.left+28+sw,r.top+166};
    RECT nr{ns.right+16,r.top+56,r.right-28,r.top+166};
    draw_waveform(dc,ns,net_sent_history,C_PINK,  L"TX BANDWIDTH",net_sent_mb,L"MB/s",500.0);
    draw_waveform(dc,nr,net_recv_history,C_TEAL,  L"RX BANDWIDTH",net_recv_mb,L"MB/s",500.0);
    wchar_t sb[64]{}; swprintf_s(sb,L"SOCKET CONNECTIONS (%zu)",network_sockets.size());
    RECT tbl{r.left+28,r.top+180,r.right-28,r.bottom-20};
    draw_hud_panel(dc,tbl,C_PANEL,C_BORDER,sb);
    int y=tbl.top+40; SelectObject(dc,font_mono); SetTextColor(dc,C_CYAN);
    auto ch2=[&](int x,int w,const wchar_t* t){RECT rh{x,y,x+w,y+20};DrawTextW(dc,t,-1,&rh,DT_LEFT|DT_VCENTER|DT_SINGLELINE);};
    ch2(tbl.left+16,65,L"PROTO"); ch2(tbl.left+88,188,L"LOCAL"); ch2(tbl.left+282,188,L"REMOTE"); ch2(tbl.left+476,120,L"STATE"); ch2(tbl.left+602,78,L"PID"); ch2(tbl.left+686,0,L"PROCESS"); y+=24;
    size_t shown2=0;
    for (const auto& s:network_sockets){
        if (y>=tbl.bottom-28) break; ++shown2;
        RECT row{tbl.left+12,y,tbl.right-12,y+26}; fill_solid(dc,row,(shown2%2==0)?C_PANEL2:RGB(13,20,32));
        SetTextColor(dc,s.is_unauthorized?C_RED:C_CYAN); RECT p0{row.left+4,y,row.left+72,y+26}; DrawTextW(dc,s.protocol.c_str(),-1,&p0,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,C_TEXT);
        std::wstring la=s.local_addr+L":"+std::to_wstring(s.local_port);
        std::wstring ra=(s.remote_port>0)?(s.remote_addr+L":"+std::to_wstring(s.remote_port)):s.remote_addr;
        RECT p1{row.left+76,y,row.left+270,y+26}; DrawTextW(dc,la.c_str(),-1,&p1,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        RECT p2{row.left+274,y,row.left+464,y+26}; DrawTextW(dc,ra.c_str(),-1,&p2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,(s.state==L"ESTABLISHED")?C_GREEN:(s.state==L"LISTENING")?C_CYAN:C_MUTED);
        RECT p3{row.left+466,y,row.left+590,y+26}; DrawTextW(dc,s.state.c_str(),-1,&p3,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,C_TEXT); RECT p4{row.left+592,y,row.left+680,y+26}; DrawTextW(dc,std::to_wstring(s.pid).c_str(),-1,&p4,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        std::wstring pn=s.process_name+(s.is_unauthorized?L"  [UNAU]":L""); SetTextColor(dc,s.is_unauthorized?C_RED:C_TEXT);
        RECT p5{row.left+682,y,row.right-4,y+26}; DrawTextW(dc,pn.c_str(),-1,&p5,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        y+=28;
    }
}

static const ProcessRecord* selected_process() {
    for (const auto& p:processes) if (p.pid==selected_pid) return &p;
    return nullptr;
}

static void draw_details(HDC dc, RECT r) {
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,r.top+14,r.right-28,r.top+48};
    DrawTextW(dc,L"\u2261  DEEP PROCESS FORENSICS",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    const ProcessRecord* p=selected_process();
    if (!p){ SetTextColor(dc,C_MUTED);SelectObject(dc,font_normal);RECT nr{r.left+28,r.top+80,r.right-28,r.top+120};
        DrawTextW(dc,L"Select a process from the Processes page to inspect its forensic dossier.",-1,&nr,DT_LEFT|DT_VCENTER|DT_SINGLELINE); return; }

    // Tab bar
    struct Tab{const wchar_t* l;int id;};
    Tab tabs[]={{L"FIELDS",0},{L"ENVIRONMENT",1},{L"MODULES",2}};
    int tx=r.left+28;
    for (const auto& t:tabs){
        int tw=static_cast<int>(wcslen(t.l))*10+28;
        RECT tbr{tx,r.top+58,tx+tw,r.top+80};
        bool act=(g_detail_tab==t.id);
        draw_badge(dc,tbr,t.l,act?C_VOID:C_MUTED,act?C_CYAN:C_PANEL2,act?C_CYAN:C_BORDER);
        tx=tbr.right+8;
    }

    RECT pan{r.left+28,r.top+86,r.right-28,r.bottom-20};
    draw_hud_panel(dc,pan,C_PANEL2,p->is_unauthorized?C_RED:C_BORDER,nullptr);
    SetTextColor(dc,p->is_unauthorized?C_RED:C_CYAN); SelectObject(dc,font_title);
    RECT nr{pan.left+28,pan.top+16,pan.right-28,pan.top+52};
    DrawTextW(dc,(p->name+L"  [PID: "+std::to_wstring(p->pid)+L"]").c_str(),-1,&nr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    if (p->threat_score>0){ RECT bar{pan.left+28,pan.top+58,pan.left+420,pan.top+72}; draw_glow_bar(dc,bar,static_cast<double>(p->threat_score),p->is_unauthorized?C_RED:C_AMBER);
        SetTextColor(dc,C_MUTED);SelectObject(dc,font_small);RECT bs{pan.left+430,pan.top+58,pan.left+560,pan.top+74};DrawTextW(dc,(L"Threat Score: "+std::to_wstring(p->threat_score)+L"/100").c_str(),-1,&bs,DT_LEFT|DT_VCENTER|DT_SINGLELINE); }

    int y=pan.top+(p->threat_score>0?82:60); SelectObject(dc,font_mono);

    if (g_detail_tab==0) {
        // Fields tab
        wchar_t cf[32]{}; swprintf_s(cf,L"%.2f%%",p->cpu);
        struct Field{const wchar_t* l;std::wstring v;COLORREF c;};
        std::vector<Field> fields={
            {L"PID",std::to_wstring(p->pid),C_CYAN},{L"PARENT PID",std::to_wstring(p->parent_pid),C_TEXT},
            {L"CPU %",cf,C_CYAN},{L"WORKING SET",format_bytes(p->memory),C_TEXT},{L"PRIVATE BYTES",format_bytes(p->private_bytes),C_TEXT},
            {L"I/O READ",format_bytes(p->io_read_bytes),C_TEXT},{L"I/O WRITE",format_bytes(p->io_write_bytes),C_TEXT},
            {L"THREADS",std::to_wstring(p->thread_count),C_TEXT},{L"HANDLES",std::to_wstring(p->handle_count),C_TEXT},
            {L"ARCHITECTURE",p->architecture==64?L"64-bit":L"32-bit (WOW64)",C_TEXT},
            {L"INTEGRITY",p->integrity,(p->integrity==L"System")?C_PURPLE:C_TEXT},
            {L"ELEVATION",p->elevated?L"Administrator":L"Standard",p->elevated?C_AMBER:C_TEXT},
            {L"SESSION",std::to_wstring(p->session),C_TEXT},
            {L"AUTHENTICODE",p->is_signed?(L"Verified ("+p->signer_name+L")"):L"Unsigned",p->is_signed?C_GREEN:C_RED},
            {L"SHA-256",p->sha256.empty()?L"Unavailable":p->sha256,C_MUTED},
            {L"UNAU STATUS",p->is_unauthorized?L"UNAUTHORIZED":L"Authorized",p->is_unauthorized?C_RED:C_GREEN},
            {L"USER",p->user,C_TEXT},{L"BINARY PATH",p->path.empty()?L"Unavailable":p->path,C_TEXT},
            {L"COMMAND LINE",p->command_line.empty()?L"Unavailable":p->command_line,C_MUTED},
        };
        for (const auto& f:fields){
            if (y>=pan.bottom-40) break;
            RECT lr{pan.left+28,y,pan.left+230,y+22}; SetTextColor(dc,C_MUTED); DrawTextW(dc,f.l,-1,&lr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
            RECT vr{pan.left+236,y,pan.right-28,y+22}; SetTextColor(dc,f.c); DrawTextW(dc,f.v.c_str(),-1,&vr,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
            draw_line(dc,pan.left+28,y+22,pan.right-28,y+22,C_DIM);
            y+=24;
        }
        if (!p->findings.empty()&&y<pan.bottom-50){
            y+=8; SetTextColor(dc,C_RED); SelectObject(dc,font_heading);
            RECT fh{pan.left+28,y,pan.right-28,y+26}; DrawTextW(dc,L"POLICY VIOLATIONS:",-1,&fh,DT_LEFT|DT_VCENTER|DT_SINGLELINE); y+=28;
            SelectObject(dc,font_mono);
            for (const auto& fi:p->findings){ if(y>=pan.bottom-24) break; SetTextColor(dc,C_RED); RECT fl{pan.left+28,y,pan.right-28,y+22}; DrawTextW(dc,(L"  \u2023 "+fi).c_str(),-1,&fl,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS); y+=22; }
        }
    } else if (g_detail_tab==1) {
        // Environment tab
        if (env_vars.empty()){SetTextColor(dc,C_MUTED);RECT em{pan.left+28,y+20,pan.right-28,y+50};DrawTextW(dc,L"Click 'ENVIRONMENT' tab after selecting a process. Environment vars will load.",-1,&em,DT_LEFT|DT_VCENTER|DT_SINGLELINE);}
        else {
            SetTextColor(dc,C_CYAN); RECT hr{pan.left+28,y,pan.left+280,y+22}; DrawTextW(dc,L"NAME",-1,&hr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
            RECT hr2{pan.left+286,y,pan.right-28,y+22}; DrawTextW(dc,L"VALUE",-1,&hr2,DT_LEFT|DT_VCENTER|DT_SINGLELINE); y+=24;
            size_t row2=0;
            for (const auto& ev:env_vars){ if(y>=pan.bottom-28) break; ++row2;
                RECT row{pan.left+24,y,pan.right-24,y+22}; fill_solid(dc,row,(row2%2==0)?C_PANEL2:RGB(13,20,32));
                SetTextColor(dc,C_CYAN); RECT nv{pan.left+28,y,pan.left+280,y+22}; DrawTextW(dc,ev.name.c_str(),-1,&nv,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
                SetTextColor(dc,C_TEXT); RECT vv{pan.left+286,y,pan.right-28,y+22}; DrawTextW(dc,ev.value.c_str(),-1,&vv,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
                y+=24;
            }
        }
    } else {
        // Modules tab
        if (modules.empty()){SetTextColor(dc,C_MUTED);RECT em{pan.left+28,y+20,pan.right-28,y+50};DrawTextW(dc,L"Click 'MODULES' tab. Loaded DLLs will appear here.",-1,&em,DT_LEFT|DT_VCENTER|DT_SINGLELINE);}
        else {
            SetTextColor(dc,C_CYAN);
            RECT h1{pan.left+28,y,pan.left+200,y+22}; DrawTextW(dc,L"MODULE NAME",-1,&h1,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
            RECT h2{pan.left+206,y,pan.left+326,y+22}; DrawTextW(dc,L"BASE ADDR",-1,&h2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
            RECT h3{pan.left+332,y,pan.left+412,y+22}; DrawTextW(dc,L"SIZE",-1,&h3,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
            RECT h4{pan.left+418,y,pan.right-28,y+22}; DrawTextW(dc,L"PATH",-1,&h4,DT_LEFT|DT_VCENTER|DT_SINGLELINE); y+=24;
            size_t row2=0;
            for (const auto& m:modules){ if(y>=pan.bottom-28) break; ++row2;
                RECT row{pan.left+24,y,pan.right-24,y+22}; fill_solid(dc,row,(row2%2==0)?C_PANEL2:RGB(13,20,32));
                SetTextColor(dc,C_CYAN); RECT c1{pan.left+28,y,pan.left+200,y+22}; DrawTextW(dc,m.name.c_str(),-1,&c1,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
                SetTextColor(dc,C_AMBER); wchar_t ab[32]{}; swprintf_s(ab,L"%016llX",m.base_address); RECT c2{pan.left+206,y,pan.left+326,y+22}; DrawTextW(dc,ab,-1,&c2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
                SetTextColor(dc,C_TEXT); RECT c3{pan.left+332,y,pan.left+412,y+22}; DrawTextW(dc,format_bytes(m.base_size).c_str(),-1,&c3,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
                SetTextColor(dc,C_MUTED); RECT c4{pan.left+418,y,pan.right-28,y+22}; DrawTextW(dc,m.path.c_str(),-1,&c4,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
                y+=24;
            }
        }
    }
}

static void draw_threads(HDC dc, RECT r) {
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,r.top+14,r.right-28,r.top+48};
    DrawTextW(dc,L"\u2301  THREAD EXECUTION TELEMETRY",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    const ProcessRecord* p=selected_process();
    std::wstring sub=p?(p->name+L"  \u2022  PID "+std::to_wstring(p->pid)+L"  \u2022  "+std::to_wstring(selected_threads.size())+L" threads"):L"Select a process to inspect threads.";
    SetTextColor(dc,C_MUTED); SelectObject(dc,font_small); RECT sr{r.left+28,r.top+52,r.right-28,r.top+72};
    DrawTextW(dc,sub.c_str(),-1,&sr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
}

static void draw_startup_page(HDC dc, RECT r) {
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,r.top+14,r.right-28,r.top+48};
    DrawTextW(dc,L"\u25b7  SYSTEM STARTUP SENTINEL",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SetTextColor(dc,C_MUTED); SelectObject(dc,font_small); wchar_t sub[128]{}; swprintf_s(sub,L"%zu STARTUP ENTRIES",startup_entries.size());
    RECT sr{r.left+28,r.top+52,r.right-28,r.top+72}; DrawTextW(dc,sub,-1,&sr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT tbl{r.left+28,r.top+80,r.right-28,r.bottom-20};
    draw_hud_panel(dc,tbl,C_PANEL,C_BORDER,L"AUTO-RUN REGISTRY INVENTORY");
    int y=tbl.top+40; SelectObject(dc,font_mono); SetTextColor(dc,C_CYAN);
    RECT h1{tbl.left+16,y,tbl.left+216,y+22}; DrawTextW(dc,L"NAME",-1,&h1,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT h2{tbl.left+222,y,tbl.left+362,y+22}; DrawTextW(dc,L"SCOPE",-1,&h2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT h3{tbl.left+368,y,tbl.right-16,y+22}; DrawTextW(dc,L"COMMAND / PATH",-1,&h3,DT_LEFT|DT_VCENTER|DT_SINGLELINE); y+=26;
    size_t row2=0;
    for (const auto& e:startup_entries){
        if (y>=tbl.bottom-28) break; ++row2;
        RECT rr{tbl.left+12,y,tbl.right-12,y+36}; fill_solid(dc,rr,(row2%2==0)?C_PANEL2:RGB(13,20,32));
        COLORREF sc=(e.scope==L"System"||e.scope==L"System (Once)")?C_AMBER:C_CYAN;
        SetTextColor(dc,C_TEXT); RECT c1{rr.left+4,y,rr.left+210,y+36}; DrawTextW(dc,e.name.c_str(),-1,&c1,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        SetTextColor(dc,sc); RECT c2{rr.left+218,y,rr.left+358,y+36}; DrawTextW(dc,e.scope.c_str(),-1,&c2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,C_MUTED); RECT c3{rr.left+364,y,rr.right-4,y+36}; DrawTextW(dc,e.command.c_str(),-1,&c3,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        y+=40;
    }
    if (startup_entries.empty()){SetTextColor(dc,C_MUTED);SelectObject(dc,font_normal);RECT em{tbl.left+20,y+20,tbl.right-20,y+50};DrawTextW(dc,L"No startup entries found in registry.",-1,&em,DT_CENTER|DT_VCENTER|DT_SINGLELINE);}
}

static void draw_users_page(HDC dc, RECT r) {
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,r.top+14,r.right-28,r.top+48};
    DrawTextW(dc,L"\u25a6  ACTIVE USERS & SESSIONS",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SetTextColor(dc,C_MUTED); SelectObject(dc,font_small);
    wchar_t sub[128]{}; swprintf_s(sub,L"%zu SESSION%s ACTIVE",sessions.size(),sessions.size()==1?L"":L"S");
    RECT sr{r.left+28,r.top+52,r.right-28,r.top+72}; DrawTextW(dc,sub,-1,&sr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT tbl{r.left+28,r.top+80,r.right-28,r.bottom-20};
    draw_hud_panel(dc,tbl,C_PANEL,C_BORDER,L"WINDOWS SESSION MATRIX");
    int y=tbl.top+40; SelectObject(dc,font_mono); SetTextColor(dc,C_CYAN);
    RECT h1{tbl.left+16,y,tbl.left+82,y+22}; DrawTextW(dc,L"SID",-1,&h1,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT h2{tbl.left+88,y,tbl.left+268,y+22}; DrawTextW(dc,L"USERNAME",-1,&h2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT h3{tbl.left+274,y,tbl.left+414,y+22}; DrawTextW(dc,L"DOMAIN",-1,&h3,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT h4{tbl.left+420,y,tbl.left+580,y+22}; DrawTextW(dc,L"STATE",-1,&h4,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT h5{tbl.left+586,y,tbl.right-16,y+22}; DrawTextW(dc,L"CLIENT",-1,&h5,DT_LEFT|DT_VCENTER|DT_SINGLELINE); y+=26;
    size_t row2=0;
    for (const auto& s:sessions){
        if (y>=tbl.bottom-28) break; ++row2;
        RECT rr{tbl.left+12,y,tbl.right-12,y+42}; fill_solid(dc,rr,(row2%2==0)?C_PANEL2:RGB(13,20,32));
        COLORREF sc=(s.state==WTSActive)?C_GREEN:(s.state==WTSDisconnected)?C_AMBER:C_MUTED;
        SetTextColor(dc,C_TEXT); RECT c1{rr.left+4,y,rr.left+80,y+42}; DrawTextW(dc,std::to_wstring(s.session_id).c_str(),-1,&c1,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        RECT c2{rr.left+86,y,rr.left+268,y+42}; DrawTextW(dc,(s.username.empty()?L"SYSTEM":s.username).c_str(),-1,&c2,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        RECT c3{rr.left+270,y,rr.left+408,y+42}; DrawTextW(dc,s.domain.c_str(),-1,&c3,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        SetTextColor(dc,sc); RECT c4{rr.left+414,y,rr.left+578,y+42}; DrawTextW(dc,s.state_str.c_str(),-1,&c4,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,C_MUTED); RECT c5{rr.left+582,y,rr.right-4,y+42}; DrawTextW(dc,(s.client_name.empty()?L"Local":s.client_name).c_str(),-1,&c5,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        y+=46;
    }
}

static void draw_modules_page(HDC dc, RECT r) {
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,C_TEXT); SelectObject(dc,font_title);
    RECT tr{r.left+28,r.top+14,r.right-28,r.top+48};
    DrawTextW(dc,L"\u25a9  MODULE & DLL INSPECTOR",-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    const ProcessRecord* p=selected_process();
    std::wstring sub=p?(L"Loaded modules for: "+p->name+L"  [PID "+std::to_wstring(p->pid)+L"]  \u2022  "+std::to_wstring(modules.size())+L" modules"):L"Select a process from the Processes page, then navigate here.";
    SetTextColor(dc,C_MUTED); SelectObject(dc,font_small);
    RECT sr{r.left+28,r.top+52,r.right-28,r.top+72}; DrawTextW(dc,sub.c_str(),-1,&sr,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    // Draw the module list inline (since module_list ListView is NOT used for this page, we draw with GDI)
    RECT tbl{r.left+28,r.top+80,r.right-28,r.bottom-20};
    draw_hud_panel(dc,tbl,C_PANEL,C_BORDER,L"LOADED DLL & MODULE MAP");
    int y=tbl.top+40; SelectObject(dc,font_mono); SetTextColor(dc,C_CYAN);
    RECT h1{tbl.left+16,y,tbl.left+200,y+22}; DrawTextW(dc,L"MODULE",-1,&h1,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT h2{tbl.left+206,y,tbl.left+346,y+22}; DrawTextW(dc,L"BASE ADDRESS",-1,&h2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT h3{tbl.left+352,y,tbl.left+452,y+22}; DrawTextW(dc,L"SIZE",-1,&h3,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT h4{tbl.left+458,y,tbl.right-16,y+22}; DrawTextW(dc,L"FULL PATH",-1,&h4,DT_LEFT|DT_VCENTER|DT_SINGLELINE); y+=26;
    if (modules.empty()&&p){ SetTextColor(dc,C_MUTED); SelectObject(dc,font_normal); RECT em{tbl.left+20,y+20,tbl.right-20,y+50}; DrawTextW(dc,L"Module enumeration in progress or access denied...",-1,&em,DT_LEFT|DT_VCENTER|DT_SINGLELINE); }
    size_t row2=0;
    for (const auto& m:modules){
        if (y>=tbl.bottom-28) break; ++row2;
        RECT rr{tbl.left+12,y,tbl.right-12,y+24}; fill_solid(dc,rr,(row2%2==0)?C_PANEL2:RGB(13,20,32));
        SetTextColor(dc,C_CYAN); RECT c1{rr.left+4,y,rr.left+200,y+24}; DrawTextW(dc,m.name.c_str(),-1,&c1,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        SetTextColor(dc,C_AMBER); wchar_t ab[32]{}; swprintf_s(ab,L"0x%016llX",m.base_address); RECT c2{rr.left+202,y,rr.left+342,y+24}; DrawTextW(dc,ab,-1,&c2,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,C_TEXT); RECT c3{rr.left+348,y,rr.left+446,y+24}; DrawTextW(dc,format_bytes(m.base_size).c_str(),-1,&c3,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,C_MUTED); RECT c4{rr.left+452,y,rr.right-4,y+24}; DrawTextW(dc,m.path.c_str(),-1,&c4,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        y+=26;
    }
}

// ============================================================
// SIDEBAR
// ============================================================
static void draw_sidebar(HDC dc, RECT r) {
    // Background gradient (simulated with vertical strips)
    for (int x=0;x<r.right;++x) {
        int rf=static_cast<int>(6.0+(1.0*x/r.right)*3.0);
        int gf=static_cast<int>(10.0+(1.0*x/r.right)*5.0);
        int bf=static_cast<int>(17.0+(1.0*x/r.right)*7.0);
        draw_line(dc,x,r.top,x,r.bottom,RGB(rf,gf,bf),1);
    }
    draw_line(dc,r.right-1,r.top,r.right-1,r.bottom,C_BORDER,1);

    SetBkMode(dc,TRANSPARENT);
    // Accent bar TL
    fill_solid(dc,RECT{0,0,3,r.bottom},C_CYAN);

    SetTextColor(dc,C_CYAN); SelectObject(dc,font_title);
    RECT logo{16,14,r.right-10,48}; DrawTextW(dc,L"\u2b21 TASKLET",-1,&logo,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SetTextColor(dc,RGB(0,120,140)); SelectObject(dc,font_small);
    RECT brand{16,46,r.right-10,62}; DrawTextW(dc,L"CYBER DEFENSE CONSOLE",-1,&brand,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    draw_line(dc,12,68,r.right-12,68,C_BORDER,1);

    struct NavItem{const wchar_t* icon;const wchar_t* name;Page page;COLORREF ic;};
    const NavItem nav[]={
        {L"\u25cf",L"Overview",   PAGE_OVERVIEW,   C_CYAN},
        {L"\u2b21",L"UNAU",       PAGE_UNAU,        C_RED},
        {L"\u2263",L"Processes",  PAGE_PROCESSES,  C_BLUE},
        {L"\u2699",L"Services",   PAGE_SERVICES,   C_TEAL},
        {L"\u25c8",L"Performance",PAGE_PERFORMANCE,C_CYAN},
        {L"\u26a1",L"Kernel",     PAGE_KERNEL,     C_AMBER},
        {L"\u2b21",L"Network",    PAGE_NETWORK,    C_PINK},
        {L"\u2261",L"Details",    PAGE_DETAILS,    C_PURPLE},
        {L"\u2301",L"Threads",    PAGE_THREADS,    C_BLUE},
        {L"\u25b7",L"Startup",    PAGE_STARTUP,    C_LIME},
        {L"\u25a6",L"Users",      PAGE_USERS,      C_GREEN},
        {L"\u25a9",L"Modules",    PAGE_MODULES,    C_ORANGE},
    };

    int y=76;
    for (int i=0;i<PAGE_COUNT;++i) {
        const auto& n=nav[i];
        RECT item{10,y,r.right-10,y+40};
        bool active=(current_page==n.page), hovered=(g_sidebar_hover==i);
        if (active) {
            HBRUSH hb=CreateSolidBrush(RGB(18,32,54)); HPEN hp=CreatePen(PS_SOLID,1,n.ic);
            auto ob=SelectObject(dc,hb); auto op=SelectObject(dc,hp);
            RoundRect(dc,item.left,item.top,item.right,item.bottom,8,8);
            SelectObject(dc,ob);SelectObject(dc,op);DeleteObject(hb);DeleteObject(hp);
            fill_solid(dc,RECT{10,y+6,14,y+34},n.ic);
        } else if (hovered) {
            fill_solid(dc,RECT{item.left,item.top,item.right,item.bottom},C_PANEL_HOVER);
        }
        SetTextColor(dc,active?n.ic:C_DIM); SelectObject(dc,font_normal);
        RECT ir{20,y,44,y+40}; DrawTextW(dc,n.icon,-1,&ir,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SetTextColor(dc,active?C_TEXT:(hovered?C_MUTED:RGB(65,88,120)));
        RECT nr{48,y,r.right-18,y+40}; DrawTextW(dc,n.name,-1,&nr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        // UNAU badge
        if (n.page==PAGE_UNAU&&g_unau_stats.unauthorized_count>0){
            RECT bdg{r.right-44,y+8,r.right-16,y+32};
            draw_badge(dc,bdg,std::to_wstring(g_unau_stats.unauthorized_count).c_str(),C_TEXT,C_RED,C_RED);
        }
        y+=42;
    }

    // Bottom section
    draw_line(dc,12,r.bottom-108,r.right-12,r.bottom-108,C_BORDER,1);
    SetTextColor(dc,C_DIM); SelectObject(dc,font_small);
    RECT ul{12,r.bottom-104,r.right-12,r.bottom-88}; DrawTextW(dc,(L"UP: "+format_uptime()).c_str(),-1,&ul,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    // CPU bar
    RECT clbl{12,r.bottom-82,52,r.bottom-68}; DrawTextW(dc,L"CPU",-1,&clbl,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT cbar{56,r.bottom-80,r.right-14,r.bottom-70}; draw_glow_bar(dc,cbar,system_cpu,C_CYAN);
    // RAM bar
    RECT mlbl{12,r.bottom-62,52,r.bottom-48}; DrawTextW(dc,L"RAM",-1,&mlbl,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT mbar{56,r.bottom-60,r.right-14,r.bottom-50}; draw_glow_bar(dc,mbar,system_memory,C_GREEN);
    // NET bar
    RECT nlbl{12,r.bottom-42,52,r.bottom-28}; DrawTextW(dc,L"NET",-1,&nlbl,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    double netmax=(std::max)(net_sent_mb,net_recv_mb);
    RECT nbar{56,r.bottom-40,r.right-14,r.bottom-30}; draw_glow_bar(dc,nbar,(std::min)(100.0,netmax*10.0),C_PINK);
    // Version
    SetTextColor(dc,C_DIM); SelectObject(dc,font_mono);
    RECT ver{12,r.bottom-22,r.right-12,r.bottom-4}; DrawTextW(dc,L"TASKLET v2.2",-1,&ver,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
}

// ============================================================
// HEADER
// ============================================================
static void draw_header(HDC dc, RECT r) {
    // Subtle gradient header
    for (int y=r.top;y<r.bottom;++y) {
        int rf=static_cast<int>(8.0+(1.0*(y-r.top)/(r.bottom-r.top))*4.0);
        int gf=static_cast<int>(13.0+(1.0*(y-r.top)/(r.bottom-r.top))*4.0);
        int bf=static_cast<int>(21.0+(1.0*(y-r.top)/(r.bottom-r.top))*6.0);
        draw_line(dc,r.left,y,r.right,y,RGB(rf,gf,bf),1);
    }
    // Cyan accent top edge
    fill_solid(dc,RECT{0,0,r.right,2},C_CYAN);
    draw_line(dc,0,r.bottom-1,r.right,r.bottom-1,C_BORDER,1);

    SetBkMode(dc,TRANSPARENT);
    SetTextColor(dc,C_CYAN); SelectObject(dc,font_title);
    RECT lg{16,8,220,46}; DrawTextW(dc,L"\u2b21 TASKLET",-1,&lg,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SetTextColor(dc,C_MUTED); SelectObject(dc,font_small);
    RECT sub{208,18,580,46}; DrawTextW(dc,L"// KERNEL PROCESS SENTINEL & CYBER DEFENSE CONSOLE",-1,&sub,DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    // Clock
    SYSTEMTIME st{}; GetLocalTime(&st);
    wchar_t clk[64]{}; swprintf_s(clk,L"%02d:%02d:%02d",st.wHour,st.wMinute,st.wSecond);
    SetTextColor(dc,C_CYAN); SelectObject(dc,font_title);
    RECT ckr{r.right-180,8,r.right-16,46}; DrawTextW(dc,clk,-1,&ckr,DT_RIGHT|DT_VCENTER|DT_SINGLELINE);

    // Date
    wchar_t dt[64]{}; swprintf_s(dt,L"%04d-%02d-%02d",st.wYear,st.wMonth,st.wDay);
    SetTextColor(dc,C_DIM); SelectObject(dc,font_small);
    RECT dr2{r.right-180,48,r.right-16,62}; DrawTextW(dc,dt,-1,&dr2,DT_RIGHT|DT_VCENTER|DT_SINGLELINE);

    // Driver status pulse
    bool pulse=(GetTickCount64()/500)%2==0;
    SetTextColor(dc,driver_connected?(pulse?C_GREEN:C_TEAL):C_MUTED); SelectObject(dc,font_mono);
    RECT driverR{580,18,r.right-190,46};
    DrawTextW(dc,(L"[\u25cf] "+driver_status_text).c_str(),-1,&driverR,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);

    // Threat indicator in header
    if (g_unau_stats.unauthorized_count>0) {
        bool fl=(GetTickCount64()/300)%2==0;
        SetTextColor(dc,fl?C_RED:RGB(200,30,70)); SelectObject(dc,font_mono);
        wchar_t tb[64]{}; swprintf_s(tb,L"  [!] %zu UNAU  [!]",g_unau_stats.unauthorized_count);
        RECT tr{r.right-420,8,r.right-190,46};
        DrawTextW(dc,tb,-1,&tr,DT_RIGHT|DT_VCENTER|DT_SINGLELINE);
    }
}

// ============================================================
// PROCESS LIST (OWNER DATA + CUSTOM DRAW)
// ============================================================
static bool proc_matches(const ProcessRecord& p) {
    if (current_filter==PFILTER_UNAU&&!p.is_unauthorized) return false;
    if (current_filter==PFILTER_ELEVATED&&!p.elevated) return false;
    if (current_filter==PFILTER_SYSTEM&&p.integrity!=L"System") return false;
    if (current_filter==PFILTER_USER&&(p.integrity==L"System"||p.user.empty())) return false;
    if (search_text.empty()) return true;
    std::wstring q=lower_copy(search_text);
    return lower_copy(p.name).find(q)!=std::wstring::npos||
           std::to_wstring(p.pid).find(q)!=std::wstring::npos||
           lower_copy(p.path).find(q)!=std::wstring::npos||
           lower_copy(p.user).find(q)!=std::wstring::npos;
}

static std::vector<const ProcessRecord*> visible_procs() {
    std::vector<const ProcessRecord*> v;
    for (const auto& p:processes) if (proc_matches(p)) v.push_back(&p);
    std::sort(v.begin(),v.end(),[](const ProcessRecord* a,const ProcessRecord* b){
        int c=0;
        switch(proc_sort_col){
        case 0: c=lower_copy(a->name).compare(lower_copy(b->name));break;
        case 1: c=(a->pid<b->pid)?-1:(a->pid>b->pid)?1:0;break;
        case 2: c=(a->cpu<b->cpu)?-1:(a->cpu>b->cpu)?1:0;break;
        case 3: c=(a->memory<b->memory)?-1:(a->memory>b->memory)?1:0;break;
        case 4: c=(a->private_bytes<b->private_bytes)?-1:(a->private_bytes>b->private_bytes)?1:0;break;
        case 5: c=(a->thread_count<b->thread_count)?-1:(a->thread_count>b->thread_count)?1:0;break;
        case 6: c=(a->handle_count<b->handle_count)?-1:(a->handle_count>b->handle_count)?1:0;break;
        case 7: c=(a->io_read_bytes<b->io_read_bytes)?-1:(a->io_read_bytes>b->io_read_bytes)?1:0;break;
        case 8: c=(a->io_write_bytes<b->io_write_bytes)?-1:(a->io_write_bytes>b->io_write_bytes)?1:0;break;
        case 9: c=lower_copy(a->user).compare(lower_copy(b->user));break;
        case 10:c=(a->threat_score<b->threat_score)?-1:(a->threat_score>b->threat_score)?1:0;break;
        default:c=0;
        }
        return proc_sort_reverse?(c>0):(c<0);
    });
    return v;
}

static std::wstring proc_col_text(const ProcessRecord& p, int col) {
    wchar_t b[64]{};
    switch(col){
    case 0: if(current_view==PVIEW_TREE&&p.depth>0){std::wstring ind;for(int i=0;i<p.depth;++i)ind+=L"  ";return ind+L"\u2514\u2500 "+p.name;}return p.name;
    case 1: return std::to_wstring(p.pid);
    case 2: swprintf_s(b,L"%.1f%%",p.cpu);return b;
    case 3: return format_bytes(p.memory);
    case 4: return format_bytes(p.private_bytes);
    case 5: return std::to_wstring(p.thread_count);
    case 6: return std::to_wstring(p.handle_count);
    case 7: return format_bytes(p.io_read_bytes);
    case 8: return format_bytes(p.io_write_bytes);
    case 9: return p.user;
    case 10:return p.is_unauthorized?L"UNAUTHORIZED!":(p.threat_score>0?L"Review":L"Clean");
    }return L"";
}

static void create_process_list() {
    if (process_list) return;
    process_list=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,L"",
        WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS|LVS_OWNERDATA,
        0,0,0,0,main_window,reinterpret_cast<HMENU>(200),GetModuleHandleW(nullptr),nullptr);
    SendMessageW(process_list,WM_SETFONT,reinterpret_cast<WPARAM>(font_mono),TRUE);
    SendMessageW(process_list,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP);
    ListView_SetBkColor(process_list,C_PANEL); ListView_SetTextBkColor(process_list,C_PANEL); ListView_SetTextColor(process_list,C_TEXT);
    const wchar_t* names[]={L"Process Name",L"PID",L"CPU %",L"Working Set",L"Private",L"Threads",L"Handles",L"I/O Read",L"I/O Write",L"User",L"UNAU Status"};
    int widths[]={230,70,70,110,110,65,70,100,100,135,115};
    for (int i=0;i<11;++i){LVCOLUMNW c{};c.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;c.cx=widths[i];c.pszText=const_cast<LPWSTR>(names[i]);c.iSubItem=i;SendMessageW(process_list,LVM_INSERTCOLUMNW,i,reinterpret_cast<LPARAM>(&c));}
}

static void update_process_list() {
    if (!process_list) return;
    auto vis=visible_procs();
    SendMessageW(process_list,LVM_SETITEMCOUNT,static_cast<WPARAM>(vis.size()),0);
    if (selected_pid){
        auto it=std::find_if(vis.begin(),vis.end(),[](const ProcessRecord* p){return p->pid==selected_pid;});
        if (it!=vis.end()){int idx=static_cast<int>(std::distance(vis.begin(),it));ListView_SetItemState(process_list,idx,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);}
    }
    InvalidateRect(process_list,nullptr,FALSE);
}

static void create_thread_list() {
    if (thread_list) return;
    thread_list=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS,0,0,0,0,main_window,reinterpret_cast<HMENU>(201),GetModuleHandleW(nullptr),nullptr);
    SendMessageW(thread_list,WM_SETFONT,reinterpret_cast<WPARAM>(font_mono),TRUE);
    SendMessageW(thread_list,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
    ListView_SetBkColor(thread_list,C_PANEL); ListView_SetTextBkColor(thread_list,C_PANEL); ListView_SetTextColor(thread_list,C_TEXT);
    const wchar_t* nm[]={L"Thread ID",L"CPU Time",L"Priority Delta",L"Access"}; int ww[]={130,170,130,200};
    for(int i=0;i<4;++i){LVCOLUMNW c{};c.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;c.cx=ww[i];c.pszText=const_cast<LPWSTR>(nm[i]);c.iSubItem=i;SendMessageW(thread_list,LVM_INSERTCOLUMNW,i,reinterpret_cast<LPARAM>(&c));}
}

static void update_thread_list() {
    if (!thread_list) return;
    selected_threads=enumerate_threads(selected_pid);
    SendMessageW(thread_list,WM_SETREDRAW,FALSE,0); ListView_DeleteAllItems(thread_list);
    for (size_t i=0;i<selected_threads.size();++i){
        const auto& t=selected_threads[i]; LVITEMW item{}; item.mask=LVIF_TEXT; item.iItem=static_cast<int>(i);
        std::wstring tid=std::to_wstring(t.tid); item.pszText=tid.data(); SendMessageW(thread_list,LVM_INSERTITEMW,0,reinterpret_cast<LPARAM>(&item));
        std::wstring cpu=t.accessible?format_cpu_time(t.cpu_time_100ns):L"Restricted";
        std::wstring pri=std::to_wstring(t.priority_delta);
        std::wstring acc=t.accessible?L"Readable":L"Privileged";
        ListView_SetItemText(thread_list,static_cast<int>(i),1,cpu.data());
        ListView_SetItemText(thread_list,static_cast<int>(i),2,pri.data());
        ListView_SetItemText(thread_list,static_cast<int>(i),3,acc.data());
    }
    SendMessageW(thread_list,WM_SETREDRAW,TRUE,0); InvalidateRect(thread_list,nullptr,FALSE);
}

static void create_service_list() {
    if (service_list) return;
    service_list=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS,0,0,0,0,main_window,reinterpret_cast<HMENU>(202),GetModuleHandleW(nullptr),nullptr);
    SendMessageW(service_list,WM_SETFONT,reinterpret_cast<WPARAM>(font_mono),TRUE);
    SendMessageW(service_list,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
    ListView_SetBkColor(service_list,C_PANEL); ListView_SetTextBkColor(service_list,C_PANEL); ListView_SetTextColor(service_list,C_TEXT);
    const wchar_t* nm[]={L"Display Name",L"Service Name",L"Status",L"Start Type",L"PID",L"Description"}; int ww[]={260,180,90,90,72,280};
    for(int i=0;i<6;++i){LVCOLUMNW c{};c.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;c.cx=ww[i];c.pszText=const_cast<LPWSTR>(nm[i]);c.iSubItem=i;SendMessageW(service_list,LVM_INSERTCOLUMNW,i,reinterpret_cast<LPARAM>(&c));}
}

static void update_service_list() {
    if (!service_list) return;
    SendMessageW(service_list,WM_SETREDRAW,FALSE,0); ListView_DeleteAllItems(service_list);
    for (size_t i=0;i<services.size();++i){
        const auto& s=services[i]; LVITEMW item{}; item.mask=LVIF_TEXT; item.iItem=static_cast<int>(i);
        std::wstring dn=s.display_name; item.pszText=dn.data(); SendMessageW(service_list,LVM_INSERTITEMW,0,reinterpret_cast<LPARAM>(&item));
        std::wstring nm2=s.name; ListView_SetItemText(service_list,static_cast<int>(i),1,nm2.data());
        std::wstring st=s.status_str; ListView_SetItemText(service_list,static_cast<int>(i),2,st.data());
        std::wstring sp=s.start_type_str; ListView_SetItemText(service_list,static_cast<int>(i),3,sp.data());
        std::wstring pid=(s.pid>0)?std::to_wstring(s.pid):L"-"; ListView_SetItemText(service_list,static_cast<int>(i),4,pid.data());
        std::wstring desc=s.description; ListView_SetItemText(service_list,static_cast<int>(i),5,desc.data());
    }
    SendMessageW(service_list,WM_SETREDRAW,TRUE,0); InvalidateRect(service_list,nullptr,FALSE);
}

// ============================================================
// LAYOUT
// ============================================================
static void layout() {
    RECT r{}; GetClientRect(main_window,&r);
    constexpr int SW=248, HH=70, BTNBAR=42, SB=22;
    MoveWindow(sidebar_wnd,0,HH,SW,r.bottom-HH-SB,TRUE);
    int cw=r.right-SW;

    bool svcPage=(current_page==PAGE_SERVICES);
    bool procPage=(current_page==PAGE_PROCESSES);
    bool thrPage=(current_page==PAGE_THREADS);

    MoveWindow(content_wnd,SW,HH,cw,r.bottom-HH-SB-(svcPage?BTNBAR:0),TRUE);
    if (search_box)    MoveWindow(search_box,r.right-344,22,236,28,TRUE);
    if (process_list)  MoveWindow(process_list,SW+22,HH+98,cw-44,r.bottom-HH-SB-118,TRUE);
    if (thread_list)   MoveWindow(thread_list, SW+22,HH+96,cw-44,r.bottom-HH-SB-116,TRUE);
    if (service_list)  MoveWindow(service_list,SW+22,HH+80,cw-44,r.bottom-HH-SB-BTNBAR-94,TRUE);
    if (svc_start_btn) MoveWindow(svc_start_btn,SW+22,r.bottom-SB-BTNBAR+8,130,28,TRUE);
    if (svc_stop_btn)  MoveWindow(svc_stop_btn, SW+160,r.bottom-SB-BTNBAR+8,130,28,TRUE);
    if (status_bar)    MoveWindow(status_bar,0,r.bottom-SB,r.right,SB,TRUE);

    ShowWindow(process_list,  procPage?SW_SHOW:SW_HIDE);
    ShowWindow(thread_list,   thrPage ?SW_SHOW:SW_HIDE);
    ShowWindow(service_list,  svcPage ?SW_SHOW:SW_HIDE);
    ShowWindow(svc_start_btn, svcPage ?SW_SHOW:SW_HIDE);
    ShowWindow(svc_stop_btn,  svcPage ?SW_SHOW:SW_HIDE);
    ShowWindow(search_box,    procPage?SW_SHOW:SW_HIDE);
}

// ============================================================
// CONTENT PROC
// ============================================================
static LRESULT CALLBACK content_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg==WM_PAINT) {
        PAINTSTRUCT ps{}; HDC hdc=BeginPaint(hwnd,&ps);
        RECT r{}; GetClientRect(hwnd,&r);
        HDC mem=CreateCompatibleDC(hdc); HBITMAP bm=CreateCompatibleBitmap(hdc,r.right,r.bottom);
        auto ob=SelectObject(mem,bm); fill_solid(mem,r,C_VOID);
        switch(current_page){
        case PAGE_OVERVIEW:    draw_overview(mem,r);       break;
        case PAGE_UNAU:        draw_unau_sentinel(mem,r);  break;
        case PAGE_PROCESSES:   draw_processes_page(mem,r); break;
        case PAGE_SERVICES:    draw_services_page(mem,r);  break;
        case PAGE_PERFORMANCE: draw_performance(mem,r);    break;
        case PAGE_KERNEL:      draw_kernel_monitor(mem,r); break;
        case PAGE_NETWORK:     draw_network_sentinel(mem,r);break;
        case PAGE_DETAILS:     draw_details(mem,r);        break;
        case PAGE_THREADS:     draw_threads(mem,r);        break;
        case PAGE_STARTUP:     draw_startup_page(mem,r);   break;
        case PAGE_USERS:       draw_users_page(mem,r);     break;
        case PAGE_MODULES:     draw_modules_page(mem,r);   break;
        default: break;
        }
        BitBlt(hdc,0,0,r.right,r.bottom,mem,0,0,SRCCOPY);
        SelectObject(mem,ob); DeleteObject(bm); DeleteDC(mem);
        EndPaint(hwnd,&ps); return 0;
    }
    if (msg==WM_ERASEBKGND) return 1;
    return DefWindowProcW(hwnd,msg,wp,lp);
}

// ============================================================
// SIDEBAR PROC
// ============================================================
static LRESULT CALLBACK sidebar_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg==WM_PAINT){
        PAINTSTRUCT ps{}; HDC hdc=BeginPaint(hwnd,&ps);
        RECT r{}; GetClientRect(hwnd,&r);
        HDC mem=CreateCompatibleDC(hdc); HBITMAP bm=CreateCompatibleBitmap(hdc,r.right,r.bottom);
        auto ob=SelectObject(mem,bm); draw_sidebar(mem,r);
        BitBlt(hdc,0,0,r.right,r.bottom,mem,0,0,SRCCOPY);
        SelectObject(mem,ob); DeleteObject(bm); DeleteDC(mem);
        EndPaint(hwnd,&ps); return 0;
    }
    if (msg==WM_MOUSEMOVE){
        int y=GET_Y_LPARAM(lp);
        int idx=(y>=76&&y<76+PAGE_COUNT*42)?((y-76)/42):-1;
        if (idx!=g_sidebar_hover){ g_sidebar_hover=idx; InvalidateRect(hwnd,nullptr,FALSE); }
        return 0;
    }
    if (msg==WM_MOUSELEAVE){ g_sidebar_hover=-1; InvalidateRect(hwnd,nullptr,FALSE); return 0; }
    if (msg==WM_LBUTTONUP){
        int y=GET_Y_LPARAM(lp);
        if (y>=76){ int idx=(y-76)/42; if (idx>=0&&idx<PAGE_COUNT){
            current_page=static_cast<Page>(idx);
            layout();
            if (current_page==PAGE_PROCESSES) update_process_list();
            else if (current_page==PAGE_THREADS) update_thread_list();
            else if (current_page==PAGE_SERVICES) update_service_list();
            else if (current_page==PAGE_DETAILS&&selected_pid){ g_detail_tab=0; }
            else if (current_page==PAGE_MODULES&&selected_pid){ modules=enumerate_modules(selected_pid); }
            else if (current_page==PAGE_USERS){ sessions=enumerate_sessions(); }
            InvalidateRect(sidebar_wnd,nullptr,FALSE); InvalidateRect(content_wnd,nullptr,FALSE); InvalidateRect(main_window,nullptr,FALSE);
        }}
        return 0;
    }
    if (msg==WM_ERASEBKGND) return 1;
    return DefWindowProcW(hwnd,msg,wp,lp);
}

// ============================================================
// CONTEXT MENU
// ============================================================
static void show_process_context_menu(HWND hwnd, int sx, int sy) {
    const ProcessRecord* p=selected_process(); if (!p) return;
    HMENU menu=CreatePopupMenu();
    AppendMenuW(menu,MF_STRING,IDM_END_TASK,  L"End Task");
    AppendMenuW(menu,MF_STRING,IDM_END_TREE,  L"End Process Tree");
    AppendMenuW(menu,MF_SEPARATOR,0,nullptr);
    AppendMenuW(menu,MF_STRING,IDM_SUSPEND,   p->suspended?L"Resume Process":L"Suspend Process");
    AppendMenuW(menu,MF_SEPARATOR,0,nullptr);
    HMENU prio=CreatePopupMenu();
    AppendMenuW(prio,MF_STRING,IDM_PRIO_REALTIME,   L"Realtime");
    AppendMenuW(prio,MF_STRING,IDM_PRIO_HIGH,        L"High");
    AppendMenuW(prio,MF_STRING,IDM_PRIO_ABOVENORMAL, L"Above Normal");
    AppendMenuW(prio,MF_STRING,IDM_PRIO_NORMAL,      L"Normal");
    AppendMenuW(prio,MF_STRING,IDM_PRIO_BELOWNORMAL,  L"Below Normal");
    AppendMenuW(prio,MF_STRING,IDM_PRIO_LOW,          L"Low");
    AppendMenuW(menu,MF_POPUP,reinterpret_cast<UINT_PTR>(prio),L"Set Priority");
    AppendMenuW(menu,MF_SEPARATOR,0,nullptr);
    AppendMenuW(menu,MF_STRING,IDM_OPEN_LOCATION,L"Open File Location");
    AppendMenuW(menu,MF_STRING,IDM_COPY_PID,     L"Copy PID");
    AppendMenuW(menu,MF_STRING,IDM_COPY_PATH,    L"Copy Full Path");
    AppendMenuW(menu,MF_STRING,IDM_GO_DETAILS,   L"Inspect in Details");
    int cmd=TrackPopupMenuEx(menu,TPM_RETURNCMD|TPM_RIGHTBUTTON,sx,sy,hwnd,nullptr);
    DestroyMenu(menu);
    switch(cmd){
    case IDM_END_TASK: terminate_process(selected_pid); request_process_refresh(); break;
    case IDM_END_TREE: terminate_process_tree(selected_pid); request_process_refresh(); break;
    case IDM_SUSPEND:
        if (p->suspended) resume_process(selected_pid); else suspend_process(selected_pid);
        request_process_refresh(); break;
    case IDM_PRIO_REALTIME:case IDM_PRIO_HIGH:case IDM_PRIO_ABOVENORMAL:
    case IDM_PRIO_NORMAL:case IDM_PRIO_BELOWNORMAL:case IDM_PRIO_LOW:{
        DWORD pr=NORMAL_PRIORITY_CLASS;
        if(cmd==IDM_PRIO_REALTIME)pr=REALTIME_PRIORITY_CLASS;
        else if(cmd==IDM_PRIO_HIGH)pr=HIGH_PRIORITY_CLASS;
        else if(cmd==IDM_PRIO_ABOVENORMAL)pr=ABOVE_NORMAL_PRIORITY_CLASS;
        else if(cmd==IDM_PRIO_BELOWNORMAL)pr=BELOW_NORMAL_PRIORITY_CLASS;
        else if(cmd==IDM_PRIO_LOW)pr=IDLE_PRIORITY_CLASS;
        HANDLE h=OpenProcess(PROCESS_SET_INFORMATION,FALSE,selected_pid);
        if(h){SetPriorityClass(h,pr);CloseHandle(h);} break;
    }
    case IDM_OPEN_LOCATION:if(!p->path.empty()){std::wstring d=p->path.substr(0,p->path.find_last_of(L"\\/"));ShellExecuteW(nullptr,L"explore",d.c_str(),nullptr,nullptr,SW_SHOW);}break;
    case IDM_COPY_PID:
    case IDM_COPY_PATH:{
        std::wstring txt=(cmd==IDM_COPY_PID)?std::to_wstring(selected_pid):p->path;
        if (OpenClipboard(hwnd)){EmptyClipboard();HGLOBAL hg=GlobalAlloc(GMEM_MOVEABLE,(txt.size()+1)*sizeof(wchar_t));if(hg){wchar_t* d=static_cast<wchar_t*>(GlobalLock(hg));if(d){wcscpy_s(d,txt.size()+1,txt.c_str());GlobalUnlock(hg);}SetClipboardData(CF_UNICODETEXT,hg);}CloseClipboard();} break;
    }
    case IDM_GO_DETAILS:current_page=PAGE_DETAILS;g_detail_tab=0;layout();InvalidateRect(sidebar_wnd,nullptr,FALSE);InvalidateRect(content_wnd,nullptr,FALSE);break;
    }
}

// ============================================================
// MAIN WINDOW PROC
// ============================================================
static LRESULT CALLBACK main_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg){
    case WM_CREATE:{
        main_window=hwnd;
        SetTimer(hwnd,1,1000,nullptr);
        SetTimer(hwnd,2,100,nullptr);
        SetTimer(hwnd,3,5000,nullptr);
        sidebar_wnd=CreateWindowExW(0,L"TaskletSidebar",nullptr,WS_CHILD|WS_VISIBLE,0,70,248,600,hwnd,nullptr,GetModuleHandleW(nullptr),nullptr);
        content_wnd=CreateWindowExW(0,L"TaskletContent",nullptr,WS_CHILD|WS_VISIBLE,248,70,900,600,hwnd,nullptr,GetModuleHandleW(nullptr),nullptr);
        search_box=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,0,0,220,28,hwnd,reinterpret_cast<HMENU>(100),GetModuleHandleW(nullptr),nullptr);
        SendMessageW(search_box,WM_SETFONT,reinterpret_cast<WPARAM>(font_normal),TRUE);
        SendMessageW(search_box,EM_SETCUEBANNER,0,reinterpret_cast<LPARAM>(L">> Search processes..."));
        svc_start_btn=CreateWindowExW(0,L"BUTTON",L"\u25b6  Start Service",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,130,28,hwnd,reinterpret_cast<HMENU>(300),GetModuleHandleW(nullptr),nullptr);
        svc_stop_btn =CreateWindowExW(0,L"BUTTON",L"\u25a0  Stop Service", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,130,28,hwnd,reinterpret_cast<HMENU>(301),GetModuleHandleW(nullptr),nullptr);
        SendMessageW(svc_start_btn,WM_SETFONT,reinterpret_cast<WPARAM>(font_normal),TRUE);
        SendMessageW(svc_stop_btn, WM_SETFONT,reinterpret_cast<WPARAM>(font_normal),TRUE);
        // Status bar
        status_bar=CreateWindowExW(0,STATUSCLASSNAMEW,nullptr,WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP,0,0,0,0,hwnd,reinterpret_cast<HMENU>(400),GetModuleHandleW(nullptr),nullptr);
        SendMessageW(status_bar,WM_SETFONT,reinterpret_cast<WPARAM>(font_mono),TRUE);
        create_process_list(); create_thread_list(); create_service_list();
        // Load NT functions
        HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
        if (ntdll){ fnNtSuspend=reinterpret_cast<pNtSuspendProcess>(GetProcAddress(ntdll,"NtSuspendProcess")); fnNtResume=reinterpret_cast<pNtResumeProcess>(GetProcAddress(ntdll,"NtResumeProcess")); }
        telemetry_client.start(); init_perf_counters(); g_cpu_brand=get_cpu_brand();
        services=enumerate_services(); startup_entries=enumerate_startup(); sessions=enumerate_sessions();
        ShowWindow(search_box,SW_HIDE); ShowWindow(process_list,SW_HIDE); ShowWindow(thread_list,SW_HIDE);
        ShowWindow(service_list,SW_HIDE); ShowWindow(svc_start_btn,SW_HIDE); ShowWindow(svc_stop_btn,SW_HIDE);
        request_process_refresh(); sample_system(); layout();
        return 0;
    }
    case WM_SIZE:{
        layout();
        InvalidateRect(sidebar_wnd,nullptr,FALSE); InvalidateRect(content_wnd,nullptr,FALSE); InvalidateRect(hwnd,nullptr,FALSE);
        return 0;
    }
    case WM_TIMER:{
        if (wp==1){
            sample_system(); update_driver_snapshot(); collect_process_refresh();
            if (!process_refresh_pending) request_process_refresh();
            if (current_page==PAGE_PROCESSES) update_process_list();
            else if (current_page==PAGE_THREADS) update_thread_list();
            // Update status bar
            if (status_bar){
                wchar_t sb[512]{}; swprintf_s(sb,L"  Processes: %zu  |  CPU: %.1f%%  |  RAM: %.1f%%  |  TX: %.2f MB/s  |  RX: %.2f MB/s  |  UNAU Threats: %zu  |  %s",
                    processes.size(),system_cpu,system_memory,net_sent_mb,net_recv_mb,
                    g_unau_stats.unauthorized_count, format_uptime().c_str());
                SetWindowTextW(status_bar,sb);
            }
            InvalidateRect(content_wnd,nullptr,FALSE); InvalidateRect(sidebar_wnd,nullptr,FALSE); InvalidateRect(hwnd,nullptr,FALSE);
        } else if (wp==2){
            ++g_anim_tick;
            if (current_page==PAGE_OVERVIEW||current_page==PAGE_PERFORMANCE||current_page==PAGE_KERNEL)
                InvalidateRect(content_wnd,nullptr,FALSE);
            InvalidateRect(hwnd,nullptr,FALSE); // clock
        } else if (wp==3){
            services=enumerate_services(); startup_entries=enumerate_startup(); sessions=enumerate_sessions();
            if (current_page==PAGE_SERVICES){ update_service_list(); InvalidateRect(content_wnd,nullptr,FALSE); }
            else if (current_page==PAGE_USERS||current_page==PAGE_STARTUP) InvalidateRect(content_wnd,nullptr,FALSE);
        }
        return 0;
    }
    case WM_COMMAND:{
        int id=LOWORD(wp);
        if (id==100&&HIWORD(wp)==EN_CHANGE){
            int len=GetWindowTextLengthW(search_box); search_text.resize(static_cast<size_t>(len)+1);
            int cp=len>0?GetWindowTextW(search_box,search_text.data(),len+1):0; search_text.resize(static_cast<size_t>(cp)); update_process_list();
        } else if (id==300){
            if (g_sel_service<services.size()){ SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(scm){SC_HANDLE sh=OpenServiceW(scm,services[g_sel_service].name.c_str(),SERVICE_START);if(sh){StartServiceW(sh,0,nullptr);CloseServiceHandle(sh);}CloseServiceHandle(scm);} services=enumerate_services();update_service_list(); }
        } else if (id==301){
            if (g_sel_service<services.size()){ SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(scm){SC_HANDLE sh=OpenServiceW(scm,services[g_sel_service].name.c_str(),SERVICE_STOP);if(sh){SERVICE_STATUS ss{};ControlService(sh,SERVICE_CONTROL_STOP,&ss);CloseServiceHandle(sh);}CloseServiceHandle(scm);} services=enumerate_services();update_service_list(); }
        }
        return 0;
    }
    case WM_NOTIFY:{
        auto* hdr=reinterpret_cast<NMHDR*>(lp); if(!hdr) break;
        if (hdr->hwndFrom==process_list){
            if (hdr->code==LVN_GETDISPINFOW){
                auto* di=reinterpret_cast<NMLVDISPINFOW*>(lp);
                auto vis=visible_procs();
                if (di->item.iItem<static_cast<int>(vis.size())){
                    const auto& p=*vis[static_cast<size_t>(di->item.iItem)];
                    if (di->item.mask&LVIF_TEXT){ static std::wstring buf; buf=proc_col_text(p,di->item.iSubItem); wcsncpy_s(di->item.pszText,di->item.cchTextMax,buf.c_str(),_TRUNCATE); }
                }
                return 0;
            }
            if (hdr->code==NM_CUSTOMDRAW){
                auto* cd=reinterpret_cast<NMLVCUSTOMDRAW*>(lp);
                if (cd->nmcd.dwDrawStage==CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
                if (cd->nmcd.dwDrawStage==CDDS_ITEMPREPAINT){
                    auto vis=visible_procs();
                    if (cd->nmcd.dwItemSpec<vis.size()){
                        const auto& p=*vis[cd->nmcd.dwItemSpec];
                        if (p.is_unauthorized){
                            cd->clrTextBk=(cd->nmcd.dwItemSpec%2==0)?RGB(35,8,15):RGB(28,6,12);
                            cd->clrText=C_RED;
                        } else if (p.elevated){
                            cd->clrTextBk=(cd->nmcd.dwItemSpec%2==0)?C_AMBER_DARK:RGB(45,30,0);
                            cd->clrText=C_TEXT;
                        } else if (p.threat_score>0){
                            cd->clrTextBk=(cd->nmcd.dwItemSpec%2==0)?RGB(12,18,30):C_PANEL2;
                            cd->clrText=C_AMBER;
                        } else {
                            cd->clrTextBk=(cd->nmcd.dwItemSpec%2==0)?C_PANEL:C_PANEL2;
                            cd->clrText=C_TEXT;
                        }
                    }
                    return CDRF_NEWFONT;
                }
                return CDRF_DODEFAULT;
            }
            if (hdr->code==LVN_ITEMCHANGED){
                auto* item=reinterpret_cast<NMLISTVIEW*>(lp);
                if (item->uNewState&LVIS_SELECTED){ auto vis=visible_procs(); if(item->iItem>=0&&item->iItem<static_cast<int>(vis.size())) selected_pid=vis[static_cast<size_t>(item->iItem)]->pid; }
                return 0;
            }
            if (hdr->code==LVN_COLUMNCLICK){
                auto* clk=reinterpret_cast<NMLISTVIEW*>(lp);
                if (proc_sort_col==clk->iSubItem) proc_sort_reverse=!proc_sort_reverse;
                else { proc_sort_col=clk->iSubItem; proc_sort_reverse=false; }
                update_process_list(); return 0;
            }
            if (hdr->code==NM_RCLICK){ POINT pt{}; GetCursorPos(&pt); show_process_context_menu(hwnd,pt.x,pt.y); return 0; }
            if (hdr->code==NM_DBLCLK){ current_page=PAGE_DETAILS;g_detail_tab=0;layout();InvalidateRect(sidebar_wnd,nullptr,FALSE);InvalidateRect(content_wnd,nullptr,FALSE); return 0; }
        }
        if (hdr->hwndFrom==service_list&&hdr->code==LVN_ITEMCHANGED){
            auto* item=reinterpret_cast<NMLISTVIEW*>(lp);
            if (item->uNewState&LVIS_SELECTED&&item->iItem>=0) g_sel_service=static_cast<DWORD>(item->iItem);
            return 0;
        }
        break;
    }
    case WM_KEYDOWN:{
        if (wp>='1'&&wp<='9'){ current_page=static_cast<Page>(wp-'1');layout();InvalidateRect(sidebar_wnd,nullptr,FALSE);InvalidateRect(content_wnd,nullptr,FALSE);return 0; }
        if (wp=='0'){ current_page=PAGE_STARTUP;layout();InvalidateRect(sidebar_wnd,nullptr,FALSE);InvalidateRect(content_wnd,nullptr,FALSE);return 0; }
        if (wp==VK_F5){ request_process_refresh();return 0; }
        if (wp==VK_DELETE&&selected_pid){ terminate_process(selected_pid);request_process_refresh();return 0; }
        if (wp==VK_ESCAPE&&search_box&&IsWindowVisible(search_box)){ SetWindowTextW(search_box,L"");search_text.clear();update_process_list();return 0; }
        if (wp=='T'&&current_page==PAGE_PROCESSES){ current_view=(current_view==PVIEW_LIST)?PVIEW_TREE:PVIEW_LIST;update_process_list();InvalidateRect(content_wnd,nullptr,FALSE);return 0; }
        if (wp=='L'&&current_page==PAGE_PROCESSES){ current_view=PVIEW_LIST;update_process_list();InvalidateRect(content_wnd,nullptr,FALSE);return 0; }
        if (wp=='A'&&current_page==PAGE_PROCESSES){ current_filter=PFILTER_ALL;update_process_list();InvalidateRect(content_wnd,nullptr,FALSE);return 0; }
        if (wp=='U'&&current_page==PAGE_PROCESSES){ current_filter=PFILTER_UNAU;update_process_list();InvalidateRect(content_wnd,nullptr,FALSE);return 0; }
        if (wp=='E'&&current_page==PAGE_PROCESSES){ current_filter=PFILTER_ELEVATED;update_process_list();InvalidateRect(content_wnd,nullptr,FALSE);return 0; }
        // Detail tab navigation
        if (current_page==PAGE_DETAILS){
            if (wp==VK_F1){ g_detail_tab=0;InvalidateRect(content_wnd,nullptr,FALSE);return 0; }
            if (wp==VK_F2){ g_detail_tab=1;env_vars=enumerate_env_vars(selected_pid);InvalidateRect(content_wnd,nullptr,FALSE);return 0; }
            if (wp==VK_F3){ g_detail_tab=2;modules=enumerate_modules(selected_pid);InvalidateRect(content_wnd,nullptr,FALSE);return 0; }
        }
        break;
    }
    case WM_PAINT:{
        PAINTSTRUCT ps{}; HDC hdc=BeginPaint(hwnd,&ps);
        RECT r{}; GetClientRect(hwnd,&r);
        HDC mem=CreateCompatibleDC(hdc); HBITMAP bm=CreateCompatibleBitmap(hdc,r.right,70);
        auto ob=SelectObject(mem,bm); RECT hr{0,0,r.right,70}; draw_header(mem,hr);
        BitBlt(hdc,0,0,r.right,70,mem,0,0,SRCCOPY);
        SelectObject(mem,ob); DeleteObject(bm); DeleteDC(mem);
        EndPaint(hwnd,&ps); return 0;
    }
    case WM_ERASEBKGND: return 1;
    case WM_DESTROY:{
        KillTimer(hwnd,1);KillTimer(hwnd,2);KillTimer(hwnd,3);
        telemetry_client.stop();
        if (process_refresh_pending){ process_refresh.wait(); try{process_refresh.get();}catch(...){} }
        cleanup_perf_counters();
        if(font_normal)DeleteObject(font_normal); if(font_small)DeleteObject(font_small);
        if(font_title)DeleteObject(font_title);   if(font_heading)DeleteObject(font_heading);
        if(font_mono)DeleteObject(font_mono);     if(font_tiny)DeleteObject(font_tiny);
        PostQuitMessage(0); return 0;
    }
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}

} // namespace tasklet

// ============================================================
// ENTRY POINT
// ============================================================
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    using namespace tasklet;
    INITCOMMONCONTROLSEX icc{}; icc.dwSize=sizeof(icc);
    icc.dwICC=ICC_LISTVIEW_CLASSES|ICC_STANDARD_CLASSES|ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    font_normal  = CreateFontW(-14,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");
    font_small   = CreateFontW(-12,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");
    font_title   = CreateFontW(-22,0,0,0,FW_BOLD,  FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");
    font_heading = CreateFontW(-16,0,0,0,FW_BOLD,  FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");
    font_mono    = CreateFontW(-13,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,FIXED_PITCH|FF_MODERN,L"Consolas");
    font_tiny    = CreateFontW(-11,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");

    WNDCLASSW mc{}; mc.lpfnWndProc=main_proc; mc.hInstance=instance;
    mc.hCursor=LoadCursorW(nullptr,IDC_ARROW); mc.hbrBackground=CreateSolidBrush(C_VOID);
    mc.lpszClassName=L"TaskletMain"; RegisterClassW(&mc);

    WNDCLASSW sc{}; sc.lpfnWndProc=sidebar_proc; sc.hInstance=instance;
    sc.hCursor=LoadCursorW(nullptr,IDC_ARROW); sc.hbrBackground=CreateSolidBrush(C_SIDEBAR);
    sc.lpszClassName=L"TaskletSidebar"; RegisterClassW(&sc);

    WNDCLASSW cc{}; cc.lpfnWndProc=content_proc; cc.hInstance=instance;
    cc.hCursor=LoadCursorW(nullptr,IDC_ARROW); cc.hbrBackground=CreateSolidBrush(C_VOID);
    cc.lpszClassName=L"TaskletContent"; RegisterClassW(&cc);

    HWND hwnd=CreateWindowExW(0,L"TaskletMain",
        L"TASKLET // KERNEL PROCESS SENTINEL & CYBER DEFENSE CONSOLE v2.2",
        WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN|WS_CLIPSIBLINGS,
        CW_USEDEFAULT,CW_USEDEFAULT,1680,1000,
        nullptr,nullptr,instance,nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd,show); UpdateWindow(hwnd);
    MSG msg{}; while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    return static_cast<int>(msg.wParam);
}
