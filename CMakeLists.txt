cmake_minimum_required(VERSION 3.20)

project(Tasklet
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    add_compile_options(/W4 /EHsc /utf-8)
endif()

# Core Tasklet GUI Application
add_executable(tasklet WIN32
    src/main.cpp
    src/telemetry_client.cpp
    src/telemetry_protocol.cpp
    src/unauprocdetect.cpp
)

target_link_libraries(tasklet PRIVATE
    advapi32
    comctl32
    psapi
    user32
    gdi32
    shell32
    shlwapi
    ole32
    oleaut32
    wbemuuid
    iphlpapi
    ws2_32
    wintrust
    crypt32
    bcrypt
    wtsapi32
    pdh
)

target_include_directories(tasklet PRIVATE
    include
    shared
)

# Standalone Unauprocdetect CLI Tool
add_executable(unauprocdetect
    src/unauprocdetect_main.cpp
    src/unauprocdetect.cpp
    src/telemetry_protocol.cpp
)

target_link_libraries(unauprocdetect PRIVATE
    advapi32
    psapi
    wtsapi32
    wintrust
    crypt32
    bcrypt
)

target_include_directories(unauprocdetect PRIVATE
    include
    shared
)

include(CTest)
if (BUILD_TESTING)
    add_executable(tasklet_protocol_tests
        tests/test_telemetry_protocol.cpp
        src/telemetry_protocol.cpp
    )
    target_include_directories(tasklet_protocol_tests PRIVATE
        include
        shared
    )
    add_test(NAME telemetry_protocol COMMAND tasklet_protocol_tests)

    add_executable(unauprocdetect_tests
        tests/test_unauprocdetect.cpp
        src/unauprocdetect.cpp
        src/telemetry_protocol.cpp
    )
    target_link_libraries(unauprocdetect_tests PRIVATE
        advapi32
        psapi
        wtsapi32
        wintrust
        crypt32
        bcrypt
    )
    target_include_directories(unauprocdetect_tests PRIVATE
        include
        shared
    )
    add_test(NAME unauprocdetect_tests COMMAND unauprocdetect_tests)
endif()
