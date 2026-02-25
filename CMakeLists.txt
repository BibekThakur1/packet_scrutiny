cmake_minimum_required(VERSION 3.16)
project(PacketScrutiny
    VERSION 1.0.0
    DESCRIPTION "Deep Packet Inspection Engine for Education"
    LANGUAGES CXX
)

# ── C++17 Standard ───────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Source files ─────────────────────────────────────────────────────────────
set(SENTINEL_SOURCES
    src/core/Protocol.cpp
    src/core/Types.cpp
    src/capture/PcapIngester.cpp
    src/capture/FrameDissector.cpp
    src/flow/SessionLedger.cpp
    src/flow/FlowOrchestrator.cpp
    src/analysis/TlsProber.cpp
    src/analysis/AppFingerprinter.cpp
    src/rules/PolicyEngine.cpp
    src/engine/InspectionPipeline.cpp
    src/benchmark/Stopwatch.cpp
    src/main.cpp
)

# ── Executable ───────────────────────────────────────────────────────────────
add_executable(packet_scrutiny ${SENTINEL_SOURCES})

target_include_directories(packet_scrutiny
    PRIVATE ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(packet_scrutiny PRIVATE
    -Wall -Wextra -Wpedantic
)

# ── macOS / Linux specific ───────────────────────────────────────────────────
if(APPLE)
    # macOS: arpa/inet.h available by default
endif()

if(UNIX AND NOT APPLE)
    # Linux may need pthread
    find_package(Threads REQUIRED)
    target_link_libraries(net_sentinel PRIVATE Threads::Threads)
endif()
