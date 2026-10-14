cmake_minimum_required(VERSION 3.20)
project(UbisoftSDKShim LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CORE_SOURCES
    src/core/config.cpp
    src/core/config_line.cpp
    src/core/debug/fault_logger.cpp
    src/core/debug/field_sampler.cpp
    src/core/debug/module_dump.cpp
    src/core/debug/watchpoint.cpp
    src/core/logging.cpp
    src/core/hooking/iat.cpp
    src/core/networking/redirect.cpp
    src/core/networking/tls.cpp
    src/core/networking/tls_observer.cpp
    src/core/networking/tls_pin.cpp
    src/core/playforward/bridge_client.cpp
    src/core/playforward/https_client.cpp
    src/core/playforward/launch_envelope.cpp
    src/core/playforward/launch_proof.cpp
    src/core/playforward/launch_session.cpp
    src/core/playforward/play_presence.cpp
    src/core/playforward/sha256.cpp
    src/core/runtime.cpp)

function(add_game_shim target game_sources exports)
    add_library(${target} SHARED ${CORE_SOURCES} ${game_sources} ${exports})
    target_include_directories(${target} PRIVATE src)
    target_compile_definitions(${target} PRIVATE WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
    target_compile_options(${target} PRIVATE -Wall -Wextra)
    # winhttp: the launch's HTTPS calls (src/core/playforward/https_client.cpp),
    # with the system's own TLS and certificate store -- Schannel on Windows,
    # GnuTLS and the host's CA store under Wine.
    target_link_libraries(${target} PRIVATE ws2_32 winhttp)
    # Proxy DLLs are dropped directly into a game directory. Do not make the
    # user also install MinGW's libwinpthread/libgcc runtime DLLs.
    target_link_options(${target} PRIVATE -static -static-libgcc -static-libstdc++)
    set_target_properties(${target} PROPERTIES
        PREFIX ""
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${target}")
endfunction()

# Do not permit an easy-to-install wrong-architecture proxy. Configure one
# build tree per architecture; the available targets match that architecture.
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_game_shim(farcry3_shim "src/games/farcry3/adapter.cpp;src/games/farcry3/build_fixes.cpp;src/games/farcry3/code_scan.cpp;src/games/farcry3/launch.cpp;src/games/farcry3/launch_command_line.cpp;src/games/farcry3/input_inject.cpp;src/games/farcry3/online_autologin.cpp;src/games/farcry3/tracer.cpp;src/games/farcry3/uplay_trace.cpp;src/games/common/uplay_debug.cpp" src/games/farcry3/proxy_exports.def)
    set_target_properties(farcry3_shim PROPERTIES OUTPUT_NAME binkw32)

    add_game_shim(splintercellblacklist_shim "src/games/blacklist/adapter.cpp;src/games/blacklist/identity.cpp;src/games/blacklist/net_trace.cpp;src/games/blacklist/nla_stub.cpp;src/games/blacklist/winhttp_trace.cpp" src/games/blacklist/proxy_exports.def)
    set_target_properties(splintercellblacklist_shim PROPERTIES OUTPUT_NAME bink2w32)

    add_game_shim(ghostreconfuturesoldier_shim "src/games/futuresoldier/adapter.cpp;src/games/futuresoldier/identity.cpp" src/games/futuresoldier/proxy_exports.def)
    set_target_properties(ghostreconfuturesoldier_shim PROPERTIES OUTPUT_NAME binkw32)
else()
    add_game_shim(farcry4_shim src/games/farcry4/adapter.cpp src/games/farcry4/proxy_exports.def)
    set_target_properties(farcry4_shim PROPERTIES OUTPUT_NAME bink2w64)

    add_game_shim(farcry5_shim "src/games/farcry5/adapter.cpp;src/games/farcry5/cng_debug.cpp;src/games/common/fc_m64_debug.cpp;src/games/common/uplay_debug.cpp" src/games/farcry5/proxy_exports.def)
    set_target_properties(farcry5_shim PROPERTIES OUTPUT_NAME bink2w64)

    add_game_shim(farcrynewdawn_shim "src/games/newdawn/adapter.cpp;src/games/common/fc_m64_debug.cpp;src/games/common/uplay_debug.cpp" src/games/newdawn/proxy_exports.def)
    set_target_properties(farcrynewdawn_shim PROPERTIES OUTPUT_NAME bink2w64)
endif()
