# Ubisoft SDK Shim

A reusable Windows proxy-DLL framework for redirecting Ubisoft game services to a user-controlled LAN server. Game adapters locate networking and TLS hooks while the shared core applies DNS policy, socket capture, certificate-verification bypass, configuration, and logging.

```
src/core /                    shared runtime, hook registry, network and TLS policy
src/games/<game>/adapter.cpp  game capabilities and optional debugging hooks
src/games/<game>/versions/    build-specific modules, hosts and verified RVAs
src/games/<game>/*.def        exact proxy export table for that title
```

[`manifest.json`](manifest.json) is the machine-readable artifact map for a future installer or release packager.

See [the LAN setup guide](docs/LAN_SETUP.md) for installation, server ports, TLS RVAs, game-specific configuration, and launch troubleshooting.

## Building

Use a separate MinGW build tree for each architecture:

```sh
cmake -S . -B build/x64 -DCMAKE_TOOLCHAIN_FILE=/path/to/mingw64.cmake
cmake --build build/x64 --target farcry4_shim farcry5_shim farcrynewdawn_shim

cmake -S . -B build/x86 -DCMAKE_TOOLCHAIN_FILE=/path/to/mingw32.cmake
cmake --build build/x86 --target farcry3_shim splintercellblacklist_shim ghostreconfuturesoldier_shim
```

Each artifact is placed in its own target directory to avoid the intentional filename collisions: `bink2w64.dll` between FC4, FC5, and New Dawn, and `binkw32.dll` between FC3 and Future Soldier. Each game keeps its own Bink export definition under its adapter because the export tables differ even where the proxy filename is shared.

## Adding another Ubisoft game

Add an adapter and a version definition describing the proxy DLL, main module, backend host rules, resolver methods, exact name/ordinal bindings, and verified TLS hook. The adapter locates hooks; it must not reimplement redirect or capture policy. Add a separate build target only when the proxy/export table differs.

For a title that logs in through Playforward, the version definition also carries the local UDP port the game binds its RendezVous socket to (the launch proof runs on that bind), the server's authentication port for the title (where the proof goes), and the title id Playforward knows it by; and the adapter hooks whatever the game reads its identity from -- a command-line option, a Uplay export, an Orbit callback -- to answer with `hook.config`'s `login_name`. `src/games/blacklist/identity.cpp` and `src/games/futuresoldier/identity.cpp` are the two shapes of that so far.
