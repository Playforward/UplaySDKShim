# Ubisoft LAN setup

This guide covers the consolidated shim for Ubisoft Games. The server and Uplay emulator are separate projects. This repository provides the per-game Bink proxy that redirects Ubisoft services and bypasses the certificate verifier.

## Network layout

Run one shared server stack on the LAN host. Point every game client—including the client running on the server machine—at that machine's LAN address, such as `192.168.1.50`. Do not use `127.0.0.1`, because the other clients must reach the same Storm broker.

| Port | Protocol | Purpose |
| --- | --- | --- |
| 443 | TCP/TLS | UbiServices REST and WebSocket |
| 11000, 11001 | UDP | Storm detect |
| 11005 | UDP | Storm traversal |
| 12000 | UDP | Storm relay |
| 47100 | UDP | Uplay emulator/CoopNet LAN discovery |
| 9000 | UDP | Direct game data path used by the existing setup |

Allow the applicable ports through the host firewall. The ServerEmus configuration used by the original setup was:

```json
{
  "Servers": [
    { "Name": "UbiServices",    "Port": 443,   "UseUDP": false, "UseCerts": true  },
    { "Name": "StormDetect01",  "Port": 11000, "UseUDP": true,  "UseCerts": false },
    { "Name": "StormDetect02",  "Port": 11001, "UseUDP": true,  "UseCerts": false },
    { "Name": "StormTraversal", "Port": 11005, "UseUDP": true,  "UseCerts": false },
    { "Name": "StormRelay",     "Port": 12000, "UseUDP": true,  "UseCerts": false }
  ],
  "CertDetails": [
    { "Name": "UbisoftCert", "Password": "", "IsMainCert": true }
  ]
}
```

Place `UbisoftCert.crt` and `UbisoftCert.key` in the server's `Cert` directory. A self-signed certificate is expected, but a client accepts it only when the correct game profile has a verified TLS bypass, `bypass_tls_verify=1`, and the server's key in `tls_pin_sha256` (see [Pinning the server's key](#pinning-the-servers-key)).

## Install

For each game, rename its original Bink library once, then copy the matching artifact and `hook.config` beside the game executable:

| Game | Shim artifact | Preserve original as |
| --- | --- | --- |
| Far Cry 3 | `build/x86/farcry3_shim/binkw32.dll` | `binkw32_real.dll` |
| Far Cry 4 | `build/x64/farcry4_shim/bink2w64.dll` | `bink2w64_real.dll` |
| Far Cry 5 | `build/x64/farcry5_shim/bink2w64.dll` | `bink2w64_real.dll` |
| Far Cry New Dawn | `build/x64/farcrynewdawn_shim/bink2w64.dll` | `bink2w64_real.dll` |
| Splinter Cell Blacklist | `build/x86/splintercellblacklist_shim/bink2w32.dll` | `bink2w32_real.dll` (in `src/SYSTEM`, beside `Blacklist_DX11_game.exe`) |
| Ghost Recon Future Soldier | `build/x86/ghostreconfuturesoldier_shim/binkw32.dll` | `binkw32_real.dll` |

Files that share a name are not interchangeable: the three x64 `bink2w64.dll` builds, and the two x86 `binkw32.dll` builds (FC3 and Future Soldier), each carry a different game adapter.

## Game profiles and TLS RVAs

These values are relative to the listed module.

| Game/profile | Main module | Resolver strategy | TLS verifier RVA and behavior |
| --- | --- | --- | --- |
| Far Cry 3 (`fc3-pc-2018`) | `FC3_d3d11.dll` or `FC3.dll` | Static IAT plus dynamic `GetProcAddress`; classic Winsock names and ordinals | No safe default. A verified override also needs the x86 `__stdcall` argument-byte count. |
| Far Cry 4 (`fc4-fc64-rva-024134f0`) | `FC64.dll` | Direct `ws2_32` export detours because the packed module's import table is unusable | `0x024134f0`, `X509_verify_cert`; forced success with per-thread hardware breakpoints. |
| Far Cry 5 (`fc5-fc_m64-rva-03e01eb0`) | `FC_m64.dll` | Early `GetProcAddress` interception; `getaddrinfo` by name and `gethostbyname` by ordinal 52 | `0x03e01eb0`; forced success and clears the verifier error field at object offset `0x17c`. |
| Far Cry New Dawn (`fcnd-fc_m64-67ef9b27`) | `FC_m64.dll` | Static Winsock IAT, including `gethostbyname` ordinal 52 | `0x03e07d00`; forced success and clears the verifier error field at object offset `0x17c`. |
| Splinter Cell Blacklist (`scbl-pc-2425`) | `Blacklist_DX11_game.exe` or `Blacklist_game.exe` (the executable is the engine) | Static Winsock IAT: classic calls by ordinal, `WSA*` by name; bound from DllMain, ahead of the entry point | None needed: the OnlineConfig bootstrap is plain HTTP and RendezVous is PRUDP. |
| Ghost Recon Future Soldier (`grfs-pc-2013`) | `Future Soldier DX11.exe` or `Future Soldier DX9.exe` | As Blacklist | None needed, as Blacklist. |
| Assassin's Creed Brotherhood (`acb-pc-2011`) | `ACBMP.exe` (the 2011 multiplayer executable; the proxy also loads into `ACBSP.exe`, which launches it) | As Blacklist: classic calls by ordinal, `WSA*` and `getaddrinfo` by name. `*.ubi.com` and `*.ubisoft.com` are redirected too, because a missed lookup reaches Ubisoft's still-running ACB RendezVous hosts | None needed: plain-HTTP OnlineConfig, then PRUDP. |

Blacklist and Future Soldier are pre-UbiServices titles like FC3: the only hostnames in either binary are the three `*onlineconfigservice.ubi.com` bootstrap hosts, and everything after that (the RendezVous sandbox, Storm/NAT, tracking) comes out of the OnlineConfig document the server serves — so the server's title entry decides where the game goes next. The `onlineConfigID` each sends is `967fad701a3648d8bf099f07207f4a73` for Blacklist (`3d33c627fd494564932ee0ad3cca365c` on its alternate-environment flag) and `23ad683803a0457cabce83f905811dbc` for Future Soldier; the server has to know these to answer `/OnlineConfigService.svc/GetOnlineConfig`.

Both titles log in the way Far Cry 3 does: the identity is the shim's, not the Uplay or Orbit DLL's, and the launch is proved on the game's own socket. Each adapter carries the three facts that takes -- the local UDP port the game binds its RendezVous socket to (Blacklist 3074, Future Soldier 2347; neither is an immediate in the executable, both are settled from the bind that every RendezVous packet then leaves from), the server's authentication port the proof goes to (6572 and 6574; the server keys launches by the port they arrive on, so FC3's 6570 would bind nothing this title's login could find), and the title id the desktop client's bridge is asked for (`splinter-cell-blacklist`, `ghost-recon-future-soldier`).

Where each title reads its name from, and what the shim answers there with `login_name`:

| Title | The game's identity call | Hooked in |
| --- | --- | --- |
| Far Cry 3 | `-login <name>` on the engine's command line (the 2022 build never builds its Uplay identity) | `src/games/farcry3/launch.cpp` |
| Splinter Cell Blacklist | `UPLAY_USER_GetUsername` / `GetPassword` / `GetAccountId` out-buffer imports of `uplay_r1_loader.dll` | `src/games/blacklist/identity.cpp` |
| Ghost Recon Future Soldier | `OrbitClient::GetLoginDetails` import of `ubiorbitapi_r2_loader.dll`, answered through the game's listener callback | `src/games/futuresoldier/identity.cpp` |
| Assassin's Creed Brotherhood | `/onlineUser:<name> /onlinePassword:<pw>` on `ACBMP.exe`'s command line (put there by `ACBSP.exe`); the shim's `GetCommandLineA` says `login_name` instead and adds `/launchedfromotherexec`, so `ACBMP.exe` can be started on its own. A name with a space cannot be carried. | `src/games/brotherhood/identity.cpp` |

The Uplay emulator (Blacklist) and the Orbit stub (Future Soldier) still have to be installed for everything else they provide -- friends and party init, savegames, the launcher check -- but their `upc.json` `Account.Name` and `orbit_stub.ini` `username` no longer decide who logs in and need not match anything. Without a `login_name` the shim leaves those imports alone and the DLLs' own values are used, as before.

Do not copy an RVA from one game or executable update to another. The shim logs the module PE timestamp and image size so a failing report can identify the actual build. For an updated supported build, add a new definition below the game's `versions/` directory rather than replacing an unrelated profile.

## Client `hook.config`

The minimum configuration for FC4, FC5, and New Dawn is:

```ini
redirect_ip=192.168.1.50
bypass_tls_verify=1
tls_pin_sha256=QRxKRhqbX1O9pZ4G+/fO+6UM6xFthLTXKQqcHusAQlo=
```

Far Cry 3 has no default verifier address. Keep bypass disabled unless both values have been verified against that exact DLL:

```ini
redirect_ip=192.168.1.50
bypass_tls_verify=1
tls_pin_sha256=QRxKRhqbX1O9pZ4G+/fO+6UM6xFthLTXKQqcHusAQlo=
rva_tls_verify=0x01234567
tls_verify_stack_bytes=8
```

The pin shown is an example; use your own server's.

### Pinning the server's key

The server's certificate is self-signed for Ubisoft's hostnames, so no game trusts it, and the bypass makes the game's certificate check pass. It used to pass *every* check, on every connection. Anybody on a player's network (café Wi-Fi, a compromised router) could then pose as the server and feed the game's parsers whatever they liked.

The bypass now trusts one server: the one whose key is in `tls_pin_sha256`.

1. **Reading the key.** On every TCP connection the game makes, the shim reads the server's certificate off the wire as it arrives. TLS 1.2 and older send it in the clear, and every title here speaks one of them.
2. **Refusing anything else.** The shim shuts down any connection that presents another key, or that hides it. Hiding it means TLS 1.3, an anonymous cipher, or encryption before any certificate (which is also how CVE-2014-0224 looks).
3. **Letting the check pass.** The game's check passes only in the five seconds after a pinned key was read.
4. **Every other check.** Any other check runs the game's own verifier, unchanged, which refuses a self-signed certificate. So a connection whose bytes the shim cannot see fails closed rather than open.

The pin is RFC 7469's `pin-sha256`: base64 of the SHA-256 of the certificate's SubjectPublicKeyInfo. There are two ways to get it:

- **From the game server's startup log:**
  ```
  Cert Cert/UbisoftCert.crt: shims trust it with tls_pin_sha256=QRxKRhqb...
  ```
- **With openssl:**
  ```sh
  openssl x509 -in UbisoftCert.crt -pubkey -noout | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | base64
  ```

It pins the key, not the certificate, so renewing a certificate with the same key changes nothing. To move to a new key, list both pins, comma-separated, until every player has updated. At most two pins are accepted.

Without a pin, `bypass_tls_verify=1` arms nothing, and `hook.log` says how to get one.

`hook.log` shows what happened on each connection:

- `[tls] <server> presented the pinned server key`: trusted.
- `[tls] refused the connection to <server>: ...`: somebody else, or your server with a key that isn't pinned.
- `[tls] cannot read the certificate on the connection to ...`: this title reads the connection through a path the shim doesn't hook, so the game's own verifier decides.
- `certificate check #N with no pinned server key read beforehand`: a check the shim couldn't vouch for.

If the last two appear for your own server, that title's TLS reads still need hooking. This is a known open question for Far Cry 4, whose packed module's import table the shim cannot patch.

Common options:

Each line is one `key=value`, and a line may be at most 639 bytes. A longer line is ignored as a whole and `hook.log` names it: older shims read it in pieces and treated each piece as an entry of its own, so a value that ran past the limit could end in a second entry nobody wrote. The desktop client refuses to write such a line, and refuses a `login_name` from a game server that isn't a plain name of at most 63 bytes.

| Key | Meaning |
| --- | --- |
| `redirect_ip` | IPv4 address returned for the game profile's Ubisoft service hosts. |
| `redirect_all_dns` | Redirect every IPv4 DNS result. Use only while discovering a missing hostname. |
| `bypass_tls_verify` | Enable the profile's verified certificate-verifier hook, for the server key in `tls_pin_sha256` only. |
| `tls_pin_sha256` | The game server's TLS key: base64 SHA-256 of its SubjectPublicKeyInfo, or two such pins, comma-separated, during a key change. Required for the bypass to arm. See [Pinning the server's key](#pinning-the-servers-key). |
| `rva_tls_verify` | Override the profile RVA for a separately verified build. |
| `tls_verify_stack_bytes` | FC3/x86 stack cleanup required when skipping a `__stdcall` verifier. |
| `capture_tcp` | Capture traffic associated with the redirected address. |
| `log_rdv_full` | Full UDP/Storm packet logging. |
| `log_tcp_full` | Full TCP logging. |
| `trace_getprocaddr` | Log dynamic API resolution. |
| `capture_uplay`, `trace_uplay` | Structured Uplay SDK call diagnostics (session/party/friends/consumables) on FC3, FC5, and New Dawn. `trace_uplay` additionally logs every other named `UPLAY_*` resolution on FC5/New Dawn (x64); on FC3 (x86) that generic catch-all is unavailable, so only the named calls above are logged — GetCredentials and its completion APIs are deliberately never wrapped, on any title. |
| `trace_cng`, `trace_cng_payload` | FC5 BCrypt diagnostics. |
| `capture_ssl` | Decrypted SSL read/write capture where the game profile has verified RVAs (New Dawn currently). |
| `trace_game_log` | Enable the verified FC_m64 native game-log callback. |
| `dump_module` | Press F10 to dump the live game module beside the shim. |
| `trace_winhttp` | Blacklist-only. Log every WinHTTP call with its result; the game's ProxyDetection step is a WinHTTP probe that the Winsock hooks cannot see. |
| `trace_points` | FC3-only comma-separated `module:rva:label` INT3 trace points. |
| `login_name` | The RendezVous login name. FC3 puts it on the engine's command line as `-login <name>` (replacing any `-login` already there) so no Steam launch option is needed; Blacklist and Future Soldier answer their Uplay / Orbit credential calls with it (see above). The Playforward desktop client writes this from what the game server will render; set it by hand only on a machine with no client. At most 63 bytes (UTF-8); a longer one is ignored. The password each title sends is a stand-in, and the server never checks it. |
| `playforward_launch` | Default `1`. Before the game logs in, prove a Playforward launch to the game server on the game's own RendezVous socket, so the server binds *this socket* -- not this machine's address -- to the player. The shim asks the desktop client's bridge pipe for the launch (once per game process) and speaks a four-datagram exchange (`src/core/playforward/launch_envelope.h`) right after the game binds its RendezVous socket (FC3 and Blacklist UDP/3074, Future Soldier UDP/2347); the key never leaves the process. With no client running it is skipped, and the client's address binding carries the login as before. Set `0` on a server without Playforward, where the HELLOs are only noise and cost the bind up to 3 s. |
| `build_fixes` | FC3 only, default `1`. The code repairs the 2022 build needs online, formerly `trace_points` entries every install had to carry: the decommission-notice check (`true+4` at `0x1167d90`), the uninitialised containers in the UPlayPC friend provider (`0x1219340`, the crash at `+0x12194dd` after going online) and the two selector constructors (`0x12181d0`, `0x1218290`), and the stats login listener's pre-login crc32(`login_name`) call (`retifcrc+0x10` at `0x12ab180`, needs `login_name`). Found by signature in `FC3_d3d11.dll` / `FC3.dll` and logged as `[fixes]`; other builds are left alone. A `trace_points` entry on a patched site is skipped. |
| `online_autologin` | FC3 only, default `1`. The 2022 build only goes online when the player opens the social Wall (Right / Y on the main menu): the 2018 menu event that did it automatically (`SinglePlayerMenuCheckConnectionStatus`) was removed. This runs the game's own Wall handler once the session manager reaches the online-ready main menu (slot state `0xd`), from the manager's per-frame update, so it needs no focus or input. Found by signature in `FC3_d3d11.dll` / `FC3.dll`; on any other build (2018 included, which signs in by itself) it logs why and does nothing. Supersedes `menu_autopress`, which stands down when this is armed. Details: farcry-lan docs/63 §17. |
| `prudp_port` | Overrides the profile's RendezVous listener port -- the local UDP bind the launch proof runs on (FC3 3074, Blacklist 3074, Future Soldier 2347). Only for a build that binds elsewhere, and only from a capture: with `log_rdv_full=1` every wildcard bind is logged, and the one the RendezVous traffic then leaves from is the port. |
| `launch_port` | Overrides the profile's server port the launch proof is sent to: the title's RendezVous authentication port (FC3 6570, Blacklist 6572, Future Soldier 6574). The game server keys launches by the port they arrive on, so this must be the port the same title's login goes to; only for a server whose title ports differ from `Titles.json`'s defaults. |
| `playforward_presence` | Default `1`. While the game runs, hold a `playing <title>` request open on the desktop client's bridge (same pipe, then port, as below), so friends see the player in this game; the client turns them back to online when the connection closes, which the operating system does however the game ends. With no client running the shim tries again every 5 s, logging only the first miss. Only titles Playforward knows (FC3, Blacklist, Future Soldier) report. Set `0` to keep the game from reporting itself. |
| `launch_pipe` | Default `playforward-game-bridge`, the desktop client's bridge pipe name. Only for a client built to listen elsewhere. |
| `bridge_port` | Default `24771`, the loopback port the desktop client's bridge answers on. The shim asks over the pipe first and falls back to `127.0.0.1:<bridge_port>`, which is the path every launch under Wine or Proton takes: there the client's pipe is in the host's namespace and the prefix's is its own, so the pipe is never found. The client writes the port it actually bound into this file, so this default only matters for a game launched before the client has ever provisioned it. |
| `redirect_http_port` | Default `0` (off). A TCP connect to `redirect_ip:80` goes to this port instead -- for a server run unprivileged on a development machine, which cannot bind 80. |
| `agora_root_key` | Splinter Cell: Conviction only. Path (absolute, or relative to the game executable) of the root public key to trust for the Agora account service on TCP 3081, a binary X.509 SubjectPublicKeyInfo (DER). The game verifies the service's certificate against a key it loads from `DemonWareAccountSecureKey.pub`, which is the original publisher's; when the file exists the shim hands the game this key instead (at the one call that imports it), so a certificate signed by the server's matching private key verifies. Default `conviction_agora_root.pub.der` beside the executable; with no such file the game's own key is left alone. Everything is logged as `[scc-agora]`. |

### How the shim finds the desktop client

The launch proof needs a launch, and the launch comes from the Playforward desktop client over a one-line local protocol. The shim looks in two places, in this order:

1. The named pipe `\\.\pipe\playforward-game-bridge` (`launch_pipe`). This is what a game running natively on Windows finds.
2. `127.0.0.1:<bridge_port>`. This is what a game under Wine or Proton finds: Wine gives the prefix its own pipe namespace, so the client's pipe -- a host object on Linux and macOS -- is not there to be opened, and only a socket crosses that boundary. Wine does share the host's loopback stack.

With neither answering, the game logs in the way it did before any of this existed: recognised by the address the client bound, or not at all. `hook.log` says which happened on every launch.

## Uplay emulator

Install the matching Uplay emulator loader beside each game. Every machine must have a distinct `AccountId` and clients sharing an ID discard one another's LAN announcements. LAN co-op is disabled by default: set `Coop.Enabled` to `true` only when testing co-op, then set `Coop.IsHost` to `true` on the hosting client and `false` on the peer when the emulator supports those settings.

## Launch and verify

1. Start the REST and Storm server stack.
2. Launch both clients and inspect `hook.log` beside each shim.
3. Confirm a DNS redirect line appears for the server hostname.
4. Confirm the resolver strategy matches the table above.
5. Exercise an HTTPS request. `presented the pinned server key` is logged as the certificate arrives, then `verifier bypass active` on the first verifier call. A `refused the connection` or `cannot read the certificate` line instead means the pin or the title's hooks need attention (see [Pinning the server's key](#pinning-the-servers-key)).
6. Create the co-op session on the host and watch the emulator/Storm logs for both distinct accounts.
