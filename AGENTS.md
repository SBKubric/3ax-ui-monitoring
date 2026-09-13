# 3ax-ui-monitoring

Project guide for AI assistants.

- Read `CONTEXT.md` first and use its vocabulary (mon-server, mon-client, target, path, probe account, tunnel probe, heartbeat, registration request, pairing code, client token, config revision, unverified cycle, admin UI). Terms shared with the panel repo (real server, proxy front, host override, tunnel subscription) are copied there from [SBKubric/3ax-ui-proxy/CONTEXT.md](https://github.com/SBKubric/3ax-ui-proxy/blob/main/CONTEXT.md); the panel repo is the source of truth for them.
- Specs live in `docs/spec/`: `mon-server.md`, `mon-client.md`, `mon-protocol.md`. The panel side (contract `/mon/v1/*`, panel tables and UI) lives in the panel repo under `docs/spec/monitoring-*.md`; decisions are recorded in the panel repo's `docs/adr/` (0003 for monitoring).
- Planning happens on the panel repo's issue tracker (wayfinder map #20); this repo holds the implementation once it starts.
