# Snare 1.2.0rc2 — Windows review

Download the `Snare-Windows-review` artifact from the **Windows review build** workflow. Unzip it, then run `Snare-Windows.exe`. Python is not required. The executable is Windows x64 and portable. This test build is not Authenticode-signed.

Verified 1.2.0rc2 build: [download Windows artifact](https://github.com/IamSodikov/snare/actions/runs/36715900029/artifacts/11096461333). The GitHub artifact contains `Snare-Windows-review.zip`; extract that ZIP too. The artifact expires on October 30, 2026. Source build commit: `dc1aba0ca2e95980a631fb359229a1a4caa9a7de`.

The artifact contains `SHA256SUMS`, build information and the result of a packaged smoke test. The test starts the actual executable, opens its Qt UI, starts its internal proxy, restarts the proxy, waits beyond the previous kill timer, sends a real local mock request and verifies the stored final capture.

## What changed

- Fusion widgets, bundled Noto Sans, one light palette and consistent button sizes on Windows, Linux and macOS. Emoji-dependent controls were removed. The compact main window fits 1024×768.
- Cancellable engine stop timer and own-addon readiness; previous Windows proxy/PAC values are restored on stop, restart, failure and close. A stale snapshot is recovered on the next single-instance startup.
- Versioned JSON patches support null, false, zero, empty collections and literal deletion-marker strings. Body edits recompute patches; truncated body replacement is blocked.
- Click-to-edit bodies and fields; selection/Ctrl+C and section context menus for copy/edit/discard; original/modified/diff, raw/hex preview, lazy large-body display, pending/duration/size columns, method/status/mock filters, pinning and pause-view.
- Copy as cURL (POSIX shell syntax), deliberate Replay through the proxy, sanitized HAR import/export, rule reorder, per-rule match explanations, hits/scenario/drop dashboard and reset.
- Mobile interface selector, copy/QR, optional LAN proxy password, include/bypass host regex, optional recording/redaction, time/byte/row retention and disk maintenance.
- WebSocket messages and SSE frames, local OpenAPI JSON example import (disabled rules), and `snare-cli` for headless runs and matching.
- Invalid-rule backups/recovery, aligned version and assets, HTTPS-only update checks, semantic version comparison, SHA256 verification and cooperative download cancellation. Downloads open beside the working application; the updater no longer deletes/replaces the installed executable.

## 1.2.0rc2 interaction changes

Replay and Pin/Unpin appear on the hovered traffic row and act on that row without replacing the current draft selection. While Pause view is enabled, the row also shows Play to resume list updates. Pause view does not intercept or hold network requests. The row context menu provides the same actions. Body editing starts with a click; large bounded previews open their full editor on double-click or via their context menu. Truncated and binary body safeguards remain in place.

## Windows check

1. Open the program in `Start · Stopped`, click **Start**, and confirm the same button turns green with `Stop · Running`. Amber means starting/stopping or connection changes; red means an error.
2. Open **Connection / Storage**, enable Windows System Proxy, then send a test HTTP request. For HTTPS trust the CA shown by **Mobile Setup**.
3. Select traffic, edit response JSON, click **Apply → Mock**, repeat the request, then inspect **Original / Modified / Diff**.
4. Restart several times and wait at least five seconds. Change the port with **Apply connection**.
5. Stop and close the program. Confirm your previous Windows proxy configuration is restored.
6. Try the compact window, keyboard focus, 125–200% display scaling, HAR exchange and mobile connection.

## Limits and operational notes

- Authenticode signing and an independent release signing key are not available for this review. SHA256 over verified GitHub HTTPS checks bytes; it is not a substitute for an independent signature. Automatic in-place installation is intentionally absent.
- Redaction masks common header/query/JSON secrets. Arbitrary text, binary bodies and WebSocket/SSE payloads need manual review before sharing.
- Original/modified snapshots and stream buffers are bounded; previews and stream history are not a lossless archival protocol capture.
- OpenAPI import uses local JSON examples, not full schema generation or remote `$ref` resolution. Scenario state is global to a workspace; per-client state is not implemented.
- Real Android/iOS certificate trust and native display scaling still need device/user verification. CA installation alone does not bypass certificate pinning.
- SQLite byte quotas bound logical stored documents; explicit **Reclaim disk** reclaims file allocation. Queue overflow is visible in the dashboard.

## Validation

GitHub Actions run 36715900029 passed on September 30, 2026: Linux, Windows and macOS each passed 48 tests, Ruff E4/E7/E9/F and the real UI/internal-proxy smoke. The native Windows x64 executable also passed its packaged smoke: two proxy starts and a completed persisted local mock after the previous restart timeout. Frozen Windows proxy logs now use an explicit channel instead of unavailable windowed standard streams.

Local pip check passed. The local HTTP/HTTPS suite passed Local/Replace/Patch/Request Patch, gzip, duplicate headers, HEAD/204, fixtures, delay, scenarios and 80/80 concurrent captures. A 1,938,890-byte JSON preview opened in about 80 ms in one offscreen measurement; this is not a cross-machine benchmark. CI uses offscreen Qt; native display scaling and device certificate setup still need user verification.
