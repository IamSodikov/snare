# Snare 1.2.0rc1 — Windows review

Download the `Snare-Windows-review` artifact from the **Windows review build** workflow. Unzip it, then run `Snare-Windows.exe`. Python is not required. The executable is Windows x64 and portable. This test build is not Authenticode-signed.

The artifact contains `SHA256SUMS`, build information and the result of a packaged smoke test. The test starts the actual executable, opens its Qt UI, starts its internal proxy, restarts the proxy, waits beyond the previous kill timer, sends a real local mock request and verifies the stored final capture.

## What changed

- Fusion widgets, bundled Noto Sans, one light palette and consistent button sizes on Windows, Linux and macOS. Emoji-dependent controls were removed. The compact main window fits 1024×768.
- Cancellable engine stop timer and own-addon readiness; previous Windows proxy/PAC values are restored on stop, restart, failure and close. A stale snapshot is recovered on the next single-instance startup.
- Versioned JSON patches support null, false, zero, empty collections and literal deletion-marker strings. Body edits recompute patches; truncated body replacement is blocked.
- Explicit Edit/Discard drafts, original/modified/diff, raw/hex preview, lazy large-body display, pending/duration/size columns, method/status/mock filters, pinning and pause-view.
- Copy as cURL (POSIX shell syntax), deliberate Replay through the proxy, sanitized HAR import/export, rule reorder, per-rule match explanations, hits/scenario/drop dashboard and reset.
- Mobile interface selector, copy/QR, optional LAN proxy password, include/bypass host regex, optional recording/redaction, time/byte/row retention and disk maintenance.
- WebSocket messages and SSE frames, local OpenAPI JSON example import (disabled rules), and `snare-cli` for headless runs and matching.
- Invalid-rule backups/recovery, aligned version and assets, HTTPS-only update checks, semantic version comparison, SHA256 verification and cooperative download cancellation. Downloads open beside the working application; the updater no longer deletes/replaces the installed executable.

## Windows check

1. Start the program and confirm `Running` appears.
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

## Local validation before Windows CI

Linux/Python 3.12: 43 tests passed; Ruff E4/E7/E9/F and pip check passed. The actual UI/internal-proxy smoke passed two engine starts and a local HTTP mock after the old restart timeout. The local HTTP/HTTPS suite passed Local/Replace/Patch/Request Patch, gzip, duplicate headers, HEAD/204, fixtures, delay, scenarios and 80/80 concurrent captures. A 1,938,890-byte JSON preview opened in about 80 ms in one offscreen measurement; this is not a cross-machine benchmark. Native Windows CI has not run yet because source upload requires explicit user approval.
