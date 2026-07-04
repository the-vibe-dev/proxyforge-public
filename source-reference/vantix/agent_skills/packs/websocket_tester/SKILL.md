---
name: websocket_tester
description: Test WebSocket subscriptions for cross-user data leaks, replay attacks, permission bypasses, and malformed-event handling.
---
# WebSocket Tester

WebSocket endpoints handle realtime subscriptions, notifications, and collaborative features. The attack surface spans authentication timing (can you subscribe before login?), channel authorization (can user A see user B's channel?), and event validation (do malformed events crash the server or leak state?). This class is often overlooked because WebSocket traffic doesn't appear in traditional HTTP logs.

This pack composes with `packs/authz_matrix_tester/SKILL.md`, `packs/api_security/SKILL.md`, and `shared/evidence_rules.md`.

## When to Use

- The application uses WebSocket for realtime features (chat, notifications, live feeds, collaborative editing).
- Multiple users share channels or subscriptions.
- The application has authentication and permission boundaries.
- Events are sent or received over the WebSocket.

## Operating Rules

- **Connection state**: track whether the WebSocket is authenticated, and when authentication is required relative to subscription.
- **Channel taxonomy**: document every channel, its visibility (public/private/team/org), and who can read/write.
- **Event validation**: test whether the server validates event type, structure, and permissions before processing.
- **Timing**: test whether events sent before, during, or after logout/permission-revocation are processed differently.
- **Scope**: confirm testing of WebSocket channels is in scope.

## Phase 1: Channel Inventory

Map every WebSocket channel and subscription model:

1. **Public channels**: everyone can subscribe (e.g., notifications, broadcasts).
2. **Private channels**: only the owner can subscribe (e.g., user A's notifications).
3. **Team/org channels**: members of a team/org can subscribe.
4. **Direct message channels**: only the two participants can subscribe.
5. **Collaborative channels**: multiple writers; permission model varies.

## Phase 2: Connection Lifecycle Tests

### A. Subscribe Before Authentication
- Open WebSocket connection (unauthenticated).
- Attempt to subscribe to a private channel.
- Expected: rejection or no data sent.
- Bug: subscription succeeds; data is sent to unauthenticated user.

### B. Subscribe After Logout
- User A logs in, opens WebSocket, subscribes to private channel.
- User A logs out (session is invalidated).
- WebSocket is still open.
- Attempt to send an event on the WebSocket.
- Expected: rejection (not authenticated).
- Bug: event is processed; state changes occur without authentication.

### C. Cross-User Channel Subscribe
- Connect as User A.
- Authenticate as User A.
- Attempt to subscribe to User B's private channel (e.g., `/user/B/notifications`).
- Expected: rejection (not authorized).
- Bug: subscription succeeds; User A receives User B's data.

## Phase 3: Event Handling Tests

### A. Send Event Before Authentication
- Open WebSocket connection.
- Send an event (e.g., `{"type": "message", "text": "hi"}`).
- Expected: rejection or error.
- Bug: event is processed without authentication.

### B. Send Malformed Event
- Send an event with invalid type (e.g., `{"type": "admin_promote", "userId": "..."}`).
- Expected: validation error or silent rejection.
- Bug: event is processed; state changes (user is promoted).

### C. Send Admin-Only Event as Non-Admin
- User A has role "Viewer".
- User A sends an event (e.g., `{"type": "audit_log_delete", "id": "..."}`).
- Expected: rejection (insufficient permissions).
- Bug: event is processed; admin action occurs.

## Phase 4: Subscription-Change Tests

### A. Modify Channel ID in Subscription
- User A subscribes to `/org/123/chat`.
- Intercept the subscription message and change `123` to `456` (another org).
- Expected: rejection or subscription to org 456 fails.
- Bug: User A subscribes to org 456 and receives its messages.

### B. Replay Old Messages
- User A receives a message from User B on a public channel.
- Intercept and replay the message (same timestamp, content).
- Expected: server deduplicates (same ID or timestamp) or rejects.
- Bug: message is processed again; duplicate action or state change.

### C. Permission Removed, Event Sent
- User A has permission to subscribe to channel C.
- Admin removes User A's permission.
- User A's WebSocket is still connected to C.
- User A sends an event on C.
- Expected: rejection or event is silently dropped.
- Bug: event is processed; User A still has write access despite permission removal.

## Phase 5: Disconnect and Resume

### A. Reconnect with Old Session ID
- User A connects, receives a session or connection ID.
- User A disconnects.
- User A attempts to reconnect with the old session ID.
- Expected: rejection (session expired or new connection required).
- Bug: User A reconnects and is subscribed to old channels.

## Evidence Capture

For each test, document:

1. **Baseline**: list of subscribed channels, authenticated user, permissions.
2. **Request**: WebSocket frame (as JSON or hex).
3. **Response**: server response or event received.
4. **Post-state**: list of channels, data received, or state changes.

Store under `websocket_<test>_<timestamp>/`:
- `01_baseline.txt` — subscription state before the test.
- `02_request.txt` — WebSocket frame sent.
- `03_response.txt` — server response or event received.
- `04_post_state.txt` — subscription state and data received post-test.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then:

- [ ] The channel or subscription model is documented and in scope.
- [ ] Authentication state is clearly documented (authenticated vs. unauthenticated).
- [ ] The test mutation is a valid application scenario (not synthetic).
- [ ] Data leakage or state change is confirmed via post-state inspection.
- [ ] The finding is reproducible across multiple attempts.

## Exclusions

- Do not test WebSocket endpoints out of scope.
- Do not spam or flood the WebSocket (DoS not allowed).
- Do not exfiltrate user data beyond the proof of visibility.

## See Also

- `agent_skills/packs/authz_matrix_tester/SKILL.md` — authorization testing.
- `agent_skills/packs/api_security/SKILL.md` — API authentication and session binding.
