# DOM Tracer Operator Guide

The DOM Tracer is an analyst-driven companion for finding DOM XSS and client-side injection vulnerabilities. It instruments the managed browser in real-time, surfaces source reads and sink writes as they happen, and lets you stamp a canary value to trace source→transformation→sink chains.

## Overview

| Component | Role |
|---|---|
| `domTracerDriver.ts` | CDP attach, isolated-world setup, console bridge |
| `domTracerInstrumentation.ts` | JS payload injected per page navigation |
| `domTracerEngine.ts` | Off-thread session/canary/event reducer |
| `src/components/domTracer/` | Analyst panel (Sources, Sinks, Canary Composer, Flow Graph) |
| `src/data/domTracerSinks.ts` | Registry of 21 sink descriptors with severity + CWE |

## Quick Start

1. Open a project and start the managed browser (Proxy → Launch Browser).
2. Open the **Tracer** tab in the Proxy screen.
3. Navigate to a target page in the managed browser. Sources appear immediately.
4. Click **Inject Canary** to stamp a nonce value (`pf-xxxxxxxx`).
5. Interact with the page — click links, submit forms, change routes.
6. Matched sinks appear in the Sinks table with a green **MATCHED** badge.
7. The Flow Graph visualises the source → transformation → sink chain.
8. Click **Promote to Issue** to attach the full trace as scanner evidence.

## Instrumented Sources

| Source | Signal |
|---|---|
| `location.search` | URL query string on page load and navigation |
| `location.hash` | Fragment identifier |
| `location.href` | Full URL |
| `document.referrer` | HTTP Referer value |
| `window.name` | Window name (cross-origin persistence vector) |
| `document.cookie` | Cookie jar read |
| `postMessage` | Incoming `message` events (origin + data) |
| `localStorage.getItem` | Local storage reads |
| `sessionStorage.getItem` | Session storage reads |
| `canary-inject` | When you manually inject a canary nonce |

## Instrumented Sinks

| Sink | Severity | CWE | Category |
|---|---|---|---|
| `innerHTML` | High | CWE-79 | DOM XSS |
| `outerHTML` | High | CWE-79 | DOM XSS |
| `insertAdjacentHTML` | High | CWE-79 | DOM XSS |
| `document.write` | Critical | CWE-79 | DOM XSS |
| `document.writeln` | Critical | CWE-79 | DOM XSS |
| `eval` | Critical | CWE-95 | Code Execution |
| `Function` (constructor) | Critical | CWE-95 | Code Execution |
| `setTimeout` (string arg) | High | CWE-95 | Code Execution |
| `setInterval` (string arg) | High | CWE-95 | Code Execution |
| `location.href` | Medium | CWE-601 | Open Redirect |
| `script.src` | High | CWE-95 | Script Injection |
| `iframe.src` | Medium | CWE-79 | Framing |
| `fetch.url` | Medium | CWE-918 | SSRF |
| `xhr.url` | Medium | CWE-918 | SSRF |
| `Worker` | High | CWE-95 | Code Execution |
| `importScripts` | High | CWE-95 | Code Execution |

## Canary Mode

The canary system lets you trace whether a specific value you control (the nonce) flows into a dangerous sink.

**Nonce format:** `pf-<8 random hex chars>` — short enough to fit most params, distinctive enough to avoid false matches.

**Stamping targets:** You can target a specific source by selecting it in the Canary Composer dropdown before injecting. If left blank, the nonce is set on `window.__pf_canary` only.

**Transformations detected:**

| Name | Example |
|---|---|
| raw | `pf-abc123` → `pf-abc123` |
| url-encoded | `pf-abc123` → `pf-abc123` (unchanged) or `%70%66-abc123` |
| html-encoded | `pf-abc123` → `&#112;f-abc123` |
| dash-to-underscore | `pf-abc123` → `pf_abc123` |
| case-normalized | `pf-ABC123` → `pf-abc123` |

## Safety Constraints

- Instrumentation is **only injected into in-scope managed-browser tabs**. Pages opened by the operator outside the managed browser are never touched.
- The tracer never modifies response bodies or intercepts TLS — it operates purely via CDP isolated-world script injection.
- Canary nonces are project-scoped and HMAC-validated when promoted to scanner issues.
- All tracer sessions are persisted in the project store and can be reviewed after the session ends.

## Sink Registry

Sink descriptors are in `src/data/domTracerSinks.ts`. Each descriptor has:

```ts
{
  name: string;         // sink identifier (matches instrumentation)
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe: string;          // e.g. 'CWE-79'
  category: string;     // e.g. 'dom-xss'
  description: string;
}
```

To add a new sink, append a descriptor here and add the corresponding hook to `domTracerInstrumentation.ts`.

## Promoting to an Issue

When a canary reaches a high-severity sink:

1. The Sinks table shows a green **MATCHED** badge.
2. The Flow Graph shows the full chain with transformation label.
3. Click **Promote to Issue** (in the Sinks table Actions column or the Flow Graph toolbar).
4. ProxyForge creates a Scanner issue with:
   - Sink name and severity
   - Full source → transformation → sink chain
   - Canary nonce + evidence of reflection
   - CWE reference
   - Session ID for audit trail
