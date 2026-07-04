# Web Messaging (postMessage) Hunter

Scans every linked JS bundle for `window.addEventListener('message', handler)` calls whose handler body never references `event.origin` / `e.origin`. Each match is a cross-origin postMessage acceptance surface — an attacker page can iframe the target and send arbitrary messages.
