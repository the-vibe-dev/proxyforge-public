# Client-Side Storage Audit

Sensitive tokens (JWTs, refresh tokens) stored in `localStorage` are readable by any script on the same origin — including injected XSS. Cookies marked `HttpOnly` mitigate this; storage values cannot. The probe dumps both stores post-login and flags JWT-shape / email-shape values.
