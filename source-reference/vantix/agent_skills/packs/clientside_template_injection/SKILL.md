# Client-Side Template Injection (CSTI)

Front-end frameworks that interpolate user input through their template engine (`{{...}}`, `${...}`, `<%= ... %>`) can be coerced into evaluating attacker-supplied expressions. Severity matches DOM XSS when the framework's sandbox can be escaped (`{{constructor.constructor('alert(1)')()}}`).
