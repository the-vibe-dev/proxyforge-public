# HTTP Verb + Parameter Abuse

Routes that only handle GET often forget to reject non-GET methods — TRACE leads to XST, PUT/DELETE leads to write/delete primitives. Parameter pollution exploits parser disagreement between layers (front-end takes first value, back-end takes last, or vice versa).
