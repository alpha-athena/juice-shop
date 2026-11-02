# Athena notes

2026-11-02 — Looked at routes/search.ts and server.ts after the finding that `/rest/products/search` builds its SQL by string concatenation from the `q` parameter (UNION-based injection reads the Users table). Ruled out parameterising the query because the product list is also served by `/api/Products`. Changed server.ts to stop registering the search route and replaced the search API test with one that proves the injection payload no longer reaches the database (404). Why: with no route there is no query to inject into.
