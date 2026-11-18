# Exploit Chains

A single Finding is a door. A chain is the room behind it. The Attacker must ask after every hit: **what does this unlock next?** Report the chain as one impact, not as disconnected findings.

Use these as patterns, not scripts. Each step must still be proven with evidence and stay inside the Proof Cap.

## 1. Recon leak → token → account takeover

- **Prerequisites:** exposed source map, debug endpoint, or `.git`.
- **Steps:** recover an API token or signing key; replay it against the API; access a privileged object.
- **Why it matters:** an information leak becomes Critical when the leaked material is a credential.
- **Report as:** one chain with the leak as step 1, the replay as step 2, and the takeover as impact.

## 2. IDOR → tenant breakout → bulk export

- **Prerequisites:** an object ID that is not scoped to the session, plus an export or list route.
- **Steps:** read one foreign object; find the list endpoint; export the collection; stop at the Proof Cap (one page or one record).
- **Why it matters:** a single IDOR is often rated Medium until the attacker shows that enumeration turns it into a mass leak.
- **Stop:** prove one foreign record and the existence of the list route. Do not exfiltrate the dataset.

## 3. SSRF → internal service → control plane

- **Prerequisites:** a URL fetch with weak allowlisting, plus an internal service or mock metadata endpoint.
- **Steps:** reach the local mock metadata; recover a token; use the token against a local internal API.
- **Why it matters:** SSRF severity depends on what the internal network exposes.
- **Stop:** one mock credential and one internal response. Do not scan the network.

## 4. XSS → CSRF → admin action

- **Prerequisites:** stored XSS in a page an admin views, plus a state-changing admin action without a CSRF token.
- **Steps:** store the payload; wait for or simulate the admin view; issue the action from the admin's session.
- **Why it matters:** XSS in a user page can become admin compromise.
- **Stop:** prove the action with a seeded admin account and a reversible change.

## 5. Upload → path traversal → code execution

- **Prerequisites:** an upload that preserves the filename or a path parameter, plus a served directory.
- **Steps:** upload a marker with a traversal filename; request the written path; if the server executes it, run `id` only.
- **Why it matters:** upload plus traversal plus execution is a common Critical chain.
- **Stop:** one marker file and one `id` output. Do not leave a webshell.

## 6. JWT weak secret → role forgery → admin API

- **Prerequisites:** an HS256 JWT and a guessable secret.
- **Steps:** crack or guess the secret; forge `role=admin`; call an admin API.
- **Why it matters:** the token is the authorization boundary; a weak key collapses it.
- **Stop:** one admin read. Do not modify data.

## 7. Business-logic race → double spend

- **Prerequisites:** a redeem, refund, or transfer endpoint without an atomic constraint.
- **Steps:** send parallel requests with one coupon or balance; count successes; show the duplicated value.
- **Why it matters:** the app works as designed per request; the bug is in the concurrency model.
- **Stop:** show the duplicated credit in the seeded ledger. Restore the fixture.

## 8. Open redirect → OAuth code theft

- **Prerequisites:** an open redirect on the OAuth callback domain and a loose `redirect_uri` check.
- **Steps:** craft an authorize URL with the redirect; capture the code at a local listener; exchange it.
- **Why it matters:** the redirect turns into account takeover.
- **Stop:** use a local client and a seeded account. Never touch a real identity provider.

## 9. Deserialization → RCE → local privilege check

- **Prerequisites:** an unsafe deserialization sink and a gadget or a pickle entry point.
- **Steps:** send a benign `id` payload; confirm execution; check `id`/`hostname` only.
- **Why it matters:** deserialization is usually a direct Critical.
- **Stop:** one command. Do not establish a shell or persist.

## 10. Dependency CVE → reachable exploit

- **Prerequisites:** a known vulnerable component and a reachable code path.
- **Steps:** fingerprint the version; read the advisory; reproduce the smallest proof; confirm the path is reachable from the app.
- **Why it matters:** an unreachable CVE is not a Finding; a reachable one can be Critical.
- **Stop:** one proof of the vulnerable behavior. Do not run a full exploit kit.

## 11. Host header poisoning → password reset takeover

- **Prerequisites:** the reset link is built from the `Host` header, and the victim can be induced to click.
- **Steps:** request a reset with a foreign `Host`; capture the link at a local listener; show that the token is delivered to the attacker host.
- **Why it matters:** the token is the account.
- **Stop:** use a seeded account and a local listener. Never send a real email.

## 12. Debug endpoint → env secret → signing key forgery

- **Prerequisites:** an exposed debug/actuator endpoint and a secret in the environment.
- **Steps:** read the environment; extract the session or JWT key; forge an admin token; call an admin route.
- **Why it matters:** debug exposure plus a static key is a full compromise.
- **Stop:** one admin read. Redact the secret in the report.

## Chaining rules

- A chain is Confirmed only when every step is reproduced, not inferred.
- Score the chain once at its combined impact; list the component Findings without double-counting.
- If a step is blocked, the chain is Suspected, with the blocked step named.
- Stop at the Proof Cap even if the chain could go further. The report says what was proven and what the next step would be.
- A chain that requires a real third-party service is out of scope; mock the dependency locally or mark it blocked.
