# 10 — Business Logic and State

## 1. Scope and preconditions

The app has money, inventory, quotas, approvals, or a multi-step workflow. Logic bugs do not look like injections; they look like the app working exactly as designed, just not as intended. Test with seeded data and restore state after each case.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/logic"
A="$OUT/cookies_a.txt"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

User A with a cart, an order, a coupon, and a quota. User B with the same so cross-user state can be compared. Admin for approval workflows. Seed a low-value item and a fixed budget; never test with real money.

## 3. Enumeration

Map the state machine: cart → checkout → payment → fulfillment → refund. For each transition, note the server-side checks, the client-supplied fields, and the idempotency key.

```bash
curl -sS -b "$A" "$TARGET/api/cart" | jq .
curl -sS -b "$A" "$TARGET/api/orders" | jq .
curl -sS -b "$A" "$TARGET/api/coupons" | jq .
```

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | Negative quantity | `-d '{"item":"sku-1","qty":-1}'` | Total decreases or credit issued |
| 2 | Negative price | `-d '{"item":"sku-1","price":-100}'` | Server trusts client price |
| 3 | Coupon reuse | Apply the same coupon twice or in two carts | Discount applied twice |
| 4 | Coupon stacking | Apply two exclusive coupons in one order | Both accepted |
| 5 | Workflow skip | Call `/api/orders/<id>/ship` before payment | State moves forward |
| 6 | Payment replay | Replay a successful payment callback | Order paid twice or credit duplicated |
| 7 | Race / double spend | Send 20 parallel redeem requests for one coupon | More than one success |
| 8 | Quota bypass | Delete the cookie, use a new session, or change an IP header | Quota resets |
| 9 | Refund twice | Refund the same order twice | Double refund |
| 10 | Inventory oversell | Add more than stock across two carts, then checkout both | Both succeed |
| 11 | Approval bypass | Change `status` to `approved` in the update body | Approval granted |
| 12 | Currency / rounding | Switch currency or send fractional cents | Total manipulated |
| 13 | Idempotency key reuse | Reuse one key for two different operations | Second operation accepted or first leaked |
| 14 | TOCTOU | Change an object between validation and use | Validation bypassed |

### Race test

```bash
seq 1 20 | xargs -P 20 -I{} curl -sS -b "$A" -X POST "$TARGET/api/coupons/redeem" \
  -H 'Content-Type: application/json' -d '{"code":"ONCE"}' -o "$OUT/redeem-{}.json"
grep -l 'success' "$OUT"/redeem-*.json | wc -l
```

One success is correct. More than one is a race.

## 5. Bypass variants

- Client-supplied fields: price, discount, role, status, owner, total.
- Sequence: parallel requests, out-of-order transitions, replayed callbacks, delayed retries.
- Identity: new session, new cookie, `X-Forwarded-For`, a second account.
- Numeric edges: zero, negative, fractional, huge values, `NaN`, `Infinity`, string numbers.
- Currency and locale: different decimals, rounding modes, exchange rates.
- Time: expiry boundaries, timezone shifts, clock skew.
- Idempotency: missing key, reused key, key collision across users.

## 6. Evidence to capture

- The state before and after each transition.
- The exact request and the server response.
- The parallel timing for races, with a count of successes.
- The account, cart, coupon, and order IDs.
- The restore step for any mutated state.

## 7. False-positive traps

- A UI-only change with no server effect is not a finding. Verify the order total server-side.
- A repeated coupon may be allowed by design for multi-use codes. Read the rules.
- A race may be invisible without enough concurrency or a database constraint. Repeat with more parallelism and check the final state.
- A negative quantity may be rejected at checkout, not at add-to-cart. Test the final transition.
- A refund may be idempotent by design. Check whether a second refund changes the balance.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| Double spend / infinite money | Critical | CWE-840, WSTG-BUSL-05 |
| Approval bypass | High | CWE-863, WSTG-BUSL-06 |
| Negative price / quantity | High | CWE-840, WSTG-BUSL-01 |
| Coupon stacking / reuse | Medium | CWE-840, WSTG-BUSL-05 |
| Quota bypass | Medium | CWE-799, WSTG-BUSL-07 |
| Race condition with limited impact | Medium | CWE-362, WSTG-BUSL-04 |
| Refund duplication | High | CWE-840, WSTG-BUSL-05 |

## 9. Remediation patterns

- Recompute prices, totals, discounts, and permissions server-side from trusted data.
- Enforce the state machine server-side; reject out-of-order transitions.
- Use database constraints and atomic operations for quotas, inventory, and redemptions.
- Make payment and refund callbacks idempotent with a server-side key.
- Bind idempotency keys to the user and operation; reject reuse across contexts.
- Validate numeric ranges and types; reject negative and non-finite values.

## 10. Retest procedure

Replay each case with the same seeded state. Expect the server to reject or normalize the input. For races, rerun the parallel burst and confirm one success. For refunds, confirm the balance changes once. Restore fixtures and verify no residual credit or inventory change.

## Resources

- OWASP WSTG: WSTG-BUSL.
- OWASP Cheat Sheet: Business Logic Security.
- CWE-362, CWE-799, CWE-840, CWE-863.
- PortSwigger Academy: business logic vulnerabilities.
