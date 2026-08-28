# Adapter Support Matrix

Status: repo-owned support statement only

This repository currently supports exactly one adapter contract for productized
remote control flows:

| Field | Current statement |
| --- | --- |
| Adapter id | `opencode` |
| Supported upstream version | exact `1.18.16` only |
| Supported action subset | `view`, `reply`, `deny`, `Stop` |
| Capability schema | `nomad.product-host.command-capability.v1` |
| `allow_once` | unsupported; always `false` |
| `NoCapability` semantics | keep `snapshot`; emit `capability: null` |
| Pending input behavior | adapter may emit a bounded pending-question summary only |
| Unsupported cases | non-exact version, non-exact shape, provider passthrough, multiple simultaneous targets, unmapped official lifecycle |

## Honest scope

The protocol architecture is extensible, but this repository does not claim
that multiple agent families are already supported. The only supported adapter
statement today is the exact OpenCode contract above.

## Fail-closed rules

- Unsupported version fails closed with `ERR_INCOMPATIBLE_VERSION`.
- Unsupported or non-evidenced shape fails closed with `ERR_INCOMPATIBLE_VERSION`.
- Unsupported action surface fails closed with `ERR_SAFETY_BLOCKED`.

## Capability rules

- `view` is always retained for a valid snapshot.
- `reply` is issued only for a single question target.
- `deny` is issued only for a single permission target.
- `Stop` is issued only for the exact busy session/turn boundary.
- `allow_once` is never issued.

## NoCapability rules

`NoCapability` is not the same as transport unavailability. When no actionable
capability exists, the user-visible behavior remains `snapshot + capability:
null`, not `Unavailable`.
