# SYN443 product requirements

Specification 0.9. Each item appears once. The columns show which component registers link evidence for a status above `planned`. A partial implementation counts in its component. Product acceptance requires the checks specified for that item.

| Scope | Total | Both | Android only | Control Plane only | Neither |
| --- | ---: | ---: | ---: | ---: | ---: |
| Requirements | 292 | 124 | 59 | 81 | 28 |
| Acceptance scenarios | 98 | 21 | 13 | 21 | 43 |

## Component acceptance

Each cell counts items at that exact status in the component register. Scenarios spanning Android and the Control Plane also require the end-to-end checks specified for that scenario.

| Scope | Component | Planned | Partial | Implemented | Verified |
| --- | --- | ---: | ---: | ---: | ---: |
| Requirements | Android | 109 | 183 | 0 | 0 |
| Requirements | Control Plane | 87 | 205 | 0 | 0 |
| Acceptance scenarios | Android | 64 | 33 | 0 | 1 |
| Acceptance scenarios | Control Plane | 56 | 37 | 0 | 5 |

## Requirement families

| Scope | Total | Both | Android only | Control Plane only | Neither |
| --- | ---: | ---: | ---: | ---: | ---: |
| ARC | 7 | 5 | 1 | 0 | 1 |
| MOD | 10 | 10 | 0 | 0 | 0 |
| AUTH | 5 | 4 | 0 | 1 | 0 |
| ONB | 4 | 3 | 0 | 1 | 0 |
| SUB | 12 | 1 | 0 | 11 | 0 |
| EXT | 10 | 0 | 0 | 10 | 0 |
| CFG | 6 | 2 | 0 | 4 | 0 |
| PROV | 8 | 6 | 1 | 1 | 0 |
| PROTO | 4 | 0 | 1 | 3 | 0 |
| NB | 7 | 5 | 0 | 2 | 0 |
| OVL | 7 | 2 | 0 | 5 | 0 |
| MODE | 5 | 2 | 3 | 0 | 0 |
| AUTO | 10 | 0 | 9 | 0 | 1 |
| REC | 6 | 6 | 0 | 0 | 0 |
| ALG | 24 | 0 | 18 | 1 | 5 |
| BAD | 10 | 0 | 8 | 0 | 2 |
| RLP | 10 | 4 | 0 | 4 | 2 |
| ROUTE | 6 | 1 | 2 | 2 | 1 |
| CHECK | 7 | 2 | 4 | 0 | 1 |
| CHK | 12 | 12 | 0 | 0 | 0 |
| TEL | 12 | 7 | 2 | 2 | 1 |
| LOG | 7 | 6 | 0 | 0 | 1 |
| UI | 1 | 1 | 0 | 0 | 0 |
| EDIT | 12 | 5 | 1 | 3 | 3 |
| OWN | 6 | 1 | 1 | 4 | 0 |
| MOB | 8 | 4 | 1 | 3 | 0 |
| CHAT | 15 | 15 | 0 | 0 | 0 |
| SRV | 4 | 0 | 0 | 4 | 0 |
| SVC | 10 | 0 | 0 | 10 | 0 |
| ADB | 4 | 4 | 0 | 0 | 0 |
| BOOT | 15 | 5 | 2 | 6 | 2 |
| NFR | 8 | 1 | 2 | 2 | 3 |
| SEC | 12 | 4 | 2 | 2 | 4 |
| ENG | 8 | 6 | 1 | 0 | 1 |

## Trace an item

Download `product-requirements` from the CI run for this Control Plane revision. The CSV lists every requirement and acceptance scenario with both original status values. Look up the item ID in its component register for evidence and remaining scope.

- [Control Plane register](requirements-register.json)
- [Android register at 3030a749badc](https://github.com/nd4y/syn443-android/blob/3030a749badca337d2a541d77480259779de9a8c/docs/requirements-register.json)
- [Technical specification](spec/TECHNICAL_SPEC_RU.md)
- [Live and release acceptance records](implementation-status.md)

To refresh Android coverage, update `docs/android-register-revision.txt` to a reviewed revision. Regenerate this page with `python3 tools/product_requirements.py /path/to/android/docs/requirements-register.json --write`. The documents job compares it with the pinned source on every run.
