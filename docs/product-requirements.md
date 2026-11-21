# SYN443 product requirements

Specification 0.9. Each item appears once. The columns show which component registers link evidence for a status above `planned`. A partial implementation counts in its component. Product acceptance requires the checks specified for that item.

| Scope | Total | Both | Android only | Control Plane only | Neither |
| --- | ---: | ---: | ---: | ---: | ---: |
| Requirements | 292 | 106 | 33 | 47 | 106 |
| Acceptance scenarios | 98 | 19 | 0 | 2 | 77 |

## Requirement families

| Scope | Total | Both | Android only | Control Plane only | Neither |
| --- | ---: | ---: | ---: | ---: | ---: |
| ARC | 7 | 5 | 1 | 0 | 1 |
| MOD | 10 | 10 | 0 | 0 | 0 |
| AUTH | 5 | 4 | 0 | 0 | 1 |
| ONB | 4 | 3 | 0 | 0 | 1 |
| SUB | 12 | 1 | 0 | 8 | 3 |
| EXT | 10 | 0 | 0 | 10 | 0 |
| CFG | 6 | 2 | 0 | 3 | 1 |
| PROV | 8 | 6 | 0 | 0 | 2 |
| PROTO | 4 | 0 | 0 | 1 | 3 |
| NB | 7 | 5 | 0 | 2 | 0 |
| OVL | 7 | 1 | 0 | 1 | 5 |
| MODE | 5 | 0 | 3 | 0 | 2 |
| AUTO | 10 | 0 | 2 | 0 | 8 |
| REC | 6 | 6 | 0 | 0 | 0 |
| ALG | 24 | 0 | 13 | 0 | 11 |
| BAD | 10 | 0 | 6 | 0 | 4 |
| RLP | 10 | 2 | 1 | 2 | 5 |
| ROUTE | 6 | 0 | 0 | 0 | 6 |
| CHECK | 7 | 2 | 1 | 0 | 4 |
| CHK | 12 | 12 | 0 | 0 | 0 |
| TEL | 12 | 7 | 1 | 2 | 2 |
| LOG | 7 | 6 | 0 | 0 | 1 |
| UI | 1 | 1 | 0 | 0 | 0 |
| EDIT | 12 | 0 | 0 | 5 | 7 |
| OWN | 6 | 0 | 0 | 0 | 6 |
| MOB | 8 | 3 | 2 | 2 | 1 |
| CHAT | 15 | 15 | 0 | 0 | 0 |
| SRV | 4 | 0 | 0 | 0 | 4 |
| SVC | 10 | 0 | 0 | 7 | 3 |
| ADB | 4 | 4 | 0 | 0 | 0 |
| BOOT | 15 | 2 | 1 | 2 | 10 |
| NFR | 8 | 1 | 0 | 1 | 6 |
| SEC | 12 | 3 | 2 | 1 | 6 |
| ENG | 8 | 5 | 0 | 0 | 3 |

## Trace an item

Download `product-requirements` from the CI run for this Control Plane revision. The CSV lists every requirement and acceptance scenario with both original status values. Look up the item ID in its component register for evidence and remaining scope.

- [Control Plane register](requirements-register.json)
- [Android register at c92dc9f3c43a](https://github.com/nd4y/syn443-android/blob/c92dc9f3c43a8b05d787f8a51840b9b0ff8cfcbe/docs/requirements-register.json)
- [Technical specification](spec/TECHNICAL_SPEC_RU.md)
- [Live and release acceptance records](implementation-status.md)

To refresh Android coverage, update `docs/android-register-revision.txt` to a reviewed revision. Regenerate this page with `python3 tools/product_requirements.py /path/to/android/docs/requirements-register.json --write`. The documents job compares it with the pinned source on every run.
