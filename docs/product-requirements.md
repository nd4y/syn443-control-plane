# SYN443 product requirements

Specification 0.9. Each item appears once. The columns show which component registers link evidence for a status above `planned`. A partial implementation counts in its component. Product acceptance requires the checks specified for that item.

| Scope | Total | Both | Android only | Control Plane only | Neither |
| --- | ---: | ---: | ---: | ---: | ---: |
| Requirements | 292 | 114 | 42 | 61 | 75 |
| Acceptance scenarios | 98 | 19 | 2 | 4 | 73 |

## Requirement families

| Scope | Total | Both | Android only | Control Plane only | Neither |
| --- | ---: | ---: | ---: | ---: | ---: |
| ARC | 7 | 5 | 1 | 0 | 1 |
| MOD | 10 | 10 | 0 | 0 | 0 |
| AUTH | 5 | 4 | 0 | 1 | 0 |
| ONB | 4 | 3 | 0 | 1 | 0 |
| SUB | 12 | 1 | 0 | 10 | 1 |
| EXT | 10 | 0 | 0 | 10 | 0 |
| CFG | 6 | 2 | 0 | 3 | 1 |
| PROV | 8 | 6 | 0 | 0 | 2 |
| PROTO | 4 | 0 | 1 | 2 | 1 |
| NB | 7 | 5 | 0 | 2 | 0 |
| OVL | 7 | 2 | 0 | 3 | 2 |
| MODE | 5 | 0 | 3 | 1 | 1 |
| AUTO | 10 | 0 | 3 | 0 | 7 |
| REC | 6 | 6 | 0 | 0 | 0 |
| ALG | 24 | 0 | 13 | 0 | 11 |
| BAD | 10 | 0 | 8 | 0 | 2 |
| RLP | 10 | 3 | 1 | 1 | 5 |
| ROUTE | 6 | 1 | 1 | 1 | 3 |
| CHECK | 7 | 2 | 2 | 0 | 3 |
| CHK | 12 | 12 | 0 | 0 | 0 |
| TEL | 12 | 7 | 1 | 2 | 2 |
| LOG | 7 | 6 | 0 | 0 | 1 |
| UI | 1 | 1 | 0 | 0 | 0 |
| EDIT | 12 | 5 | 1 | 0 | 6 |
| OWN | 6 | 0 | 1 | 0 | 5 |
| MOB | 8 | 3 | 2 | 2 | 1 |
| CHAT | 15 | 15 | 0 | 0 | 0 |
| SRV | 4 | 0 | 0 | 2 | 2 |
| SVC | 10 | 0 | 0 | 10 | 0 |
| ADB | 4 | 4 | 0 | 0 | 0 |
| BOOT | 15 | 2 | 2 | 6 | 5 |
| NFR | 8 | 1 | 0 | 2 | 5 |
| SEC | 12 | 3 | 2 | 2 | 5 |
| ENG | 8 | 5 | 0 | 0 | 3 |

## Trace an item

Download `product-requirements` from the CI run for this Control Plane revision. The CSV lists every requirement and acceptance scenario with both original status values. Look up the item ID in its component register for evidence and remaining scope.

- [Control Plane register](requirements-register.json)
- [Android register at 69c983b744af](https://github.com/nd4y/syn443-android/blob/69c983b744af0e813fcda0fa670e4c11b1478bae/docs/requirements-register.json)
- [Technical specification](spec/TECHNICAL_SPEC_RU.md)
- [Live and release acceptance records](implementation-status.md)

To refresh Android coverage, update `docs/android-register-revision.txt` to a reviewed revision. Regenerate this page with `python3 tools/product_requirements.py /path/to/android/docs/requirements-register.json --write`. The documents job compares it with the pinned source on every run.
