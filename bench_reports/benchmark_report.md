# Detection Benchmark Report

- seed: 42
- run_id: d6404ed05358
- corpus: 9550 positive, 2500 negative, 200 injection
- acceptance: PASS

## Aggregate

| tp | fp | fn | precision | recall | f1 |
|---|---|---|---|---|---|
| 1931 | 352 | 52 | 0.8458 | 0.9738 | 0.9053 |

## Per-entity

| entity | tp | fp | fn | precision | recall | f1 | IoU>=0.5 |
|---|---|---|---|---|---|---|---|
| ADDRESS | 248 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| API_KEY | 28 | 0 | 2 | 1.0000 | 0.9333 | 0.9655 | 0.0000 |
| BANK_ACCOUNT | 0 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| COMPANY_NAME | 168 | 40 | 0 | 0.8077 | 1.0000 | 0.8936 | 0.9167 |
| CREDIT_CARD | 67 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| CUSTOMER_ID | 208 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| EMAIL | 219 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| EMPLOYEE_ID | 208 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| JWT | 30 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| LOCATION | 0 | 118 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| ORGANIZATION | 0 | 142 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| PASSWORD | 0 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| PERSON | 289 | 52 | 50 | 0.8475 | 0.8525 | 0.8500 | 0.9654 |
| PHONE | 226 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| PRIVATE_KEY | 0 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| SECRET | 30 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| TOKEN_PATTERN | 0 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| TW_ID | 210 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| aggregate | 1931 | 352 | 52 | 0.8458 | 0.9738 | 0.9053 | 0.9660 |

## Acceptance

| metric | actual | required | passed |
|---|---|---|---|
| ADDRESS_precision | 1.0000 | 0.8000 | True |
| ADDRESS_recall | 1.0000 | 0.8500 | True |
| CUSTOMER_ID_precision | 1.0000 | 0.8000 | True |
| CUSTOMER_ID_recall | 1.0000 | 0.8500 | True |
| EMAIL_precision | 1.0000 | 0.8000 | True |
| EMAIL_recall | 1.0000 | 0.8500 | True |
| EMPLOYEE_ID_precision | 1.0000 | 0.8000 | True |
| EMPLOYEE_ID_recall | 1.0000 | 0.8500 | True |
| PERSON_precision | 0.8475 | 0.8000 | True |
| PERSON_recall | 0.8525 | 0.8500 | True |
| PHONE_precision | 1.0000 | 0.8000 | True |
| PHONE_recall | 1.0000 | 0.8500 | True |
| TW_ID_precision | 1.0000 | 0.8000 | True |
| TW_ID_recall | 1.0000 | 0.8500 | True |
| aggregate_precision | 0.8458 | 0.8000 | True |
| aggregate_recall | 0.9738 | 0.9000 | True |
