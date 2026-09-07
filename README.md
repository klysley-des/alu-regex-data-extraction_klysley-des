# ALU Regex Data Extraction

## Overview

This project uses Python and regular expressions to extract and validate structured data from raw customer support ticket text.

The program extracts:

* Email addresses
* Credit card numbers
* Phone numbers
* URLs

It also validates ALU email addresses and detects suspicious or malicious input.

## Project Structure

```text
alu-regex-data-extraction_klysley-des/
├── input/
│   └── raw-text.txt
├── src/
│   └── main.py
├── output/
│   └── sample-output.json
└── README.md
```

## ALU Email Validation

The program identifies:

* `@alueducation.com` — ALU Official
* `@alumni.alueducation.com` — ALU Alumni
* `@si.alueducation.com` — ALU SI

Malformed email addresses are rejected.

## Security

The program treats the input as untrusted data. It:

* Detects suspicious patterns such as SQL injection, scripts, and directory traversal.
* Excludes hostile ticket blocks from extraction.
* Masks email addresses and credit card numbers.
* Uses the Luhn algorithm to validate credit card numbers.
* Limits and sanitizes input before processing.

## How to Run

From the project root, run:

```bash
python3 src/main.py
```

The program reads:

```text
input/raw-text.txt
```

and generates:

```text
output/sample-output.json
```

## Sample Result

The current input produces:

```text
Emails: 6
Credit Cards: 3
Phone Numbers: 6
URLs: 3
Security Flags: 2
```

