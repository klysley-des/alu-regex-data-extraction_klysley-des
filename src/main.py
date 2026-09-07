import re
import json
import os
import unicodedata

# The quick brown fox jumps over the lazy dog

MAX_INPUT_LENGTH = 200000


# These patterns detect suspicious input such as script injection, SQL injection, JavaScript URLs, and null injections.
SUSPICIOUS_PATTERNS = [
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*['\"].*?['\"]", re.IGNORECASE),
    re.compile(r"(--|;)\s*(drop|delete|insert|update|select)\s", re.IGNORECASE),
    re.compile(r"\.\./"),
    re.compile(r"%00|\\x00"),
    re.compile(r"%3Cscript%3E", re.IGNORECASE)
]


# Removes extra spaces and limits the amount of input we process.
def sanitize_input(raw_text):
    flags = []

    if len(raw_text) > MAX_INPUT_LENGTH:
        flags.append(
            "Input truncated: exceeded {} chars".format(
                MAX_INPUT_LENGTH
            )
        )
        raw_text = raw_text[:MAX_INPUT_LENGTH]

    raw_text = unicodedata.normalize("NFKC", raw_text)

    cleaned = re.sub(
        r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",
        "",
        raw_text
    )

    return cleaned, flags


# Checks if a section of text contains dangerous content.
def block_is_hostile(block):
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(block):
            return pattern.pattern

    return None


# Identifies valid email addresses with a username, domain, and extension.
EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])"
    r"[A-Za-z0-9._%+-]+"
    r"@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
    r"(?![\w.-])"
)


# These rules identify the type of ALU email address.
ALU_DOMAIN_RULES = [
    (
        "ALU SI",
        re.compile(
            r"@si\.alueducation\.com$",
            re.IGNORECASE
        )
    ),
    (
        "ALU Alumni",
        re.compile(
            r"@alumni\.alueducation\.com$",
            re.IGNORECASE
        )
    ),
    (
        "ALU Official",
        re.compile(
            r"@alueducation\.com$",
            re.IGNORECASE
        )
    )
]


def validate_email(email):
    if not EMAIL_PATTERN.fullmatch(email):
        return False

    if ".." in email:
        return False

    local, _, domain = email.partition("@")

    if not local or not domain:
        return False

    if local.startswith(".") or local.endswith("."):
        return False

    if domain.startswith("-") or domain.endswith("-"):
        return False

    return True


# Identifies whether an email belongs to ALU or is an external email.
def classify_email(email):
    for label, pattern in ALU_DOMAIN_RULES:
        if pattern.search(email):
            return label

    return "External"


# Finds credit card numbers written with spaces, hyphens, or no spaces.
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:"
    r"\d{4}[ -]?\d{6}[ -]?\d{5}"
    r"|"
    r"\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}"
    r")\b"
)


# Checks whether a credit card number passes the Luhn check.
def validate_luhn(card_number):
    digits = re.sub(r"[ -]", "", card_number)

    if not digits.isdigit():
        return False

    checksum = 0
    parity = len(digits) % 2

    for i, digit in enumerate(digits):
        digit = int(digit)

        if i % 2 == parity:
            digit *= 2

            if digit > 9:
                digit -= 9

        checksum += digit

    return checksum % 10 == 0


# Hides most of the card number so sensitive information is not exposed.
def mask_card(card_number):
    digits = re.sub(r"[ -]", "", card_number)

    return "**** **** **** {}".format(digits[-4:])


# Finds phone numbers written in different common formats.
PHONE_PATTERN = re.compile(
    r"(?:"
    r"\+\d{1,3}[ -]?"
    r"(?:\(\d{2,4}\)[ -]?)?"
    r"\d{2,4}"
    r"(?:[ -]\d{2,4}){1,3}"
    r"|"
    r"\(\d{2,4}\)[ -]?"
    r"\d{2,4}(?:[ -]\d{2,4}){1,3}"
    r"|"
    r"\b\d{4}(?:[ -]\d{3}){1,2}\b"
    r")"
)


def is_plausible_phone(candidate):
    digit_count = len(re.sub(r"\D", "", candidate))

    return 7 <= digit_count <= 15


# Finds website addresses that start with HTTP or HTTPS.
URL_PATTERN = re.compile(
    r"\bhttps?://"
    r"[A-Za-z0-9.-]+"
    r"(?:\.[A-Za-z]{2,})"
    r"(?:/[^\s'\"<>]*)?",
    re.IGNORECASE
)


# Hides part of an email address to protect private information.
def mask_email(email):
    local, _, domain = email.partition("@")

    if len(local) <= 2:
        visible = local[0]
        stars = "*" * max(len(local) - 1, 1)
    else:
        visible = local[:2]
        stars = "*" * (len(local) - 2)

    return "{}{}@{}".format(
        visible,
        stars,
        domain
    )


def extract_all(raw_text):
    cleaned_text, global_flags = sanitize_input(raw_text)

    security_log = list(global_flags)

    blocks = re.split(
        r"\n\s*\n",
        cleaned_text
    )

    trusted_blocks = []

    for block_num, block in enumerate(
        blocks,
        start=1
    ):
        hostile_match = block_is_hostile(block)

        if hostile_match:
            security_log.append(
                "Block {} excluded from extraction "
                "(entire block discarded) - matched hostile "
                "pattern ({})".format(
                    block_num,
                    hostile_match
                )
            )
            continue

        trusted_blocks.append(block)

    trusted_text = "\n\n".join(trusted_blocks)

    emails_found = []

    for match in EMAIL_PATTERN.finditer(trusted_text):
        email = match.group(0)

        if validate_email(email):
            emails_found.append({
                "email_masked": mask_email(email),
                "category": classify_email(email),
                "valid": True
            })

    cards_found = []

    for match in CREDIT_CARD_PATTERN.finditer(trusted_text):
        candidate = match.group(0)

        valid = validate_luhn(candidate)

        cards_found.append({
            "card_masked": mask_card(candidate),
            "luhn_valid": valid,
            "status": (
                "ACCEPTED"
                if valid
                else "REJECTED (failed Luhn checksum)"
            )
        })

    phone_source_text = CREDIT_CARD_PATTERN.sub(
        "[REDACTED-CARD]",
        trusted_text
    )

    phones_found = []

    for match in PHONE_PATTERN.finditer(
        phone_source_text
    ):
        candidate = match.group(0).strip()

        if is_plausible_phone(candidate):
            phones_found.append(candidate)

    phones_found = sorted(set(phones_found))

    urls_found = sorted(
        set(
            url.rstrip(".,);]")
            for url in URL_PATTERN.findall(trusted_text)
        )
    )

    return {
        "summary": {
            "emails_found": len(emails_found),
            "credit_cards_found": len(cards_found),
            "credit_cards_accepted": sum(
                1
                for card in cards_found
                if card["luhn_valid"]
            ),
            "phone_numbers_found": len(phones_found),
            "urls_found": len(urls_found),
            "security_flags_raised": len(security_log)
        },
        "emails": emails_found,
        "credit_cards": cards_found,
        "phone_numbers": phones_found,
        "urls": urls_found,
        "security_log": security_log
    }


def main():
    base_dir = os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )

    input_path = os.path.join(
        base_dir,
        "input",
        "raw-text.txt"
    )

    output_path = os.path.join(
        base_dir,
        "output",
        "sample-output.json"
    )

    if not os.path.exists(input_path):
        print("Error: input/raw-text.txt was not found.")
        return

    with open(
        input_path,
        "r",
        encoding="utf-8"
    ) as file:
        raw_text = file.read()

    results = extract_all(raw_text)

    os.makedirs(
        os.path.dirname(output_path),
        exist_ok=True
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            results,
            file,
            indent=2
        )

    print("=" * 60)
    print("ALU Regex Data Extraction - Summary")
    print("=" * 60)

    for key, value in results["summary"].items():
        print(
            "{:35}: {}".format(
                key.replace("_", " ").title(),
                value
            )
        )

    print("\nSecurity log:")

    if results["security_log"]:
        for entry in results["security_log"]:
            print("  - {}".format(entry))
    else:
        print("  (no flags raised)")

    print(
        "\nFull structured results written to: {}".format(
            output_path
        )
    )


if __name__ == "__main__":
    main()
