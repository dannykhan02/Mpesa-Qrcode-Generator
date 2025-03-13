import re
import phonenumbers as pn

SAFARICOM_PREFIXES = {
    "0701", "0702", "0703", "0704", "0705", "0706", "0707", "0708", "0709",
    "0710", "0711", "0712", "0713", "0714", "0715", "0716", "0717", "0718", "0719",
    "0720", "0721", "0722", "0723", "0724", "0725", "0726", "0727", "0728", "0729",
    "0740", "0741", "0742", "0743", "0744", "0745", "0746", "0747", "0748", "0749",
    "0757", "0758", "0768", "0769", "0790", "0791", "0792", "0793", "0794", "0795",
    "0796", "0797", "0798", "0799", "0110", "0111", "0112", "0113", "0114", "0115"
}

def normalize_phone(phone: str) -> str:
    if not phone:
        return ""
    phone = re.sub(r"\D", "", phone)
    if phone.startswith("+254"):
        phone = "0" + phone[4:]
    elif phone.startswith("254") and len(phone) == 12:
        phone = "0" + phone[3:]
    return phone

def is_valid_safaricom_phone(phone: str, region="KE") -> bool:
    phone = normalize_phone(phone)
    if not phone or len(phone) < 10:
        return False
    try:
        parsed_number = pn.parse(phone, region)
        if not pn.is_valid_number(parsed_number):
            return False
    except pn.phonenumberutil.NumberParseException:
        return False
    return phone[:4] in SAFARICOM_PREFIXES

# Test cases
test_phones = [
    "0715455503",  # Valid Safaricom number
    "+254715455503",  # Valid Safaricom number with country code
    "254715455503",  # Valid Safaricom number with country code
    "071545550",  # Invalid, too short
    "07154555034",  # Invalid, too long
    "0799455503",  # Invalid, not a Safaricom prefix
]

for phone in test_phones:
    normalized = normalize_phone(phone)
    valid = is_valid_safaricom_phone(phone)
    print(f"Phone: {phone}, Normalized: {normalized}, Valid: {valid}")
