"""Minimal BER/DER reader used to decode the filter of an ldap3 SearchRequest.

The point is to inspect the *actual bytes* ldap3 puts on the wire (or hands
to the Mock strategy) instead of trusting the Python-level filter string.
Only the subset of ASN.1 BER used by RFC 4511 SearchRequest is implemented:
universal SEQUENCE/SET, context-specific tagged choices (the Filter and its
matching assertions), OCTET STRING, INTEGER and ENUMERATED.

Filter choice tags (RFC 4511 section 4.5.1):
    and [0] SET OF Filter          or [1] SET OF Filter       not [2] Filter
    equalityMatch [3] AttributeValueAssertion
    substrings [4] SubstringFilter (initial [0]/any [1]/final [2])
    greaterOrEqual [5]  lessOrEqual [6]  present [7] AttributeDescription
    approxMatch [8]     extensibleMatch [9]
An AttributeValueAssertion is SEQUENCE { attributeDesc OCTET STRING,
assertionValue OCTET STRING }.
"""

from ldap3.operation.search import search_operation

# Filter context tags
AND, OR, NOT = 0, 1, 2
EQUALITY, SUBSTRINGS, GTE, LTE, PRESENT, APPROX, EXTENSIBLE = range(3, 10)
SUB_INITIAL, SUB_ANY, SUB_FINAL = 0, 1, 2

FILTER_NAMES = {
    AND: "and", OR: "or", NOT: "not", EQUALITY: "equalityMatch",
    SUBSTRINGS: "substringFilter", GTE: "greaterOrEqual", LTE: "lessOrEqual",
    PRESENT: "present", APPROX: "approxMatch", EXTENSIBLE: "extensibleMatch",
}
SUBSTRING_NAMES = {SUB_INITIAL: "initial", SUB_ANY: "any", SUB_FINAL: "final"}


class TLV:
    def __init__(self, tag, content, raw):
        self.tag = tag
        self.content = content
        self.raw = raw


def _read_length(data, offset):
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    length = 0
    for _ in range(num_bytes):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def read_tlv(data, offset=0):
    """Read one BER TLV and return (TLV, offset_after)."""
    start = offset
    tag = data[offset]
    offset += 1
    length, offset = _read_length(data, offset)
    content = data[offset:offset + length]
    raw = data[start:offset + length]
    return TLV(tag, content, raw), offset + length


def iter_children(content):
    offset = 0
    while offset < len(content):
        tlv, offset = read_tlv(content, offset)
        yield tlv


def _is_context(tag):
    return bool(tag & 0xC0 == 0x80)


def _context_number(tag):
    return tag & 0x1F


def decode_filter(tlv):
    """Turn a Filter TLV into a plain, comparable Python structure."""
    number = _context_number(tlv.tag)

    if number in (AND, OR):
        children = [decode_filter(child) for child in iter_children(tlv.content)]
        return {"op": FILTER_NAMES[number], "children": children}

    if number == NOT:
        inner = next(iter_children(tlv.content))
        return {"op": "not", "child": decode_filter(inner)}

    if number == PRESENT:
        return {"op": "present", "attribute": tlv.content.decode("utf-8")}

    if number in (EQUALITY, GTE, LTE, APPROX):
        # AttributeValueAssertion is encoded inline as two OCTET STRINGs:
        # attributeDesc then assertionValue (no wrapping SEQUENCE tag).
        parts = list(iter_children(tlv.content))
        attribute = parts[0].content.decode("utf-8")
        value = bytes(parts[1].content)
        return {"op": FILTER_NAMES[number], "attribute": attribute,
                "value": value, "value_hex": value.hex()}

    if number == SUBSTRINGS:
        # SubstringFilter ::= SEQUENCE { type AttributeDescription,
        # substrings SEQUENCE OF Substring }
        seq_parts = list(iter_children(tlv.content))
        attribute = seq_parts[0].content.decode("utf-8")
        pieces = []
        for sub_tlv in iter_children(seq_parts[1].content):
            sub_value = sub_tlv.content
            pieces.append({"kind": SUBSTRING_NAMES[_context_number(sub_tlv.tag)],
                           "value": bytes(sub_value),
                           "value_hex": bytes(sub_value).hex()})
        return {"op": "substringFilter", "attribute": attribute, "substrings": pieces}

    raise ValueError("unsupported filter choice tag %d" % number)


def encode_search_request(search_base, search_filter, scope=2, attributes=None):
    """Build the full SearchRequest BER the same way Connection.search does."""
    from pyasn1.codec.ber import encoder
    request = search_operation(
        search_base, search_filter, scope, 0, attributes or ["uid"],
        0, 0, False, auto_escape=True, auto_encode=False, schema=None)
    return encoder.encode(request)


def decode_request_filter(ber_bytes):
    """Decode a SearchRequest and return (base_dn, filter_tree)."""
    outer, _ = read_tlv(ber_bytes)  # [APPLICATION 3] SearchRequest
    children = list(iter_children(outer.content))
    base_dn = children[0].content.decode("utf-8")
    filter_tlv = children[6]
    return base_dn, decode_filter(filter_tlv)
