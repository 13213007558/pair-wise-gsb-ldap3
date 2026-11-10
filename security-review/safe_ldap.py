"""Safe LDAP filter/DN construction on top of ldap3.

The key rule is *escape each piece of untrusted text exactly once, at the
layer where it is interpreted*:

* a value embedded in a search filter is RFC 4515 data and goes through
  :func:`ldap3.utils.conv.escape_filter_chars`;
* a value embedded in a Distinguished Name is RFC 4514 data and goes through
  :func:`ldap3.utils.dn.escape_rdn`.

The two escaping schemes are not interchangeable. ``escape_rdn`` never escapes
``*``, ``(`` or ``)``, so it cannot protect a filter assertion, while
``escape_filter_chars`` only escapes a leading/embedded comma as ordinary
text and does not implement the DN leading-space/``#`` rules.

ldap3's ``Connection(auto_escape=True)`` is a convenience guard, not a
substitute for escaping at the call site: the filter string is parsed into a
tree *before* ``auto_escape`` runs, and ``auto_escape`` only calls
``escape_filter_chars`` when the value already contains a backslash that does
not look like a valid escape. See README.md in this directory for the full
code-path analysis.
"""

from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

__all__ = [
    "equality_filter",
    "substring_filter",
    "present_filter",
    "and_filter",
    "or_filter",
    "not_filter",
    "dn_value",
    "build_dn",
]


def _as_text(value):
    """Normalize str/bytes user input to text without interpreting it."""
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, str):
        return value
    raise TypeError("filter/DN values must be str or bytes, got %r" % type(value))


def equality_filter(attribute, value):
    """Return ``(attribute=<escaped value>)`` for an equality match.

    Every metacharacter in *value* (``* ( ) \\ NUL``) is encoded as an RFC
    4515 hex pair, so user-supplied wildcards can never become filter
    operators. A literal star in the input matches only a literal star.
    """
    text = _as_text(value)
    return "(%s=%s)" % (attribute, escape_filter_chars(text))


def substring_filter(attribute, term, anchored=False):
    """Return a substring filter while keeping caller-owned wildcards.

    The *term* itself is escaped exactly like an equality value: any ``*``
    typed by the end user becomes ``\\2a`` and is matched literally. The
    wildcard fragments that implement the substring semantics are added by
    this function around the escaped term, so the intentional substring
    feature is preserved without trusting raw input.

    * ``anchared=False`` -> ``(attribute=*<term>*)`` (contains)
    * ``anchored=True``  -> ``(attribute=<term>*)`` (prefix)
    """
    text = _as_text(term)
    escaped = escape_filter_chars(text)
    pattern = escaped + "*" if anchored else "*" + escaped + "*"
    return "(%s=%s)" % (attribute, pattern)


def present_filter(attribute):
    """Return an RFC 4515 present filter ``(attribute=*)``.

    There is no untrusted value here; the wildcard is part of the query
    structure the caller explicitly asked for.
    """
    return "(%s=*)" % attribute


def and_filter(*clauses):
    return "(&%s)" % "".join(clauses)


def or_filter(*clauses):
    return "(|%s)" % "".join(clauses)


def not_filter(clause):
    return "(!%s)" % clause


def dn_value(value):
    """Escape a single RDN attribute *value* per RFC 4514.

    Use this for DN components (for example the ``cn`` in
    ``cn=...,ou=users``), never for a search filter. Commas, plus signs,
    quotes, angle brackets, semicolons, backslashes, ``=`` and NUL are
    backslash-escaped, with additional rules for a leading ``#``/space and a
    trailing space.
    """
    return escape_rdn(_as_text(value))


def build_dn(rdn_attribute, rdn_value, *parent_components):
    """Assemble a DN from an escaped RDN value and pre-built parent parts.

    >>> build_dn("cn", "Smith, John", "ou=users", "dc=example,dc=org")
    'cn=Smith\\, John,ou=users,dc=example,dc=org'
    """
    parts = ["%s=%s" % (rdn_attribute, dn_value(rdn_value))]
    parts.extend(parent_components)
    return ",".join(parts)
