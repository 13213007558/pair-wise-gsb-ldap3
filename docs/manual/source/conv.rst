Conversion helpers
##################

In the ldap3.utils.conv you can find some helpful function to apply encoding to/from unicode:

- ``to_unicode(obj, encoding=None)``: converts a byte object to unicode, if no encoding is specified with the ``encoding`` parameter the function
  tries to use the local environment encoding.

- ``to_raw((obj, encoding='utf-8')``: converts a string to bytes, using the specified encoding (default is utf-8)

- ``escape_filter_chars(text, encoding=None):``: escapes a string for using as a value in a filter assertion. Escaping is defined in RFC4515 (``*`` -> ``\\2a``, ``(`` -> ``\\28``, ``)`` -> ``\\29``, ``\\`` -> ``\\5c``, the NUL byte -> ``\\00``). If no
  encoding is defined tries to use the local environment encoding. Call it exactly once on each untrusted value before concatenating the filter string; escaping an already-escaped value a second time doubles the backslashes. This is the correct function for filter assertion values only -- for values embedded in a Distinguished Name use ``escape_rdn`` from ``ldap3.utils.dn`` (RFC4514), which escapes a different character set.

- `escape_bytes(bytes_value)``: applies LDAP escaping to a sequence of byte values so that it can be used in an LDAP Add or Modify operation.


These functions can be used in Python 2 or Python 3 with no changes in the code.