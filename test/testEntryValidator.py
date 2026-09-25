import unittest

from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.protocol.rfc4512 import SchemaInfo
from ldap3.utils.entry_validator import (
    validate_entry,
    MISSING_MUST_ATTRIBUTE,
    ATTRIBUTE_NOT_ALLOWED,
    ATTRIBUTE_PROHIBITED,
    AUXILIARY_CLASS_NOT_ALLOWED,
    STRUCTURAL_CLASS_CONFLICT,
    ABSTRACT_CLASS_NOT_EXTENDED,
    SINGLE_VALUE_VIOLATION,
    INVALID_SYNTAX,
    DELETE_OF_MISSING_ATTRIBUTE,
    DELETE_OF_MISSING_VALUE,
    UNKNOWN_OBJECT_CLASS,
    UNKNOWN_ATTRIBUTE_TYPE,
    CIRCULAR_SUPERIOR,
    NO_SCHEMA,
)


# small schema with cross name/OID references: 'cn' SUPerior referenced by
# name, 'sn' and 'inetUser' SUPeriors referenced by OID; 'cn' has the
# 'commonName' alias; the DIT content rule of inetUser allows only the
# securityInfo auxiliary class and prohibits givenName
SCHEMA_A_DEFINITIONS = {
    'attributeTypes': [
        "( 2.5.4.0 NAME 'objectClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
        "( 2.5.4.41 NAME 'name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )",
        "( 2.5.4.4 NAME 'sn' SUP 2.5.4.41 )",
        "( 2.5.4.42 NAME 'givenName' SUP name )",
        "( 1.3.6.1.4.1.99999.1.1 NAME 'uidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.99999.1.2 NAME 'comment' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 1.3.6.1.4.1.99999.1.3 NAME 'entryUUID' USAGE directoryOperation )",
    ],
    'objectClasses': [
        "( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
        "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( givenName $ comment ) )",
        "( 1.3.6.1.4.1.99999.2.1 NAME 'inetUser' SUP 2.5.6.6 STRUCTURAL MUST uidNumber MAY comment )",
        "( 1.3.6.1.4.1.99999.2.2 NAME 'mailAccount' SUP top STRUCTURAL MAY comment )",
        "( 1.3.6.1.4.1.99999.2.3 NAME 'securityInfo' SUP top AUXILIARY MAY comment )",
        "( 1.3.6.1.4.1.99999.2.4 NAME 'extraInfo' SUP top AUXILIARY MAY givenName )",
    ],
    'dITContentRules': [
        "( 1.3.6.1.4.1.99999.2.1 AUX ( securityInfo ) NOT givenName )",
    ],
}

# small schema with a circular SUP chain, referenced by name one way and
# by OID the other way
SCHEMA_B_DEFINITIONS = {
    'attributeTypes': [
        "( 2.5.4.0 NAME 'objectClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
    ],
    'objectClasses': [
        "( 1.3.6.1.4.1.99998.2.1 NAME 'loopA' SUP loopB STRUCTURAL )",
        "( 1.3.6.1.4.1.99998.2.2 NAME 'loopB' SUP 1.3.6.1.4.1.99998.2.1 STRUCTURAL )",
    ],
}


def make_schema(definitions):
    return SchemaInfo('cn=schema', dict((key, list(value)) for key, value in definitions.items()), {})


SCHEMA_A = make_schema(SCHEMA_A_DEFINITIONS)
SCHEMA_B = make_schema(SCHEMA_B_DEFINITIONS)


def violation_codes(result):
    return [issue.code for issue in result.violations]


def unknown_codes(result):
    return [issue.code for issue in result.unknowns]


class Test(unittest.TestCase):
    def test_valid_entry_with_auxiliary_class(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['top', 'person', 'inetUser', 'securityInfo'],
            'cn': ['alice'],
            'sn': ['Smith'],
            'uidNumber': ['1000'],
        })
        self.assertTrue(result.is_valid, repr(result))
        self.assertEqual(result.violations, [])
        self.assertEqual(result.unknowns, [])

    def test_missing_must_attribute_of_combined_child_class(self):
        # uidNumber is required by inetUser even if every person MUST is present
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['top', 'person', 'inetUser'],
            'cn': ['alice'],
            'sn': ['Smith'],
        })
        self.assertEqual(violation_codes(result), [MISSING_MUST_ATTRIBUTE])
        self.assertEqual(result.violations[0].item, 'uidNumber')

    def test_structural_classes_not_in_same_chain(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['inetUser', 'mailAccount'],
            'cn': ['alice'],
            'sn': ['Smith'],
            'uidNumber': ['1000'],
        })
        self.assertIn(STRUCTURAL_CLASS_CONFLICT, violation_codes(result))

    def test_alias_and_oid_resolve_to_same_definition(self):
        # commonName is an alias of cn, 2.5.4.4 is the OID of sn
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['person'],
            'commonName': ['alice'],
            '2.5.4.4': ['Smith'],
        })
        self.assertTrue(result.is_valid, repr(result))
        self.assertEqual(result.unknowns, [])

    def test_attribute_not_allowed_by_class_combination(self):
        # uidNumber is allowed by inetUser but not by person alone
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['person'],
            'cn': ['alice'],
            'sn': ['Smith'],
            'uidNumber': ['1000'],
        })
        self.assertEqual(violation_codes(result), [ATTRIBUTE_NOT_ALLOWED])
        self.assertEqual(result.violations[0].item, 'uidNumber')

    def test_dit_content_rule_prohibited_attribute(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['inetUser'],
            'cn': ['alice'],
            'sn': ['Smith'],
            'uidNumber': ['1000'],
            'givenName': ['Alice'],
        })
        self.assertIn(ATTRIBUTE_PROHIBITED, violation_codes(result))

    def test_dit_content_rule_auxiliary_class_not_allowed(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['inetUser', 'extraInfo'],
            'cn': ['alice'],
            'sn': ['Smith'],
            'uidNumber': ['1000'],
        })
        self.assertIn(AUXILIARY_CLASS_NOT_ALLOWED, violation_codes(result))

    def test_single_value_attribute(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['inetUser'],
            'cn': ['alice'],
            'sn': ['Smith'],
            'uidNumber': ['1000', '1001'],
        })
        self.assertIn(SINGLE_VALUE_VIOLATION, violation_codes(result))

    def test_invalid_syntax(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['inetUser'],
            'cn': ['alice'],
            'sn': ['Smith'],
            'uidNumber': ['not-a-number'],
        })
        self.assertIn(INVALID_SYNTAX, violation_codes(result))

    def test_delete_one_value_keeps_attribute(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['person'],
            'cn': ['alice', 'ally'],
            'sn': ['Smith'],
        }, changes=[
            (MODIFY_DELETE, 'cn', ['alice']),
        ])
        self.assertTrue(result.is_valid, repr(result))
        self.assertEqual(result.entry['cn'], ['ally'])

    def test_delete_last_value_removes_attribute(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['person'],
            'cn': ['alice'],
            'sn': ['Smith'],
        }, changes=[
            (MODIFY_DELETE, 'cn', ['alice']),
        ])
        self.assertIn(MISSING_MUST_ATTRIBUTE, violation_codes(result))
        self.assertNotIn('cn', result.entry)

    def test_delete_whole_attribute(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['person'],
            'cn': ['alice'],
            'sn': ['Smith'],
        }, changes=[
            (MODIFY_DELETE, 'sn', []),
        ])
        self.assertIn(MISSING_MUST_ATTRIBUTE, violation_codes(result))
        self.assertNotIn('sn', result.entry)

    def test_add_and_replace_changes(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['inetUser'],
            'cn': ['alice'],
            'sn': ['Smith'],
        }, changes=[
            (MODIFY_ADD, 'uidNumber', ['1000']),
            (MODIFY_REPLACE, 'sn', ['Jones']),
        ])
        self.assertTrue(result.is_valid, repr(result))
        self.assertEqual(result.entry['sn'], ['Jones'])
        self.assertEqual(result.entry['uidNumber'], ['1000'])

    def test_delete_of_missing_attribute_and_value(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['person'],
            'cn': ['alice'],
            'sn': ['Smith'],
        }, changes=[
            (MODIFY_DELETE, 'comment', []),
            (MODIFY_DELETE, 'cn', ['bob']),
        ])
        self.assertIn(DELETE_OF_MISSING_ATTRIBUTE, violation_codes(result))
        self.assertIn(DELETE_OF_MISSING_VALUE, violation_codes(result))

    def test_circular_superior_reported_as_unknown(self):
        result = validate_entry(SCHEMA_B, {
            'objectClass': ['loopA'],
        })
        self.assertIn(CIRCULAR_SUPERIOR, unknown_codes(result))

    def test_unknown_class_and_attribute_reported(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['person', 'alienClass'],
            'cn': ['alice'],
            'sn': ['Smith'],
            'fooBar': ['x'],
        })
        self.assertIn(UNKNOWN_OBJECT_CLASS, unknown_codes(result))
        self.assertIn(UNKNOWN_ATTRIBUTE_TYPE, unknown_codes(result))

    def test_no_schema_returns_unknowns_not_violations(self):
        result = validate_entry(None, {
            'objectClass': ['person'],
            'cn': ['alice'],
        })
        self.assertEqual(result.violations, [])
        self.assertTrue(all(code == NO_SCHEMA for code in unknown_codes(result)))
        self.assertTrue(result.unknowns)

    def test_operational_attribute_not_flagged(self):
        # entryUUID is operational: allowed even if not in MUST/MAY, and
        # never assumed missing when not visible
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['person'],
            'cn': ['alice'],
            'sn': ['Smith'],
            'entryUUID': ['abc-123'],
        })
        self.assertTrue(result.is_valid, repr(result))

    def test_abstract_class_not_extended(self):
        result = validate_entry(SCHEMA_A, {
            'objectClass': ['top'],
        })
        self.assertIn(ABSTRACT_CLASS_NOT_EXTENDED, violation_codes(result))


if __name__ == '__main__':
    unittest.main()

