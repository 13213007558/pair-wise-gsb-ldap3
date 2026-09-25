import unittest

from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, validate_entry
from ldap3.protocol.entryValidator import SEVERITY_UNDETERMINED, SEVERITY_VIOLATION, schema_from_definitions


ATTRIBUTE_TYPES = [
    "( 1.1.1 NAME ( 'cn' 'commonName' ) EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 1.1.2 NAME 'sn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 1.1.3 NAME 'uid' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
    "( 1.1.4 NAME 'employeeNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
    "( 1.1.5 NAME 'passwordHint' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 1.1.6 NAME 'auxOnly' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 1.1.7 NAME 'extra' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 1.1.8 NAME 'createTimestamp' EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )"
]

OBJECT_CLASSES = [
    "( 1.2.1 NAME 'top' ABSTRACT MUST cn )",
    "( 1.2.2 NAME 'person' SUP top STRUCTURAL MUST sn MAY ( uid $ employeeNumber ) )",
    "( 1.2.3 NAME 'employee' SUP ( top $ person ) STRUCTURAL MUST employeeNumber )",
    "( 1.2.4 NAME 'account' SUP top STRUCTURAL MUST uid )",
    "( 1.2.5 NAME 'employeeProfile' AUXILIARY MUST passwordHint MAY auxOnly )",
    "( 1.2.6 NAME 'cyclicOne' SUP cyclicTwo STRUCTURAL MAY cn )",
    "( 1.2.7 NAME 'cyclicTwo' SUP cyclicOne STRUCTURAL MAY cn )"
]

DIT_CONTENT_RULES = [
    "( 1.2.3 NAME 'employeeRule' AUX employeeProfile MAY extra NOT passwordHint )"
]


def codes(result, severity=None):
    return sorted(set(issue.code for issue in result.issues if severity is None or issue.severity == severity))


class TestEntryValidator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = schema_from_definitions(ATTRIBUTE_TYPES, OBJECT_CLASSES, DIT_CONTENT_RULES)

    def test_valid_entry_uses_inherited_must_and_may(self):
        result = validate_entry(
            {'objectClass': ['top', 'person'], 'cn': ['Jane'], 'sn': ['Doe'], 'uid': ['jane']},
            schema=self.schema
        )

        self.assertTrue(result.valid, result.issues)
        self.assertEqual(result.object_classes, ['top', 'person'])

    def test_alias_and_oid_point_to_same_required_definition(self):
        result = validate_entry(
            {'objectClass': ['1.2.3'], 'commonName': ['Jane'], 'sn': ['Doe'], 'employeeNumber': [42]},
            schema=self.schema
        )

        self.assertTrue(result.valid, result.issues)
        self.assertEqual(result.entry['cn'], ['Jane'])

    def test_modification_by_alias_or_oid_applies_to_same_attribute_bucket(self):
        result = validate_entry(
            {'objectClass': ['person'], 'commonName': ['Jane'], 'sn': ['Doe']},
            changes={'cn': [(MODIFY_ADD, ['Janet']), (MODIFY_DELETE, ['Jane'])]},
            schema=self.schema
        )

        self.assertTrue(result.valid, result.issues)
        self.assertEqual(result.entry['cn'], ['Janet'])

    def test_scalar_modification_value_is_accepted(self):
        result = validate_entry(
            {'objectClass': ['person'], 'cn': ['Jane'], 'sn': ['Doe'], 'employeeNumber': [42]},
            changes={'employeeNumber': (MODIFY_REPLACE, 43)},
            schema=self.schema
        )

        self.assertTrue(result.valid, result.issues)
        self.assertEqual(result.entry['employeeNumber'], [43])

    def test_child_required_attribute_is_not_excused_by_parent_may(self):
        result = validate_entry(
            {'objectClass': ['employee'], 'cn': ['Jane'], 'sn': ['Doe'], 'employeeNumber': [42]},
            changes={'employeeNumber': [(MODIFY_DELETE, [42])]},
            schema=self.schema
        )

        self.assertFalse(result.valid)
        self.assertEqual(codes(result), ['missing_required_attribute'])

    def test_multiple_structural_classes_from_different_chains_violate(self):
        result = validate_entry(
            {'objectClass': ['employee', 'account'], 'cn': ['Jane'], 'sn': ['Doe'],
             'employeeNumber': [42], 'uid': ['jane']},
            schema=self.schema
        )

        self.assertFalse(result.valid)
        self.assertIn('multiple_structural_object_classes', codes(result))

    def test_dit_rule_allows_auxiliary_but_still_checks_its_must_and_not(self):
        result = validate_entry(
            {'objectClass': ['employee', 'employeeProfile'], 'cn': ['Jane'], 'sn': ['Doe'],
             'employeeNumber': [42], 'passwordHint': ['hint']},
            schema=self.schema
        )

        self.assertEqual(codes(result), ['attribute_precluded'])

    def test_dit_rule_does_not_permit_unlisted_auxiliary(self):
        schema = schema_from_definitions(
            ATTRIBUTE_TYPES,
            OBJECT_CLASSES + ["( 1.2.9 NAME 'otherProfile' SUP top AUXILIARY MAY auxOnly )"],
            DIT_CONTENT_RULES
        )
        result = validate_entry(
            {'objectClass': ['employee', 'otherProfile'], 'cn': ['Jane'], 'sn': ['Doe'],
             'employeeNumber': [42], 'auxOnly': ['other']},
            schema=schema
        )

        self.assertEqual(codes(result), ['auxiliary_class_not_allowed'])

    def test_auxiliary_requires_governing_dit_content_rule_without_it(self):
        result = validate_entry(
            {'objectClass': ['person', 'employeeProfile'], 'cn': ['Jane'], 'sn': ['Doe'],
             'passwordHint': ['hint']},
            schema=self.schema
        )

        self.assertIn('auxiliary_class_not_allowed', codes(result))

    def test_dit_rule_allowed_attribute_is_permitted(self):
        result = validate_entry(
            {'objectClass': ['employee', 'employeeProfile'], 'cn': ['Jane'], 'sn': ['Doe'],
             'employeeNumber': [42], 'passwordHint': ['hint'], 'extra': ['value']},
            schema=self.schema
        )

        self.assertEqual(codes(result), ['attribute_precluded'])

    def test_delete_one_value_keeps_required_attribute_but_delete_all_removes_it(self):
        current = {'objectClass': ['person'], 'cn': ['Jane', 'Janet'], 'sn': ['Doe', 'Dough']}

        one_value = validate_entry(current, changes={'cn': [(MODIFY_DELETE, ['Janet'])]}, schema=self.schema)
        self.assertTrue(one_value.valid, one_value.issues)
        self.assertEqual(one_value.entry['cn'], ['Jane'])

        all_values = validate_entry(current, changes={'cn': [(MODIFY_REPLACE, [])]}, schema=self.schema)
        self.assertNotIn('cn', all_values.entry)
        self.assertEqual(codes(all_values), ['missing_required_attribute'])

    def test_single_value_and_syntax_are_checked_on_final_state(self):
        result = validate_entry(
            {'objectClass': ['person'], 'cn': ['Jane'], 'sn': ['Doe'], 'uid': ['jane'],
             'employeeNumber': [42]},
            changes={'employeeNumber': [(MODIFY_REPLACE, ['not-an-integer'])]},
            schema=self.schema
        )

        self.assertIn('invalid_syntax', codes(result))

        multi_value = validate_entry(
            {'objectClass': ['person'], 'cn': ['Jane'], 'sn': ['Doe']},
            changes={'uid': [(MODIFY_REPLACE, ['jane', 'janet'])]},
            schema=self.schema
        )
        self.assertIn('single_value_violation', codes(multi_value))

    def test_cyclic_sup_is_reported_as_undetermined_and_does_not_loop(self):
        result = validate_entry({'objectClass': ['cyclicOne']}, schema=self.schema)

        self.assertFalse(result.valid)
        self.assertIn('object_class_cycle', codes(result, SEVERITY_UNDETERMINED))

    def test_missing_schema_definitions_are_undetermined(self):
        unknown_attribute = validate_entry(
            {'objectClass': ['person'], 'cn': ['Jane'], 'sn': ['Doe'], 'unknown': ['value']},
            schema=self.schema
        )
        self.assertEqual(codes(unknown_attribute, SEVERITY_UNDETERMINED), ['undefined_attribute'])

        unknown_class = validate_entry({'objectClass': ['person', 'missingClass'], 'cn': ['Jane'], 'sn': ['Doe']},
                                       schema=self.schema)
        self.assertIn('undefined_object_class', codes(unknown_class, SEVERITY_UNDETERMINED))

    def test_cross_name_and_oid_superior_and_must_references(self):
        schema = schema_from_definitions(
            ATTRIBUTE_TYPES + ["( 1.1.9 NAME 'mail' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )"],
            OBJECT_CLASSES + ["( 1.2.8 NAME 'oidPerson' SUP 1.2.2 STRUCTURAL MUST 1.1.9 MAY 1.1.3 )"]
        )
        result = validate_entry(
            {'objectClass': ['oidPerson'], '1.1.1': ['Jane'], 'sn': ['Doe'], 'mail': ['jane@example.test']},
            schema=schema
        )

        self.assertTrue(result.valid, result.issues)

    def test_missing_schema_as_a_whole_is_undetermined(self):
        result = validate_entry({'cn': ['Jane']})

        self.assertFalse(result.valid)
        self.assertEqual(codes(result, SEVERITY_UNDETERMINED), ['schema_unavailable'])

    def test_unseen_operational_attribute_is_not_treated_as_missing(self):
        result = validate_entry(
            {'objectClass': ['person'], 'cn': ['Jane'], 'sn': ['Doe']},
            schema=self.schema
        )

        self.assertTrue(result.valid, result.issues)
        self.assertNotIn('createTimestamp', result.entry)


if __name__ == '__main__':
    unittest.main()
