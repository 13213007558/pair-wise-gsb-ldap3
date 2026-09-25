"""
"""

# Created on 2026.09.25
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.

"""
Offline entry validator.

Validates the structural soundness of an LDAP entry against a locally
available schema (usually read offline from a server subschema entry and
stored in a ldap3.protocol.rfc4512.SchemaInfo object). It can be used
before sending an add or a modify operation to know whether the resulting
entry would violate the schema structural rules.

The validator resolves objectClass SUP inheritance chains (with cycle
detection), STRUCTURAL/AUXILIARY/ABSTRACT relations, MUST/MAY attributes
inherited from superior classes, attribute type aliases and OIDs pointing
to the same definition, and DIT content rules (allowed auxiliary classes
and NOT attributes). Items that cannot be decided because the schema is
incomplete are reported as "unknown" instead of being silently accepted
or rejected.

This is NOT a substitute for the server: ACLs, password policies,
matching rule normalization and DIT structure rules are not checked.
Operational attributes are never assumed missing just because they are
not visible in the provided attribute set.
"""

from collections import namedtuple

from .. import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SEQUENCE_TYPES, STRING_TYPES
from ..protocol.oid import CLASS_STRUCTURAL, CLASS_ABSTRACT, CLASS_AUXILIARY, ATTRIBUTE_USER_APPLICATION
from ..protocol.formatters.standard import find_attribute_validator

# violation codes
MISSING_MUST_ATTRIBUTE = 'missing-must-attribute'
ATTRIBUTE_NOT_ALLOWED = 'attribute-not-allowed'
ATTRIBUTE_PROHIBITED = 'attribute-prohibited-by-dit-content-rule'
AUXILIARY_CLASS_NOT_ALLOWED = 'auxiliary-class-not-allowed'
STRUCTURAL_CLASS_CONFLICT = 'structural-class-conflict'
ABSTRACT_CLASS_NOT_EXTENDED = 'abstract-class-not-extended'
SINGLE_VALUE_VIOLATION = 'single-value-violation'
INVALID_SYNTAX = 'invalid-syntax'
ATTRIBUTE_WITHOUT_VALUES = 'attribute-without-values'
DELETE_OF_MISSING_ATTRIBUTE = 'delete-of-missing-attribute'
DELETE_OF_MISSING_VALUE = 'delete-of-missing-value'
UNKNOWN_OPERATION = 'unknown-modify-operation'

# unknown (cannot decide) codes
UNKNOWN_OBJECT_CLASS = 'object-class-not-in-schema'
UNKNOWN_ATTRIBUTE_TYPE = 'attribute-type-not-in-schema'
UNKNOWN_SUPERIOR_CLASS = 'superior-class-not-in-schema'
CIRCULAR_SUPERIOR = 'circular-superior-chain'
NO_SCHEMA = 'schema-not-available'

Issue = namedtuple('Issue', ['code', 'item', 'message'])

_OPERATION_ALIASES = {
    MODIFY_ADD: MODIFY_ADD,
    MODIFY_DELETE: MODIFY_DELETE,
    MODIFY_REPLACE: MODIFY_REPLACE,
    'add': MODIFY_ADD,
    'delete': MODIFY_DELETE,
    'replace': MODIFY_REPLACE,
}


class EntryValidationResult(object):
    """Holds the outcome of an entry validation.

    violations: list of Issue namedtuples - the entry definitely breaks a schema rule
    unknowns: list of Issue namedtuples - items that cannot be decided with the available schema
    entry: dict with the resulting attribute state (after changes are applied)
    """

    def __init__(self, entry, violations, unknowns):
        self.entry = entry
        self.violations = violations
        self.unknowns = unknowns

    @property
    def is_valid(self):
        return not self.violations

    def __bool__(self):
        return self.is_valid

    __nonzero__ = __bool__  # Python 2 compatibility

    def __repr__(self):
        r = 'EntryValidationResult(valid=%s)' % self.is_valid
        for issue in self.violations:
            r += '\n  violation: %s [%s] %s' % (issue.code, issue.item, issue.message)
        for issue in self.unknowns:
            r += '\n  unknown: %s [%s] %s' % (issue.code, issue.item, issue.message)
        return r


def _as_list(values):
    if values is None:
        return []
    if isinstance(values, STRING_TYPES) or isinstance(values, bytes):
        return [values]
    if isinstance(values, SEQUENCE_TYPES):
        return list(values)
    return [values]


def _normalize_attributes(attributes):
    normalized = dict()
    for name, values in attributes.items():
        normalized[name] = _as_list(values)
    return normalized


def _apply_changes(entry, changes, violations):
    """Applies modify operations to the entry state, in place.

    Each change is a (operation, attribute, values) tuple. A delete with
    no values removes the whole attribute, a delete with values removes
    only those values (and the attribute itself when no value remains).
    """
    for change in changes:
        operation, attribute, values = change[0], change[1], _as_list(change[2] if len(change) > 2 else None)
        operation = _OPERATION_ALIASES.get(operation, operation)
        if operation == MODIFY_ADD:
            current = entry.setdefault(attribute, [])
            for value in values:
                if value not in current:
                    current.append(value)
        elif operation == MODIFY_DELETE:
            if attribute not in entry:
                violations.append(Issue(DELETE_OF_MISSING_ATTRIBUTE, attribute, 'cannot delete attribute not present in the entry'))
                continue
            if not values:  # deletes the whole attribute
                del entry[attribute]
            else:
                current = entry[attribute]
                for value in values:
                    if value in current:
                        current.remove(value)
                    else:
                        violations.append(Issue(DELETE_OF_MISSING_VALUE, attribute, 'cannot delete value %r not present in attribute %s' % (value, attribute)))
                if not current:  # last value removed, the attribute is gone
                    del entry[attribute]
        elif operation == MODIFY_REPLACE:
            if values:
                entry[attribute] = list(values)
            elif attribute in entry:
                del entry[attribute]
        else:
            violations.append(Issue(UNKNOWN_OPERATION, attribute, 'unknown modify operation %r' % (change[0],)))


def _lookup(definitions, reference):
    """Resolves a name or OID to a schema definition, returns None when missing."""
    if definitions is None or reference is None:
        return None
    try:
        return definitions[reference]
    except (KeyError, TypeError):
        return None


def _class_key(object_class_info):
    return object_class_info.oid if object_class_info.oid else (object_class_info.name[0] if object_class_info.name else None)


def _collect_class_closure(schema, class_info, unknowns):
    """Walks the SUP chain of an object class, returns an ordered dict of
    ancestor ObjectClassInfo (including the class itself), the union of
    MUST attributes and the union of MAY attributes. Cycles and missing
    superior classes are reported as unknowns.
    """
    closure = dict()
    must = []
    may = []

    def visit(current, path):
        key = _class_key(current)
        if key in path:
            unknowns.append(Issue(CIRCULAR_SUPERIOR, key, 'circular SUP chain detected at object class %s' % key))
            return
        if key in closure:
            return
        closure[key] = current
        for attribute in current.must_contain:
            if attribute not in must:
                must.append(attribute)
        for attribute in current.may_contain:
            if attribute not in may:
                may.append(attribute)
        path = path | set([key])
        for superior_reference in current.superior or []:
            superior = _lookup(schema.object_classes, superior_reference)
            if superior is None:
                unknowns.append(Issue(UNKNOWN_SUPERIOR_CLASS, superior_reference, 'superior class %r of %s not found in schema' % (superior_reference, key)))
            else:
                visit(superior, path)

    visit(class_info, set())
    return closure, must, may


def validate_entry(schema, attributes, object_classes=None, changes=None, check_syntax=True):
    """Validates an entry against an offline schema.

    schema: a ldap3.protocol.rfc4512.SchemaInfo object (or any object with
        object_classes, attribute_types and dit_content_rules dicts), or None
    attributes: dict of the current entry attributes (objectClass included),
        values can be single values or sequences
    object_classes: optional sequence of objectClass values; defaults to the
        objectClass attribute of the entry
    changes: optional sequence of (operation, attribute, values) modify
        operations (MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE); the
        validation is performed on the state resulting after applying them
    check_syntax: when True values are checked against the attribute syntax

    Returns an EntryValidationResult. Structural problems are reported in
    violations; items that cannot be decided with the available schema are
    reported in unknowns.
    """
    violations = []
    unknowns = []
    entry = _normalize_attributes(attributes)
    if changes:
        _apply_changes(entry, changes, violations)

    if object_classes is None:
        object_classes = entry.get('objectClass') or entry.get('objectclass') or []
    object_classes = _as_list(object_classes)

    if schema is None or not getattr(schema, 'object_classes', None):
        for object_class in object_classes:
            unknowns.append(Issue(NO_SCHEMA, object_class, 'no schema available, cannot validate object class %r' % object_class))
        for attribute in entry:
            unknowns.append(Issue(NO_SCHEMA, attribute, 'no schema available, cannot validate attribute %r' % attribute))
        return EntryValidationResult(entry, violations, unknowns)

    # resolves the listed object classes
    listed_classes = []  # list of (token, ObjectClassInfo)
    for token in object_classes:
        class_info = _lookup(schema.object_classes, token)
        if class_info is None:
            unknowns.append(Issue(UNKNOWN_OBJECT_CLASS, token, 'object class %r not found in schema' % token))
        elif not any(_class_key(info) == _class_key(class_info) for _, info in listed_classes):
            listed_classes.append((token, class_info))

    # inheritance closures, inherited MUST/MAY
    must_tokens = []
    may_tokens = []
    closures = dict()  # class key -> closure dict
    for token, class_info in listed_classes:
        closure, must, may = _collect_class_closure(schema, class_info, unknowns)
        closures[_class_key(class_info)] = closure
        for attribute in must:
            if attribute not in must_tokens:
                must_tokens.append(attribute)
        for attribute in may:
            if attribute not in may_tokens:
                may_tokens.append(attribute)

    structural_classes = [info for _, info in listed_classes if info.kind in (None, CLASS_STRUCTURAL)]
    auxiliary_classes = [info for _, info in listed_classes if info.kind == CLASS_AUXILIARY]
    abstract_classes = [info for _, info in listed_classes if info.kind == CLASS_ABSTRACT]

    # all structural classes must belong to a single inheritance chain
    main_structural = None
    if structural_classes:
        for candidate in structural_classes:
            candidate_closure = closures.get(_class_key(candidate), {})
            if all(_class_key(other) in candidate_closure for other in structural_classes):
                main_structural = candidate
                break
        if main_structural is None:
            names = [info.name[0] if info.name else info.oid for info in structural_classes]
            violations.append(Issue(STRUCTURAL_CLASS_CONFLICT, ', '.join(str(n) for n in names), 'structural classes %s are not in the same inheritance chain' % names))

    # an abstract class is allowed only when extended by a listed structural or auxiliary class
    for abstract_info in abstract_classes:
        abstract_key = _class_key(abstract_info)
        extended = False
        for _, class_info in listed_classes:
            if class_info is abstract_info or class_info.kind == CLASS_ABSTRACT:
                continue
            if abstract_key in closures.get(_class_key(class_info), {}):
                extended = True
                break
        if not extended:
            violations.append(Issue(ABSTRACT_CLASS_NOT_EXTENDED, abstract_key, 'abstract class %s is listed but not extended by any structural or auxiliary class of the entry' % abstract_key))

    # DIT content rule of the structural class (governs auxiliary classes, MUST/MAY and NOT attributes)
    not_tokens = []
    dit_content_rule = None
    if main_structural is not None and getattr(schema, 'dit_content_rules', None):
        rule_references = [main_structural.oid] + list(main_structural.name or [])
        for reference in rule_references:
            dit_content_rule = _lookup(schema.dit_content_rules, reference)
            if dit_content_rule is not None:
                break
    if dit_content_rule is not None:
        for attribute in dit_content_rule.must_contain or []:
            if attribute not in must_tokens:
                must_tokens.append(attribute)
        for attribute in dit_content_rule.may_contain or []:
            if attribute not in may_tokens:
                may_tokens.append(attribute)
        not_tokens = list(dit_content_rule.not_contains or [])
        # when a DIT content rule governs the structural class, only the
        # auxiliary classes listed in its AUX component are allowed
        allowed_auxiliary = []
        for reference in dit_content_rule.auxiliary_classes or []:
            aux_info = _lookup(schema.object_classes, reference)
            if aux_info is None:
                unknowns.append(Issue(UNKNOWN_OBJECT_CLASS, reference, 'auxiliary class %r of DIT content rule not found in schema' % reference))
            else:
                allowed_auxiliary.append(_class_key(aux_info))
        for aux_info in auxiliary_classes:
            if _class_key(aux_info) not in allowed_auxiliary:
                name = aux_info.name[0] if aux_info.name else aux_info.oid
                violations.append(Issue(AUXILIARY_CLASS_NOT_ALLOWED, name, 'auxiliary class %s not allowed by DIT content rule of %s' % (name, _class_key(main_structural))))

    # resolves MUST/MAY/NOT tokens (names or OIDs) to attribute definitions
    def resolve_attributes(tokens):
        resolved = dict()  # attribute oid -> AttributeTypeInfo
        for token in tokens:
            attr_info = _lookup(schema.attribute_types, token)
            if attr_info is None:
                unknowns.append(Issue(UNKNOWN_ATTRIBUTE_TYPE, token, 'attribute type %r referenced by object class not found in schema' % token))
            else:
                resolved[attr_info.oid] = attr_info
        return resolved

    must_attributes = resolve_attributes(must_tokens)
    may_attributes = resolve_attributes(may_tokens)
    not_attributes = resolve_attributes(not_tokens)

    # resolves the attributes present in the resulting entry
    present_attributes = dict()  # attribute oid -> (entry name, AttributeTypeInfo or None)
    object_class_oids = set()  # oids of the objectClass attribute itself, never flagged as not allowed
    for attribute in entry:
        attr_info = _lookup(schema.attribute_types, attribute)
        if attribute.lower() == 'objectclass':
            if attr_info is not None:
                present_attributes[attr_info.oid] = (attribute, attr_info)
                object_class_oids.add(attr_info.oid)
            continue
        if attr_info is None:
            unknowns.append(Issue(UNKNOWN_ATTRIBUTE_TYPE, attribute, 'attribute %r not found in schema' % attribute))
            present_attributes[attribute] = (attribute, None)
        else:
            present_attributes[attr_info.oid] = (attribute, attr_info)

    # MUST attributes of the combined classes must be present; operational
    # attributes are not assumed missing when not visible
    for oid, attr_info in must_attributes.items():
        if oid not in present_attributes:
            if attr_info.usage not in (None, ATTRIBUTE_USER_APPLICATION):
                continue
            name = attr_info.name[0] if attr_info.name else attr_info.oid
            violations.append(Issue(MISSING_MUST_ATTRIBUTE, name, 'mandatory attribute %s is missing' % name))

    for oid, (entry_name, attr_info) in present_attributes.items():
        values = entry[entry_name]
        if attr_info is None:
            continue
        if not values:
            violations.append(Issue(ATTRIBUTE_WITHOUT_VALUES, entry_name, 'attribute %s has no values' % entry_name))
            continue
        if oid in object_class_oids:
            continue
        is_operational = attr_info.usage not in (None, ATTRIBUTE_USER_APPLICATION)
        if not is_operational and oid not in must_attributes and oid not in may_attributes:
            name = attr_info.name[0] if attr_info.name else attr_info.oid
            violations.append(Issue(ATTRIBUTE_NOT_ALLOWED, name, 'attribute %s not allowed by the object classes of the entry' % name))
        if oid in not_attributes:
            name = attr_info.name[0] if attr_info.name else attr_info.oid
            violations.append(Issue(ATTRIBUTE_PROHIBITED, name, 'attribute %s prohibited by DIT content rule' % name))
        if attr_info.single_value and len(values) > 1:
            violations.append(Issue(SINGLE_VALUE_VIOLATION, entry_name, 'attribute %s is single-valued but %d values are present' % (entry_name, len(values))))
        if check_syntax and attr_info.syntax:
            validator = find_attribute_validator(schema, entry_name, None)
            for value in values:
                try:
                    validated = validator(value)
                except Exception:
                    validated = False
                if validated is False:
                    violations.append(Issue(INVALID_SYNTAX, entry_name, 'value %r of attribute %s does not conform to syntax %s' % (value, entry_name, attr_info.syntax)))

    return EntryValidationResult(entry, violations, unknowns)
