"""Offline validation of an LDAP entry against a SchemaInfo object."""

from collections import namedtuple

from .. import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT, SEQUENCE_TYPES
from ..protocol.formatters.standard import find_attribute_validator, standard_formatter
from ..protocol.oid import CLASS_ABSTRACT, CLASS_AUXILIARY, CLASS_STRUCTURAL, \
    ATTRIBUTE_DIRECTORY_OPERATION, ATTRIBUTE_DISTRIBUTED_OPERATION, ATTRIBUTE_DSA_OPERATION
from ..utils.conv import to_raw, to_unicode
from .rfc4512 import ObjectClassInfo, SchemaInfo


SEVERITY_VIOLATION = 'violation'
SEVERITY_UNDETERMINED = 'undetermined'
OBJECT_CLASS_ATTRIBUTE_OID = '2.5.4.0'

EntryValidationIssue = namedtuple('EntryValidationIssue',
                                  ['severity', 'code', 'message', 'attribute', 'object_class', 'value'])
EntryValidationResult = namedtuple('EntryValidationResult', ['valid', 'issues', 'entry', 'object_classes'])
MODIFICATION_OPERATIONS = (MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT, 0, 1, 2, 3)


def schema_from_definitions(attribute_types=None, object_classes=None, dit_content_rules=None,
                            schema_entry='cn=subschema'):
    attributes = {
        'attributeTypes': list(attribute_types or []),
        'objectClasses': list(object_classes or []),
        'dITContentRules': list(dit_content_rules or [])
    }
    return SchemaInfo(schema_entry, dict(attributes),
                      dict((key, list(value)) for key, value in attributes.items()))


def validate_entry(attributes, object_classes=None, changes=None, schema=None, custom_validators=None):
    context = _SchemaContext(schema, custom_validators)
    entry = _copy_entry(attributes)
    entry_object_classes = _initial_object_classes(attributes, object_classes)

    if not isinstance(schema, SchemaInfo) or not schema.is_valid():
        issues = [_issue(SEVERITY_UNDETERMINED, 'schema_unavailable',
                         'no usable schema was provided', 'objectClass')]
        return EntryValidationResult(False, issues, _public_entry(entry), _public_classes(entry_object_classes))

    entry_object_classes_original = list(entry_object_classes)
    simulated, modify_issues = _apply_changes(entry, entry_object_classes, changes, context)
    entry = simulated['attributes']
    entry_object_classes = simulated['object_classes']
    original_analysis, _ = _analyze_classes(entry_object_classes_original, context)
    class_analysis, class_issues = _analyze_classes(entry_object_classes, context)
    if changes and original_analysis.structural_leaf and class_analysis.structural_leaf and \
            original_analysis.structural_leaf.oid != class_analysis.structural_leaf.oid:
        class_issues.append(_issue(SEVERITY_VIOLATION, 'structural_object_class_changed',
                                   'the structural object class of an entry cannot be changed',
                                   'objectClass'))
    issues = list(modify_issues) + class_issues
    issues.extend(_validate_content(entry, class_analysis, context))

    return EntryValidationResult(not issues, issues, _public_entry(entry),
                                 _public_classes(entry_object_classes))


class _SchemaContext(object):
    def __init__(self, schema, custom_validators):
        self.schema = schema
        self.custom_validators = custom_validators
        self.object_classes_by_oid = self._index(schema.object_classes if schema else None)
        self.attributes_by_oid = self._index(schema.attribute_types if schema else None)
        self.rules_by_oid = self._index(schema.dit_content_rules if schema else None)
        self.class_members_cache = {}
        self.attribute_properties_cache = {}

    @staticmethod
    def _index(definitions):
        indexed = {}
        if not definitions:
            return indexed
        for definition in definitions.values():
            if getattr(definition, 'oid', None) and not getattr(definition, 'obsolete', False):
                indexed[definition.oid] = definition
        return indexed

    def lookup_object_class(self, ref):
        return self.object_classes_by_oid.get(self.object_class_oid(ref)) if ref else None

    def lookup_attribute(self, ref):
        return self.attributes_by_oid.get(self.attribute_oid(ref)) if ref else None

    def lookup_rule(self, ref):
        return self.rules_by_oid.get(self.object_class_oid(ref)) if ref else None

    def object_class_oid(self, ref):
        if isinstance(ref, ObjectClassInfo):
            return ref.oid
        try:
            return self.schema.object_classes[ref].oid
        except (KeyError, TypeError):
            return _to_text(ref)

    def attribute_oid(self, ref):
        from .rfc4512 import AttributeTypeInfo
        if isinstance(ref, AttributeTypeInfo):
            return ref.oid
        if _strip_options(_to_text(ref)).lower() == 'objectclass':
            return OBJECT_CLASS_ATTRIBUTE_OID
        base_name, options = _split_options(ref)
        try:
            return self.schema.attribute_types[base_name].oid
        except (KeyError, TypeError):
            return base_name.lower()

    def attribute_identity(self, name):
        base_name, options = _split_options(name)
        if base_name.lower() == 'objectclass':
            return OBJECT_CLASS_ATTRIBUTE_OID
        definition = self.lookup_attribute(base_name)
        type_identity = definition.oid if definition else base_name.lower()
        return type_identity + options.lower()

    def attribute_type_identity(self, name):
        base_name, _ = _split_options(name)
        if base_name.lower() == 'objectclass':
            return OBJECT_CLASS_ATTRIBUTE_OID
        definition = self.lookup_attribute(base_name)
        return definition.oid if definition else base_name.lower()

    @staticmethod
    def class_kind(definition):
        return definition.kind or CLASS_STRUCTURAL

    @staticmethod
    def is_operational_usage(usage):
        return usage in (ATTRIBUTE_DIRECTORY_OPERATION, ATTRIBUTE_DISTRIBUTED_OPERATION, ATTRIBUTE_DSA_OPERATION)

    def class_membership(self, definition):
        oid = definition.oid
        if oid in self.class_members_cache:
            return self.class_members_cache[oid]

        members = {oid: definition}
        missing = set()
        cycles = set()
        state = {}

        def visit(current):
            if current is None:
                return
            if state.get(current.oid) == 1:
                cycles.add(current.oid)
                return
            if state.get(current.oid) == 2:
                return
            state[current.oid] = 1
            members[current.oid] = current
            for ref in current.superior or []:
                superclass = self.lookup_object_class(ref)
                if superclass:
                    visit(superclass)
                else:
                    missing_oid = self.object_class_oid(ref)
                    members[missing_oid] = None
                    missing.add(missing_oid)
            state[current.oid] = 2

        visit(definition)

        result = {'members': members, 'missing': missing, 'cycles': cycles}
        self.class_members_cache[oid] = result
        return result

    def effective_attribute_properties(self, definition):
        oid = definition.oid
        if oid in self.attribute_properties_cache:
            return self.attribute_properties_cache[oid]

        single_value = definition.single_value
        usage = definition.usage
        syntax = definition.syntax
        current = definition
        seen = set()
        while current and current.oid not in seen:
            seen.add(current.oid)
            single_value = single_value or current.single_value
            if usage is None:
                usage = current.usage
            if not syntax and current.syntax:
                syntax = current.syntax
            current = self.lookup_attribute(current.superior[0]) if current.superior else None

        properties = {
            'single_value': single_value,
            'usage': usage,
            'syntax': syntax,
            'operational': self.is_operational_usage(usage)
        }
        self.attribute_properties_cache[oid] = properties
        return properties

    def syntax_issue(self, name, value, definition=None):
        syntax = getattr(definition, 'syntax', None) if definition else None
        custom = self.custom_validators
        custom_covers_syntax = callable(custom) or (
            isinstance(custom, dict) and (
                name in custom or
                (definition and definition.oid in custom) or
                (syntax and syntax in custom)
            )
        )
        if syntax and syntax not in standard_formatter and not custom_covers_syntax:
            return _issue(SEVERITY_UNDETERMINED, 'unsupported_syntax',
                          'no local syntax validator is available for the attribute syntax', name, value=value)
        validator = find_attribute_validator(self.schema, name, self.custom_validators)
        try:
            valid = validator(value)
        except Exception:
            valid = False
        if valid is False:
            return _issue(SEVERITY_VIOLATION, 'invalid_syntax',
                          'value is not valid for the attribute syntax', name, value=value)
        return None


class _ClassAnalysis(object):
    def __init__(self):
        self.explicit = {}
        self.effective = {}
        self.missing_superclasses = set()
        self.cycles = set()
        self.structural = {}
        self.auxiliary = {}
        self.abstract = {}
        self.structural_leaf = None
        self.rules = []
        self.must = set()
        self.may = set()
        self.not_allowed = set()
        self.valid_chain = True


def _copy_entry(attributes):
    entry = {}
    if not attributes:
        return entry
    for name, values in attributes.items():
        entry[_to_text(name)] = _value_list(values)
    return entry


def _initial_object_classes(attributes, object_classes):
    if object_classes is not None:
        return _value_list(object_classes)
    for name, values in _copy_entry(attributes).items():
        if _strip_options(name).lower() == 'objectclass':
            return values
    return []


def _apply_changes(entry, object_classes, changes, context):
    object_classes = list(object_classes)
    issues = []
    buckets = {}
    for name, values in entry.items():
        identity = context.attribute_identity(name)
        if identity not in buckets:
            buckets[identity] = {'values': [], 'names': []}
        buckets[identity]['values'].extend(values)
        buckets[identity]['names'].append(name)
    buckets.pop(OBJECT_CLASS_ATTRIBUTE_OID, None)

    if not changes:
        final_entry = _rebuild_entry(buckets, context)
        if object_classes:
            final_entry['objectClass'] = object_classes
        return {'attributes': final_entry, 'object_classes': object_classes}, issues

    for name, change_list in changes.items():
        name = _to_text(name)
        is_object_class = _strip_options(name).lower() == 'objectclass'
        changes_for_name = change_list if _looks_like_change_sequence(change_list) else [change_list]
        for operation, values in changes_for_name:
            values = [] if values is None else _value_list(values)
            if is_object_class:
                current = object_classes
            else:
                identity = context.attribute_identity(name)
                bucket = buckets.setdefault(identity, {'values': [], 'names': [name]})
                if name not in bucket['names']:
                    bucket['names'].append(name)
                current = bucket['values']
            updated, change_issues = _apply_one_change(name, current, operation, values)
            issues.extend(change_issues)
            if is_object_class:
                object_classes = updated
            else:
                bucket['values'] = updated

    final_entry = _rebuild_entry(buckets, context)
    if object_classes:
        final_entry['objectClass'] = object_classes
    return {'attributes': final_entry, 'object_classes': object_classes}, issues


def _rebuild_entry(buckets, context):
    entry = {}
    for identity, bucket in buckets.items():
        if not bucket['values']:
            continue
        base_name, options = _split_options(bucket['names'][0])
        definition = context.lookup_attribute(base_name)
        name = (_attribute_display_name(definition) or base_name) + options
        entry[name] = list(bucket['values'])
    return entry


def _looks_like_change_sequence(change_list):
    if not isinstance(change_list, SEQUENCE_TYPES) or not change_list:
        return False
    if isinstance(change_list, tuple) and len(change_list) == 2 and change_list[0] in MODIFICATION_OPERATIONS:
        return False
    if not isinstance(change_list[0], SEQUENCE_TYPES) or len(change_list[0]) != 2:
        return False
    return change_list[0][0] in MODIFICATION_OPERATIONS


def _apply_one_change(name, current, operation, values):
    current = list(current)
    if operation in (MODIFY_ADD, 0):
        if not values:
            return current, [_issue(SEVERITY_VIOLATION, 'invalid_modification',
                                   'MODIFY_ADD requires at least one value', name)]
        return current + values, _duplicate_value_issues(name, current, values, True)

    if operation in (MODIFY_DELETE, 1):
        if not current:
            return current, [_issue(SEVERITY_VIOLATION, 'no_such_attribute',
                                   'cannot delete values from an absent attribute', name)]
        if not values:
            return [], []
        updated = list(current)
        missing = []
        for value in values:
            position = _find_value(updated, value)
            if position is None:
                missing.append(value)
            else:
                updated.pop(position)
        issues = [_issue(SEVERITY_VIOLATION, 'no_such_value',
                         'value to delete is not present in the current state', name,
                         value=value) for value in missing]
        return updated, issues

    if operation in (MODIFY_REPLACE, 2):
        return list(values), _duplicate_value_issues(name, [], values, False)

    if operation in (MODIFY_INCREMENT, 3):
        return _apply_increment(name, current, values)

    return current, [_issue(SEVERITY_VIOLATION, 'unsupported_modification',
                           'unknown modification operation: %s' % operation, name)]


def _apply_increment(name, current, values):
    if len(values) != 1:
        return current, [_issue(SEVERITY_VIOLATION, 'invalid_increment',
                               'MODIFY_INCREMENT requires exactly one value', name)]
    if not current:
        return current, [_issue(SEVERITY_VIOLATION, 'no_such_attribute',
                               'cannot increment an absent attribute', name)]
    try:
        increment = int(_to_text(values[0]))
    except (TypeError, ValueError):
        return current, [_issue(SEVERITY_VIOLATION, 'invalid_increment',
                               'MODIFY_INCREMENT value must be an integer', name, value=values[0])]

    updated = []
    for value in current:
        try:
            updated.append(str(int(_to_text(value)) + increment))
        except (TypeError, ValueError):
            return current, [_issue(SEVERITY_VIOLATION, 'invalid_increment',
                                   'current attribute value is not an integer', name, value=value)]
    return updated, []


def _duplicate_value_issues(name, current, added, include_existing):
    values = list(current) + list(added) if include_existing else list(added)
    seen = []
    issues = []
    for value in values:
        if _find_value(seen, value) is not None:
            issues.append(_issue(SEVERITY_VIOLATION, 'duplicate_value',
                                 'the same attribute value appears more than once', name, value=value))
        else:
            seen.append(value)
    return issues


def _find_value(values, expected):
    expected_raw = _comparable_value(expected)
    for index, value in enumerate(values):
        if _comparable_value(value) == expected_raw:
            return index
    return None


def _comparable_value(value):
    if isinstance(value, bool):
        return ('bool', value)
    try:
        return ('raw', to_raw(value))
    except Exception:
        return ('repr', repr(value))


def _analyze_classes(object_class_values, context):
    analysis = _ClassAnalysis()
    issues = []

    for value in object_class_values:
        definition = context.lookup_object_class(value)
        if not definition:
            issues.append(_issue(SEVERITY_UNDETERMINED, 'undefined_object_class',
                                 'object class is not present in the provided schema', 'objectClass', value=value))
            continue
        if definition.oid in analysis.explicit:
            issues.append(_issue(SEVERITY_VIOLATION, 'duplicate_object_class',
                                 'objectClass contains alias or OID values for the same object class',
                                 'objectClass', value=value))
            continue
        analysis.explicit[definition.oid] = definition
        membership = context.class_membership(definition)
        analysis.missing_superclasses.update(membership['missing'])
        analysis.cycles.update(membership['cycles'])
        analysis.effective.update(membership['members'])

    for missing in sorted(analysis.missing_superclasses):
        issues.append(_issue(SEVERITY_UNDETERMINED, 'missing_object_class_schema',
                             'superior object class is not present in schema', 'objectClass', value=missing))
    for cycle in sorted(analysis.cycles):
        issues.append(_issue(SEVERITY_UNDETERMINED, 'object_class_cycle',
                             'object class SUP inheritance contains a cycle', 'objectClass', value=cycle))

    for oid, definition in analysis.effective.items():
        if definition is None or oid in analysis.missing_superclasses:
            continue
        kind = context.class_kind(definition)
        if kind == CLASS_STRUCTURAL:
            analysis.structural[oid] = definition
        elif kind == CLASS_AUXILIARY:
            analysis.auxiliary[oid] = definition
        else:
            analysis.abstract[oid] = definition

    issues.extend(_validate_class_kind_relations(analysis, context))
    issues.extend(_choose_structural_leaf(analysis, context))
    issues.extend(_collect_content_terms(analysis, context))
    return analysis, issues


def _validate_class_kind_relations(analysis, context):
    issues = []
    concrete = {}
    for definition in analysis.explicit.values():
        kind = context.class_kind(definition)
        if kind in (CLASS_STRUCTURAL, CLASS_AUXILIARY):
            concrete[definition.oid] = definition

    for oid, definition in analysis.explicit.items():
        if context.class_kind(definition) == CLASS_ABSTRACT:
            inherited = False
            for concrete_definition in concrete.values():
                membership = context.class_membership(concrete_definition)['members']
                if oid in membership and membership.get(oid) is not None:
                    inherited = True
                    break
            if not inherited:
                issues.append(_issue(SEVERITY_VIOLATION, 'abstract_object_class_direct',
                                     'an entry cannot directly belong to an abstract object class',
                                     'objectClass', object_class=oid))

    seen_edges = set()
    for definition in list(analysis.effective.values()):
        if definition is None:
            continue
        child_kind = context.class_kind(definition)
        for ref in definition.superior or []:
            parent = context.lookup_object_class(ref)
            if not parent:
                continue
            edge = (definition.oid, parent.oid)
            if edge in seen_edges:
                continue
            seen_edges.add(edge)
            parent_kind = context.class_kind(parent)
            if child_kind == CLASS_ABSTRACT and parent_kind != CLASS_ABSTRACT:
                issues.append(_issue(SEVERITY_VIOLATION, 'invalid_object_class_kind',
                                     'abstract object classes cannot derive from structural or auxiliary classes',
                                     'objectClass', object_class=definition.oid))
            elif child_kind == CLASS_STRUCTURAL and parent_kind == CLASS_AUXILIARY:
                issues.append(_issue(SEVERITY_VIOLATION, 'invalid_object_class_kind',
                                     'structural object classes cannot derive from auxiliary classes',
                                     'objectClass', object_class=definition.oid))
            elif child_kind == CLASS_AUXILIARY and parent_kind == CLASS_STRUCTURAL:
                issues.append(_issue(SEVERITY_VIOLATION, 'invalid_object_class_kind',
                                     'auxiliary object classes cannot derive from structural classes',
                                     'objectClass', object_class=definition.oid))
    return _dedupe_issues(issues)


def _choose_structural_leaf(analysis, context):
    issues = []
    if not analysis.structural:
        if analysis.explicit:
            issues.append(_issue(SEVERITY_VIOLATION, 'missing_structural_object_class',
                                 'an entry must belong to a structural object class', 'objectClass'))
        analysis.valid_chain = False
        return issues

    explicit_structural = dict((oid, definition) for oid, definition in analysis.structural.items()
                               if oid in analysis.explicit)
    leaves = []
    for oid, definition in explicit_structural.items():
        subordinate_to_another = False
        for other_oid, other in explicit_structural.items():
            if oid == other_oid:
                continue
            members = context.class_membership(other)['members']
            if members.get(oid) is not None:
                subordinate_to_another = True
                break
        if not subordinate_to_another:
            leaves.append(definition)

    unresolved = bool(analysis.missing_superclasses or analysis.cycles)
    if len(leaves) == 1:
        analysis.structural_leaf = leaves[0]
    elif len(leaves) > 1 and unresolved:
        analysis.valid_chain = False
        issues.append(_issue(SEVERITY_UNDETERMINED, 'structural_chain_undetermined',
                             'cannot determine whether structural object classes belong to one inheritance chain',
                             'objectClass'))
    elif len(leaves) > 1:
        analysis.valid_chain = False
        issues.append(_issue(SEVERITY_VIOLATION, 'multiple_structural_object_classes',
                             'structural object classes are not on the same inheritance chain',
                             'objectClass'))
    else:
        analysis.valid_chain = False
    return issues


def _collect_content_terms(analysis, context):
    issues = []
    for definition in analysis.effective.values():
        if definition is None:
            continue
        for ref in definition.must_contain or []:
            identity = _attribute_identity(ref, context, analysis)
            if identity is None:
                issues.append(_issue(SEVERITY_UNDETERMINED, 'missing_attribute_schema',
                                     'required attribute is not present in schema', value=_to_text(ref)))
            else:
                analysis.must.add(identity)
        for ref in definition.may_contain or []:
            identity = _attribute_identity(ref, context, analysis)
            if identity is None:
                issues.append(_issue(SEVERITY_UNDETERMINED, 'missing_attribute_schema',
                                     'allowed attribute is not present in schema', value=_to_text(ref)))
            else:
                analysis.may.add(identity)

    leaf = analysis.structural_leaf
    if leaf:
        rule = context.lookup_rule(leaf.oid)
        if rule:
            analysis.rules = [rule]
            issues.extend(_collect_rule_terms(analysis, rule, context))
        elif not (analysis.missing_superclasses or analysis.cycles) and analysis.auxiliary:
            for oid in sorted(analysis.auxiliary):
                if oid in analysis.explicit:
                    issues.append(_issue(SEVERITY_VIOLATION, 'auxiliary_class_not_allowed',
                                         'no DIT content rule permits this auxiliary object class',
                                         'objectClass', object_class=oid))
    return _dedupe_issues(issues)


def _collect_rule_terms(analysis, rule, context):
    issues = []
    allowed_auxiliary_oids = set()
    for ref in rule.auxiliary_classes or []:
        auxiliary = context.lookup_object_class(ref)
        if not auxiliary:
            issues.append(_issue(SEVERITY_UNDETERMINED, 'missing_object_class_schema',
                                 'auxiliary object class named by DIT content rule is not present in schema',
                                 'objectClass', value=_to_text(ref)))
            continue
        if context.class_kind(auxiliary) != CLASS_AUXILIARY:
            issues.append(_issue(SEVERITY_VIOLATION, 'invalid_dit_content_rule',
                                 'AUX must reference an auxiliary object class', 'objectClass',
                                 object_class=auxiliary.oid))
        allowed_auxiliary_oids.add(auxiliary.oid)
        if auxiliary.oid not in analysis.explicit:
            continue
        analysis.auxiliary.setdefault(auxiliary.oid, auxiliary)
        membership = context.class_membership(auxiliary)['members']
        for inherited in membership.values():
            if inherited is None:
                continue
            for ref_attr in inherited.must_contain or []:
                _add_rule_attribute(analysis, ref_attr, context, 'must', issues)
            for ref_attr in inherited.may_contain or []:
                _add_rule_attribute(analysis, ref_attr, context, 'may', issues)

    for oid in analysis.auxiliary:
        if oid in analysis.explicit and oid not in allowed_auxiliary_oids:
            issues.append(_issue(SEVERITY_VIOLATION, 'auxiliary_class_not_allowed',
                                 'auxiliary object class is not listed in the governing DIT content rule',
                                 'objectClass', object_class=oid))

    for ref in rule.must_contain or []:
        _add_rule_attribute(analysis, ref, context, 'must', issues)
    for ref in rule.may_contain or []:
        _add_rule_attribute(analysis, ref, context, 'may', issues)
    for ref in rule.not_contains or []:
        _add_rule_attribute(analysis, ref, context, 'not', issues)
    return _dedupe_issues(issues)


def _add_rule_attribute(analysis, ref, context, target, issues):
    identity = _attribute_identity(ref, context, analysis)
    if identity is None:
        issues.append(_issue(SEVERITY_UNDETERMINED, 'missing_attribute_schema',
                             'DIT content rule attribute is not present in schema', value=_to_text(ref)))
    elif target == 'must':
        analysis.must.add(identity)
    elif target == 'may':
        analysis.may.add(identity)
    else:
        analysis.not_allowed.add(identity)


def _attribute_identity(ref, context, analysis):
    definition = context.lookup_attribute(ref)
    if not definition:
        return None
    return definition.oid


def _validate_content(entry, analysis, context):
    issues = []
    grouped_attributes = _group_entry_attributes(entry, context)
    present_identities = set(group['type_identity'] for group in grouped_attributes.values())

    for group in grouped_attributes.values():
        name = group['name']
        identity = group['type_identity']
        values = group['values']
        is_object_class = identity == OBJECT_CLASS_ATTRIBUTE_OID
        base_name, _ = _split_options(name)
        definition = context.lookup_attribute(name)
        if not definition and not is_object_class:
            issues.append(_issue(SEVERITY_UNDETERMINED, 'undefined_attribute',
                                 'attribute is not present in schema', name))
            continue

        properties = {'single_value': False, 'operational': False}
        if definition:
            properties = context.effective_attribute_properties(definition)
            issues.extend(_duplicate_value_issues(name, [], values, False))
            if properties['single_value'] and len(values) > 1:
                issues.append(_issue(SEVERITY_VIOLATION, 'single_value_violation',
                                     'attribute is defined as SINGLE-VALUE but has multiple values', name))

        if identity in analysis.not_allowed:
            issues.append(_issue(SEVERITY_VIOLATION, 'attribute_precluded',
                                 'attribute is precluded by the governing DIT content rule', name))
        elif not properties['operational'] and not is_object_class:
            permitted = identity in analysis.must or identity in analysis.may
            if analysis.valid_chain and not permitted:
                issues.append(_issue(SEVERITY_VIOLATION, 'attribute_not_allowed',
                                     'attribute is not required or allowed by the object classes or DIT content rule',
                                     name))

        if not is_object_class:
            for value in values:
                syntax_issue = context.syntax_issue(base_name, value, definition)
                if syntax_issue:
                    issues.append(syntax_issue)

    for identity in sorted(analysis.must):
        if identity in present_identities:
            continue
        definition = context.lookup_attribute(identity)
        if definition and context.effective_attribute_properties(definition)['operational']:
            continue
        name = _attribute_display_name(definition)
        issues.append(_issue(SEVERITY_VIOLATION, 'missing_required_attribute',
                             'required attribute is absent from the resulting entry', name))

    return _dedupe_issues(issues)


def _group_entry_attributes(entry, context):
    grouped = {}
    for name, values in entry.items():
        base_name = _strip_options(name)
        definition = context.lookup_attribute(base_name)
        identity = context.attribute_identity(name)
        type_identity = context.attribute_type_identity(name)
        if identity not in grouped:
            display_name = _attribute_display_name(definition) or name
            grouped[identity] = {'name': display_name, 'identity': identity,
                                 'type_identity': type_identity, 'values': []}
        grouped[identity]['values'].extend(values)
    return grouped


def _attribute_display_name(definition):
    if not definition:
        return None
    if definition.name:
        return definition.name[0]
    return definition.oid


def _value_list(values):
    if values is None:
        return []
    if isinstance(values, SEQUENCE_TYPES) and not isinstance(values, (str, bytes, bytearray)):
        return list(values)
    return [values]


def _strip_options(name):
    text = _to_text(name)
    return text.split(';', 1)[0]


def _split_options(name):
    text = _to_text(name)
    if ';' not in text:
        return text, ''
    base, options = text.split(';', 1)
    return base, ';' + options


def _to_text(value):
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return to_unicode(value)
    return str(value)


def _issue(severity, code, message, attribute=None, object_class=None, value=None):
    return EntryValidationIssue(severity, code, message, attribute, object_class, value)


def _dedupe_issues(issues):
    result = []
    seen = set()
    for issue in issues:
        key = tuple(issue)
        if key not in seen:
            seen.add(key)
            result.append(issue)
    return result


def _public_entry(entry):
    return dict((name, list(values)) for name, values in entry.items())


def _public_classes(object_classes):
    return list(object_classes)
