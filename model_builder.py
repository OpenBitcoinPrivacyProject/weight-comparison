"""Takes a valid threat model JSON and builds missing data.
Missing data includes such things as:
 * effective scores
 * default values for optional fields

 Terminology:
  1. A "bare" threat model object is the one specified in a .json file.
  2. A "built" threat model object is the one output by this module, including
    new or modified fields compared to the bare threat model object. The terms
    "build" and "built" should not be confused with software builds.

Build tasks:
 * Add printable-tags to objects that can be tagged

 Todos:
 * As we add more build tasks, it should be possible to refactor so we walk
    through the JSON once and get most of the tasks done, rather than repeating
    the walking code and do the walk for each build task.
 """

from copy import deepcopy
from pprint import pformat
from common import _empty, iter_items #common.py

ENABLE_DEBUG_PRINT = False

class ThreatModelElementType(object):
    """Enum of threat model element types"""
    ATTACKER = 1
    ATTACK = 2
    COUNTERMEASURE = 3
    CRITERION = 4
    COUNTERMEASURE_DEFINTION = 5
    CRITERION_DEFINITION = 6

def get_built_model(bare_threat_model):
    """Builds a complete threat model object from the bare model object.

    Args:
        bare_threat_model (`dict`): The bare threat model object, e.g. the one
            read in via `json.load`.

    Returns:
        `dict`: The built threat model object.
    """
    built_threat_model = deepcopy(bare_threat_model)
    built_threat_model = add_printable_tags(built_threat_model)

    dprint("get_built_model: The built model is: '%s'" %
           pformat(built_threat_model))
    return built_threat_model

def add_printable_tags(threat_model):
    """Defines a 'printable-tags' array for various objects.

    This is a non-destructive function.

    Printability is determined by computing which tags apply to an object and
    then referencing whether the 'tags' array in the document has set a given
    tag's 'print-in-docs' attribute to false.

    Objects include:
    * each attacker in the threat model
    * each attack in the threat model
    * each countermeasure in the threat model
    * each criterion in the threat model
    * each countermeasure in the document's 'countermeasures' array
    * each criterion in the document's 'countermeasures' array

    Returns: `dict`: The built threat model object
    """
    built_threat_model = deepcopy(threat_model)

    for attacker in iter_items(built_threat_model, 'attackers'):
        attacker['printable-tags'] = get_printable_tags(
            built_threat_model, attacker, ThreatModelElementType.ATTACKER)

        for attack in iter_items(attacker, 'attacks'):
            attack['printable-tags'] = get_printable_tags(
                built_threat_model, attack, ThreatModelElementType.ATTACK)

            for counterm in iter_items(attack, 'countermeasures'):
                counterm['printable-tags'] = get_printable_tags(
                    built_threat_model, counterm,
                    ThreatModelElementType.COUNTERMEASURE)

                if (not _empty(counterm, 'criteria-groups') and
                        not _empty(counterm, 'criteria')):
                    counterm_id = counterm['id'] if 'id' in counterm else 'NOID'
                    raise ValueError(("Countermeasure '%s' lists both a "
                                      "'criteria-groups' array and a 'criteria' "
                                      "array, which is not permitted.") %
                                     counterm_id)

                elif not _empty(counterm, 'criteria-groups'):
                    for criteria_group in iter_items(counterm,
                                                     'criteria-groups'):
                        tag_criteriagroup_recurse(built_threat_model,
                                                  criteria_group)
                        dprint(("add_printable_tags: Modified criteria group "
                                "is: '%s'") % criteria_group)

                elif not _empty(counterm, 'criteria'):
                    tag_criteriagroup_recurse(built_threat_model, counterm)

    for countermeasure in iter_items(built_threat_model, 'countermeasures'):
        countermeasure['printable-tags'] = get_printable_tags(
            built_threat_model, countermeasure,
            ThreatModelElementType.COUNTERMEASURE_DEFINTION)

    for criterion in iter_items(built_threat_model, 'criteria'):
        criterion['printable-tags'] = get_printable_tags(
            built_threat_model, criterion,
            ThreatModelElementType.CRITERION_DEFINITION)

    return built_threat_model

def tag_criteriagroup_recurse(threat_model, criteria_container):
    """Recursively builds tags for criteria groups.

    This is a destructive function; the `criteria_group` object will be
    modified.

    Args:
        threat_model (`dict`): The threat model object.
        criteria_container (`dict`): Either a criteria group or the
            parent countermeasure of the criteria containing a 'criteria' array.
    """
    dprint("Inspecting criteria group or countermeasure: '%s'" %
           pformat(criteria_container))

    if (_empty(criteria_container, 'criteria-groups') and
            _empty(criteria_container, 'criteria')):
        dprint("Criteria group was empty.")
        return criteria_container

    for inner_criteria_group in iter_items(criteria_container, 'criteria-groups'):
        tag_criteriagroup_recurse(threat_model, inner_criteria_group)

    for criterion in iter_items(criteria_container, 'criteria'):
        criterion['printable-tags'] = get_printable_tags(
            threat_model, criterion, ThreatModelElementType.CRITERION)

def get_printable_tags(threat_model, threat_obj, obj_type):
    """Get a set of tag strings for the specified threat model object.

    An array of tags may apply to an attacker, an attack, a counteremeasure, or
    a criterion. It may be applied within the threat model itself, or in the
    arrays of countermeasures or criteria below the threat model in the JSON
    specification.

    Args:
        threat_model (`dict`): The threat model read from the JSON file. This is
            required to determine whether the threat model author declared a
            given tag as unprintable.
        threat_obj (`dict`): The threat model object in question that we're
            accumulating tags for.
        obj_type (`ThreatModelElementType`): Whether this an attacker, attack,
            counteremeasure, or criterion we're accumulating tags for.
    Returns:
        List[str]: A list of unique tags that should be printed.
    """
    tags_to_print = set()
    if 'id' in threat_obj:
        dprint("get_printable_tags: Finding tags for '%s'" % threat_obj['id'])

    #include all tags that are explicitly within the threat model
    if not _empty(threat_obj, 'tags'):
        tags_to_print.update(threat_obj['tags'])
        dprint("get_printable_tags: Found %d immediate tags" %
               len(tags_to_print))

    #if the threat model object in question is a countermeasure or criterion,
    #go through the 'countermeasures' and 'criteria' arrays in the JSON spec
    #and look for tags for this object.
    array_name = None
    if obj_type == ThreatModelElementType.COUNTERMEASURE:
        array_name = 'countermeasures'
    elif obj_type == ThreatModelElementType.CRITERION:
        array_name = 'criteria'

    for item in iter_items(threat_model, array_name):
        if ('id' in item and 'id' in threat_obj and
                item['id'] == threat_obj['id']):
            for tag in iter_items(item, 'tags'):
                tags_to_print.add(tag)
                dprint(("get_printable_tags: Added tag '%s' from array in doc "
                        "definition.") % tag)

    #remove all tags that are not printable
    for tag_obj in iter_items(threat_model, 'tags'):
        if 'print-in-docs' in tag_obj and not tag_obj['print-in-docs']:
            tags_to_print.discard(tag_obj['name'])
            dprint(("get_printable_tags: '%s' is not printable so it was "
                    "removed from the list of tags to print.") %
                   tag_obj['name'])

    dprint("get_printable_tags: There were %d final tags for this object." %
           len(tags_to_print))

    return list(tags_to_print)

def dprint(data):
    """Print debug data."""
    if ENABLE_DEBUG_PRINT:
        print "DEBUG: %s" % data
