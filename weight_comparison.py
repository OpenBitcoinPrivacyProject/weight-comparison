"""Evaluates OBPP threat model changes.

The OBPP's current threat model is defined in JSON
format. New changes can be proposed in the same
JSON format. The newly modified version MUST conform
to the following requirements:
 * It MUST conform to the current JSON schema
 * Items in the threat model JSON MUST be unique
 * It MUST NOT add attackers, categories,
    subcategories, or criteria (not yet supported)
 * It MUST NOT remove attackers, categories,
    subcategories, or criteria (not yet supported)
 * It MAY change the weights assigned from the
    original JSON specification.

This program reports when the score relationship
between two criteria have changed. A change in
score relationship is defined as one of the following:
 * The ratio between the two criteria scores was
    below 1.0, but is now above 1.0, or vice versa
 * The ratio between the two criteria scores was
    exactly 1.0, but is no longer, or vice versa

As an organization, we can use these changes in
score relationships for criteria to judge whether
the proposed changes conform to our Acceptance
Criteria:
https://github.com/OpenBitcoinPrivacyProject/wallet-ratings/blob/master/report-03/weights.wiki
"""

import sys
import json
import collections

from jsonschema import validate

DEBUG_PRINT_ENABLED = True

FLOAT_PRECISION = 2

SCHEMA_FILENAME = 'data/threat_model_schema.json'

def print_usage_and_die():
    """Print usage string for this program."""
    print ("Usage:"
           "\tapp.py original.json changes.json")
    sys.exit()

def validate_json(json_object):
    """Raises an error if the JSON is not valid.

    TODO: implement additional checks for uniqueness
        of items in arrays, which cannot be expressed
        in the schema.

    Raises:
        ValidationError: Raised by
            `jsonschema.validate`.
    """
    validate(json_object, get_json(SCHEMA_FILENAME))

def are_jsons_equal_size(obj1, obj2):
    """Recursively check if JSONs are equal size."""
    if len(obj1) != len(obj2):
        return False

    #terminal condition
    if (not isinstance(obj1, collections.Sequence) and
            not isinstance(obj2, collections.Sequence)):
        return True

    if not isinstance(obj2, collections.Sequence):
        return False

    for key in obj1:
        if key not in obj2:
            return False
        return are_jsons_equal_size(obj1[key],
                                    obj2[key])

def get_json(filename):
    """Get JSON object from file."""
    with open(filename) as data:
        return json.load(data)

def get_ratio(dic, key1, key2):
    """Get the value ratio for two keys in a dict."""
    return float(dic[key1]) / float(dic[key2])

def requires_update(old_ratio, new_ratio):
    """Has relationship b/t old and new ratios changed?"""
    if old_ratio == new_ratio:
        return False
    if old_ratio == 1.0 and new_ratio != 1.0:
        return True
    if old_ratio > 1.0 and new_ratio <= 1.0:
        return True
    if old_ratio < 1.0 and new_ratio >= 1.0:
        return True
    return False

def get_weight_pct_at_this_level(json_arr, index):
    """Calculate % of weight for item at index.
    Args:
        json_arr: A JSON object, with the top level
            being the array of items we want to
            get weights for.
        index (int): The index of the item within
            the top-level array that we want to find
            the % of weights for.

    For example, if the json_obj is:
    [{'weight':1,...},{'weight':3,...}]
    then total weight is 4, and the weight pct at
    index 0 is 0.25 and the weight pct at index 1 is
    0.75.
    """
    total_weight = 0
    target_weight = None
    assert isinstance(json_arr, collections.Sequence)
    for i, item in enumerate(json_arr):
        total_weight += item['weight']
        if i == index:
            target_weight = item['weight']
    return float(target_weight) / float(total_weight)

def get_final_criteria_weights(json_obj):
    """Returns effective weight for each criteria.

    Returns:
        ['IA1a':0.25, 'IA1b':0.25, 'IIA1a':0.5]
    """
    effective_weights = dict()
    attackers = enumerate(json_obj['attackers'])
    for attacker_index, attacker in attackers:
        attacker_weight = get_weight_pct_at_this_level(
            json_obj['attackers'], attacker_index)

        categories = enumerate(attacker['categories'])
        for category_index, category in categories:
            category_weight = get_weight_pct_at_this_level(
                attacker['categories'], category_index)

            subcategories = enumerate(category['subcategories'])
            for subcat_index, subcat in subcategories:
                subcat_weight = get_weight_pct_at_this_level(
                    category['subcategories'],
                    subcat_index)

                criteria = enumerate(subcat['criteria'])
                for crit_index, criterion in criteria:
                    crit_weight = get_weight_pct_at_this_level(
                        subcat['criteria'], crit_index)

                    identifier = ("%s %s %s %s" %
                                  (attacker['numeral'],
                                   category['numeral'],
                                   subcat['numeral'],
                                   criterion['numeral']))

                    effective_weight = (attacker_weight *
                                        category_weight *
                                        subcat_weight *
                                        crit_weight)
                    effective_weights[identifier] = effective_weight

    return effective_weights

def main():
    """Main function."""
    if len(sys.argv) != 3:
        print_usage_and_die()
    original_json = get_json(sys.argv[1])
    changes_json = get_json(sys.argv[2])

    validate_json(original_json)
    validate_json(changes_json)
    if (not are_jsons_equal_size(original_json,
                                 changes_json)):
        print "JSONs do not match."
        sys.exit()

    original_weights = get_final_criteria_weights(original_json)
    new_weights = get_final_criteria_weights(changes_json)

    assert len(original_weights) == len(new_weights)

    dprint("Original weights: %s" %
           str(original_weights))
    dprint("New proposed weights: %s" %
           str(new_weights))

    change_num = 1
    for identifier1 in original_weights:
        for identifier2 in original_weights:
            if identifier1 == identifier2:
                continue
            if identifier1 < identifier2:
                continue #avoid duplicate pairs
            old_ratio = get_ratio(original_weights,
                                  identifier1,
                                  identifier2)
            #do rounding before comparison in
            #requires_update() to avoid rounding
            #errors
            old_ratio = round(old_ratio,
                              FLOAT_PRECISION)
            new_ratio = get_ratio(new_weights,
                                  identifier1,
                                  identifier2)
            new_ratio = round(new_ratio,
                              FLOAT_PRECISION)
            if requires_update(old_ratio, new_ratio):
                print "Change #%d:" % change_num
                change_num += 1
                print("\tWas: %s = %.2f * %s" %
                      (identifier1, old_ratio,
                       identifier2))
                print("\tNow: %s = %.2f * %s" %
                      (identifier1, new_ratio,
                       identifier2))

def dprint(string):
    """Print a debug string."""
    if DEBUG_PRINT_ENABLED:
        print "DEBUG: %s" % string

if __name__ == "__main__":
    main()
