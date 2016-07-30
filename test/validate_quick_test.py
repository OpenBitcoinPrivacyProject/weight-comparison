"""Unit tests for validate_json.py.

Todos:
    * Raises exception when JSON doesn't match schema.
    * Raises exception when countermeasure listed under attack not found in
        countermeasures array.
    * Raises exception when criterion listed under countermeasure not found in
        criteria array.
    * Raises exception when a countermeasure description provided under an
        attack does not match the description in the countermeasures array.
    * Raises exception when a criterion description provided under a
        countermeasure does not match the description in the criteria array.
    * The example JSON is validated againt the schema without exception.
"""

import unittest
import json
import os.path
import validate_json #validate_json.py

def get_json(filename):
    """Get JSON object from file.

    If the current working directory is the top (parent) directory rather than
    'test/', this will be auto-corrected.
    """
    if not os.path.exists(filename):
        filename = os.path.join('test', filename)

    with open(filename) as data:
        return json.load(data)

class DefaultValuesTest(unittest.TestCase):
    """Tests problems related to default constants."""
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_schema_location(self):
        """Verify that the default schema location is as expected."""
        self.assertEqual(validate_json.DEFAULT_SCHEMA_FILENAME,
                         'threat model schema.json')

class IDProblemsTest(unittest.TestCase):
    """Tests problems related to the 'id' field."""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_duplicate_countermeasure_ids(self):
        """Raises exception if duplicate IDs in 'countermeasures' array."""
        test_json = get_json('duplicate_countermeasure_ids.json')
        schema = get_json(validate_json.DEFAULT_SCHEMA_FILENAME)
        with self.assertRaises(ValueError):
            validate_json.validate_json(test_json, schema)

    def test_duplicate_criteria_ids(self):
        """Raises exception if duplicate IDs in 'criteria' array."""
        test_json = get_json('duplicate_criteria_ids.json')
        schema = get_json(validate_json.DEFAULT_SCHEMA_FILENAME)
        with self.assertRaises(ValueError):
            validate_json.validate_json(test_json, schema)

class NoProblemsTest(unittest.TestCase):
    """A valid JSON matches the schema."""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_valid_json(self):
        json_obj = get_json(validate_json.DEFAULT_JSON_FILENAME)
        schema = get_json(validate_json.DEFAULT_SCHEMA_FILENAME)
        validate_json.validate_json(json_obj, schema)

SUITE1 = unittest.TestLoader().loadTestsFromTestCase(DefaultValuesTest)
SUITE2 = unittest.TestLoader().loadTestsFromTestCase(IDProblemsTest)
SUITE3 = unittest.TestLoader().loadTestsFromTestCase(NoProblemsTest)
