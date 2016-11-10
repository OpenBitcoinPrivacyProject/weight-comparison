"""Unit tests for model_builder.py."""

import unittest
#import json
#import os.path
import model_builder #model_buidler.py

'''
def get_json(filename):
    """Get JSON object from file.

    If the current working directory is the top (parent) directory rather than
    'test/', this will be auto-corrected.
    """
    if not os.path.exists(filename):
        filename = os.path.join('test', filename)

    with open(filename) as data:
        return json.load(data)
'''

class PrintableTagsTest(unittest.TestCase):
    """Tests problems related to printable tags."""
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_attacker_tag(self):
        """Verify that a printable attacker tag is seen."""
        bare_model = {
            'attackers': [
                {
                    'name': 'attacker1',
                    'tags': ['a', 'b b', 'c']
                }
            ]
        }
        built_model = model_builder.get_built_model(bare_model)
        printable_tags = built_model['attackers'][0]['printable-tags']
        self.assertEqual(len(printable_tags), 3)
        self.assertIn('a', printable_tags)
        self.assertIn('b b', printable_tags)
        self.assertIn('c', printable_tags)

    def test_attack_tag(self):
        """Verify that a printable attack tag is seen."""
        bare_model = {
            'attackers': [
                {
                    'name': 'attacker1',
                    'attacks': [
                        {
                            'name': 'attack1',
                            'tags': ['a', 'b']
                        }
                    ]
                }
            ]
        }
        built_model = model_builder.get_built_model(bare_model)
        printable_tags = built_model['attackers'][0]['attacks'][0]['printable-tags']
        self.assertEqual(len(printable_tags), 2)
        self.assertIn('a', printable_tags)
        self.assertIn('b', printable_tags)

    def test_counterm_tag(self):
        """Verify that a printable countermeasure tag is seen."""
        bare_model = {
            'attackers': [
                {
                    'name': 'attacker1',
                    'attacks': [
                        {
                            'name': 'attack1',
                            'countermeasures': [
                                {
                                    'name': 'counterm1',
                                    'tags': ['a', 'b']
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        built_model = model_builder.get_built_model(bare_model)
        printable_tags = (built_model['attackers'][0]['attacks'][0]
                          ['countermeasures'][0]['printable-tags'])
        self.assertEqual(len(printable_tags), 2)
        self.assertIn('a', printable_tags)
        self.assertIn('b', printable_tags)

    def test_criterion_tag(self):
        """Verify that a printable criterion tag is seen.

        This particularly tests the recursive definition of criteria-groups.
        """
        bare_model = {
            'attackers': [
                {
                    'name': 'attacker1',
                    'attacks': [
                        {
                            'name': 'attack1',
                            'countermeasures': [
                                {
                                    'id': 'counterm1',
                                    'criteria-groups': [
                                        {
                                            'criteria': [
                                                {
                                                    'id': 'criterion1',
                                                    'tags': ['a', 'b']
                                                },
                                                {
                                                    'id': 'criterion2',
                                                    'tags': ['c', 'd']
                                                }
                                            ]
                                        },
                                        {
                                            'criteria': [
                                                {
                                                    'id': 'criterion3',
                                                    'tags': ['e', 'f']
                                                }
                                            ]
                                        },
                                        {
                                            'criteria-groups': [
                                                {
                                                    'criteria': [
                                                        {
                                                            'id': 'criterion4',
                                                            'tags': ['g', 'h']
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ],
            "countermeasures": [{'id': 'counterm1'}],
            "criteria": [{'id':'criterion1'}, {'id':'criterion2'},
                         {'id':'criterion3'}, {'id':'criterion4'}]
        }
        built_model = model_builder.get_built_model(bare_model)

        printable_tags1 = (built_model['attackers'][0]['attacks'][0]
                           ['countermeasures'][0]['criteria-groups'][0]
                           ['criteria'][0]['printable-tags'])
        printable_tags2 = (built_model['attackers'][0]['attacks'][0]
                           ['countermeasures'][0]['criteria-groups'][0]
                           ['criteria'][1]['printable-tags'])
        printable_tags3 = (built_model['attackers'][0]['attacks'][0]
                           ['countermeasures'][0]['criteria-groups'][1]
                           ['criteria'][0]['printable-tags'])
        printable_tags4 = (built_model['attackers'][0]['attacks'][0]
                           ['countermeasures'][0]['criteria-groups'][2]
                           ['criteria-groups'][0]['criteria'][0]
                           ['printable-tags'])


        self.assertEqual(len(printable_tags1), 2)
        self.assertIn('a', printable_tags1)
        self.assertIn('b', printable_tags1)

        self.assertEqual(len(printable_tags2), 2)
        self.assertIn('c', printable_tags2)
        self.assertIn('d', printable_tags2)

        self.assertEqual(len(printable_tags3), 2)
        self.assertIn('e', printable_tags3)
        self.assertIn('f', printable_tags3)

        self.assertEqual(len(printable_tags4), 2)
        self.assertIn('g', printable_tags4)
        self.assertIn('h', printable_tags4)

    def test_countermeasures_tag(self):
        """Verify that printable tag in 'countermeasures' array is included."""
        bare_model = {
            'attackers': [
                {
                    'name': 'attacker1',
                    'attacks': [
                        {
                            'name': 'attack1',
                            'countermeasures': [
                                {
                                    'id': 'counterm1',
                                    'tags': ['a', 'b']
                                }
                            ]
                        }
                    ]
                }
            ],
            "countermeasures": [{'id':'counterm1', 'tags': ['c', 'd']}]
        }
        built_model = model_builder.get_built_model(bare_model)
        printable_tags = (built_model['attackers'][0]['attacks'][0]
                          ['countermeasures'][0]['printable-tags'])
        self.assertEqual(len(printable_tags), 4)
        self.assertIn('a', printable_tags)
        self.assertIn('b', printable_tags)
        self.assertIn('c', printable_tags)
        self.assertIn('d', printable_tags)

        printable_tags = built_model['countermeasures'][0]['printable-tags']
        self.assertEqual(len(printable_tags), 2)
        self.assertIn('c', printable_tags)
        self.assertIn('d', printable_tags)

    def test_criteria_tag(self):
        """Verify that printable tag in 'criteria' array is included."""
        bare_model = {
            'attackers': [
                {
                    'name': 'attacker1',
                    'attacks': [
                        {
                            'name': 'attack1',
                            'countermeasures': [
                                {
                                    'id': 'counterm1',
                                    'criteria-groups': [
                                        {
                                            "criteria": [
                                                {
                                                    "id": "CR1",
                                                    "tags": ["a", "b"]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ],
            "countermeasures": [{'id':'counterm1'}],
            "criteria": [{"id": "CR1", 'tags': ['c', 'd']}]
        }
        built_model = model_builder.get_built_model(bare_model)
        printable_tags = (built_model['attackers'][0]['attacks'][0]
                          ['countermeasures'][0]['criteria-groups'][0]['criteria']
                          [0]['printable-tags'])
        self.assertEqual(len(printable_tags), 4)
        self.assertIn('a', printable_tags)
        self.assertIn('b', printable_tags)
        self.assertIn('c', printable_tags)
        self.assertIn('d', printable_tags)

        printable_tags = (built_model['criteria'][0]['printable-tags'])
        self.assertEqual(len(printable_tags), 2)
        self.assertIn('c', printable_tags)
        self.assertIn('d', printable_tags)

    def test_criterion_tag_only_in_defn(self):
        """Make sure tag is included if the only tags are in the criterion defn
        """
        bare_model = {
            'attackers': [
                {
                    'name': 'attacker1',
                    'attacks': [
                        {
                            'name': 'attack1',
                            'countermeasures': [
                                {
                                    'id': 'counterm1',
                                    'criteria-groups': [
                                        {
                                            "criteria": [
                                                {
                                                    "id": "CR1",
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ],
            "countermeasures": [{'id':'counterm1'}],
            "criteria": [{"id": "CR1", 'tags': ['a', 'b']}]
        }
        built_model = model_builder.get_built_model(bare_model)
        printable_tags = (built_model['attackers'][0]['attacks'][0]
                          ['countermeasures'][0]['criteria-groups'][0]['criteria']
                          [0]['printable-tags'])
        self.assertEqual(len(printable_tags), 2)
        self.assertIn('a', printable_tags)
        self.assertIn('b', printable_tags)

        printable_tags = (built_model['criteria'][0]['printable-tags'])
        self.assertEqual(len(printable_tags), 2)
        self.assertIn('a', printable_tags)
        self.assertIn('b', printable_tags)

SUITE1 = unittest.TestLoader().loadTestsFromTestCase(PrintableTagsTest)
