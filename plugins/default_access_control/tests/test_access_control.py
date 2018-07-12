"""
Tests for access control utility functions
"""
import json

from django.test import override_settings
from django.test import TestCase

from ozpcenter.scripts import sample_data_generator as data_gen
from plugins.default_access_control.main import PluginMain


@override_settings(ES_ENABLED=False)
class AccessControlTest(TestCase):

    def setUp(self):
        """
        setUp is invoked before each test method
        """
        self.access_control_instance = PluginMain()
        # TODO: Import

    @classmethod
    def setUpTestData(cls):
        """
        Set up test data for the whole TestCase (only run once for the TestCase)
        """
        data_gen.run()

    def test_split_tokens(self):
        marking = 'UNCLASSIFIED//FOUO//ABC'
        tokens = self.access_control_instance._split_tokens(marking)

        actual_value = str(tokens)
        expected_value = '[ClassificationToken(Unclassified), DisseminationControlToken(FOR OFFICIAL USE ONLY), UnknownToken(ABC)]'

        self.assertEquals(actual_value, expected_value)

        marking = 'UNCLASSIFIED'
        tokens = self.access_control_instance._split_tokens(marking)

        actual_value = str(tokens)
        expected_value = '[ClassificationToken(Unclassified)]'

        self.assertEquals(actual_value, expected_value)

        marking = 'UNcLaSsIfied'
        tokens = self.access_control_instance._split_tokens(marking)

        actual_value = str(tokens)
        expected_value = '[ClassificationToken(Unclassified)]'

        self.assertEquals(actual_value, expected_value)

    def test_validate_marking(self):
        marking = 'UNCLASSIFIED'
        validated = self.access_control_instance.validate_marking(marking)
        self.assertTrue(validated)

        marking = 'UNCLASSIFIED//FOUO//ABC'
        validated = self.access_control_instance.validate_marking(marking)
        self.assertTrue(validated)

        marking = 'Invalid//FOUO//ABC'
        validated = self.access_control_instance.validate_marking(marking)
        self.assertFalse(validated)

        marking = ''
        validated = self.access_control_instance.validate_marking(marking)
        self.assertFalse(validated)

        marking = None
        validated = self.access_control_instance.validate_marking(marking)
        self.assertFalse(validated)

    def test_has_access_unclass(self):
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED"],
                "formal_accesses": ["FOUO", "ABC"],
                "visas": []
            }
        )
        marking = 'UNCLASSIFIED//FOUO//ABC'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))

        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED"],
                "formal_accesses": [],
                "visas": []
            }
        )
        marking = 'UNCLASSIFIED'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))

        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED"],
                "formal_accesses": ["FOUO"],
                "visas": []
            }
        )
        marking = 'UNCLASSIFIED//FOUO//ABC'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED"],
                "formal_accesses": ["FOUO"],
                "visas": []
            }
        )
        marking = 'CONFIDENTIAL'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'SECRET'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'TOP SECRET'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'INVALID LEVEL'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))

    def test_has_access_confidential(self):
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL"],
                "formal_accesses": ["FOUO", "ABC"],
                "visas": []
            }
        )
        marking = 'UNCLASSIFIED//FOUO//ABC'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL"],
                "formal_accesses": [],
                "visas": []
            }
        )
        marking = 'CONFIDENTIAL'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL"],
                "formal_accesses": ["FOUO", "ABC"],
                "visas": []
            }
        )
        marking = 'CONFIDENTIAL//FOUO//ABC'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))

        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED"],
                "formal_accesses": ["FOUO"],
                "country": "USA",
                "visas": []
            }
        )
        marking = 'CONFIDENTIAL'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'SECRET'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'TOP SECRET'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'INVALID LEVEL'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))

    def test_has_access_secret(self):
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "visas": []
            }
        )
        marking = 'UNCLASSIFIED//FOUO//ABC'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "visas": []
            }
        )
        marking = 'CONFIDENTIAL//FOUO//ABC'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"],
                "formal_accesses": [],
                "visas": []
            }
        )
        marking = 'SECRET'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "visas": []
            }
        )
        marking = 'SECRET//FOUO//ABC'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))

        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "visas": []
            }
        )
        marking = 'TOP SECRET//FOUO//ABC'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'SECRET//FOUO//ABC/XYZ'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))

        marking = 'INVALID LEVEL'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))

    def test_has_access_top_secret(self):
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "visas": []
            }
        )
        marking = 'UNCLASSIFIED//FOUO//ABC'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'CONFIDENTIAL//FOUO//ABC'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'SECRET//FOUO//ABC'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'TOP SECRET//FOUO//ABC'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"],
                "formal_accesses": [],
                "visas": []
            }
        )
        marking = 'TOP SECRET'
        self.assertTrue(self.access_control_instance.future_has_access_json(user_accesses_json, marking))

        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "visas": []
            }
        )
        marking = 'SECRET//FOUO//ABC/XYZ'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'UNCLASSIFIED//FOUO//ABC/XYZ'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))
        marking = 'INVALID LEVEL'
        self.assertFalse(self.access_control_instance.future_has_access_json(user_accesses_json, marking))

    def test_has_access_top_secret_updated_super_country(self):
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "country": "SUPER",
                "visas": []
            }
        )
        marking = 'UNCLASSIFIED//FOUO//ABC'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'CONFIDENTIAL//FOUO//ABC'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'SECRET//FOUO//ABC'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'TOP SECRET//FOUO//ABC'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))

    def test_has_access_top_secret_updated_non_super_country(self):
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "country": "Jupiter",
                "visas": ["ACGU"]
            }
        )
        marking = 'TOP SECRET//ACGU'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'TOP SECRET//NOTOUTSIDE'
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'SECRET//ACGU'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'SECRET//NOTOUTSIDE'
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'UNCLASSIFIED//FVEY'
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'INVALID LEVEL'
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))

    def test_has_access_secret_updated_super_country(self):
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "country": "SUPER",
                "visas": []
            }
        )
        marking = 'UNCLASSIFIED//FOUO//ABC'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'CONFIDENTIAL//FOUO//ABC'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'SECRET//FOUO//ABC'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        marking = 'TOP SECRET//FOUO//ABC'
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))

    def test_has_access_secret_updated_country_and_visas(self):
        user_accesses_json = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "country": "SUPER",
                "visas": []
            }
        )
        user_accesses_json2 = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "country": "NONSUPER",
                "visas": ["ALL", "FOUR"]
            }
        )
        user_accesses_json3 = json.dumps(
            {
                "clearances": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"],
                "formal_accesses": ["FOUO", "ABC"],
                "country": "NONSUPER3",
                "visas": ["FOUR"]
            }
        )
        marking = 'TOP SECRET//ALL'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json2, marking))
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json3, marking))
        marking = 'TOP SECRET//ONLYA'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json2, marking))
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json3, marking))
        marking = 'SECRET//ALL'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json2, marking))
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json3, marking))
        marking = 'SECRET//ONLYA'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json2, marking))
        self.assertFalse(self.access_control_instance.has_access_json_updated(user_accesses_json3, marking))
        marking = 'SECRET//FOUR'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json2, marking))
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json3, marking))
        marking = 'UNCLASSIFIED//FOUR'
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json, marking))
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json2, marking))
        self.assertTrue(self.access_control_instance.has_access_json_updated(user_accesses_json3, marking))

    def test_anonymize_identifiable_data(self):
        # bigbrother
        # {'clearances': ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP SECRET'], 'visas': ['NOVEMBER'], 'formal_accesses': ['SIERRA', 'TANGO', 'GOLF', 'HOTEL'], 'country': 'SUPER'}
        self.assertFalse(self.access_control_instance.anonymize_identifiable_data('bigbrother'))

        # aaronson
        # {'formal_accesses': [], 'clearances': ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET'], 'country': 'NONSUPER', 'visas': ['NOVEMBER']}
        self.assertTrue(self.access_control_instance.anonymize_identifiable_data('aaronson'))
