"""
Tests for base_authorization
"""
import datetime
import pytz

from django.test import override_settings
from django.conf import settings
from django.test import TestCase

from ozpcenter import errors
from ozpcenter.scripts import sample_data_generator as data_gen
from plugins.default_authorization.main import PluginMain
import ozpcenter.model_access as model_access


@override_settings(ES_ENABLED=False)
class OzpAuthorizationTest(TestCase):

    def setUp(self):
        """
        setUp is invoked before each test method
        """
        # Store the orginal value of USE_AUTH_SERVER
        self.USE_AUTH_SERVER_ORGINAL = settings.OZP['USE_AUTH_SERVER']
        # Setting USE_AUTH_SERVER to True makes the test run
        settings.OZP['USE_AUTH_SERVER'] = True
        self.auth = PluginMain()

    def tearDown(self):
        """
        tearDown is invoked after each test method
        """
        # Set the value of USE_AUTH_SERVER to the orginal value
        settings.OZP['USE_AUTH_SERVER'] = self.USE_AUTH_SERVER_ORGINAL

    @classmethod
    def setUpTestData(cls):
        """
        Set up test data for the whole TestCase (only run once for the TestCase)
        """
        data_gen.run()

    def test_invalid_auth_cache(self):
        """
        test_invalid_auth_cache
        If user's auth_expires is set too far ahead, authorization should fail
        Set auth cache to expire in 1+ days (against the rules!)
        """
        profile = model_access.get_profile('jones')
        profile.auth_expires = datetime.datetime.now(pytz.utc) + datetime.timedelta(days=1, seconds=5)
        profile.save()

        self.assertRaises(errors.AuthorizationFailure,
            self.auth.authorization_update, 'jones', method='test_invalid_auth_cache')

    def test_valid_cache(self):
        profile = model_access.get_profile('jones')

        # set auth cache to expire in 1 day
        profile.auth_expires = datetime.datetime.now(pytz.utc) + datetime.timedelta(days=1)
        profile.save()
        self.assertEqual(self.auth.authorization_update('jones', method='test_valid_cache'), True)

        # try again with cache almost expired
        profile.auth_expires = datetime.datetime.now(pytz.utc) + datetime.timedelta(seconds=2)
        profile.save()
        self.assertEqual(self.auth.authorization_update('jones', method='test_valid_cache'), True)

    def test_update_cache(self):
        profile = model_access.get_profile('jones')
        profile.auth_expires = datetime.datetime.now(pytz.utc)
        profile.save()
        auth_data = {
            'dn': 'Jones jones',
            'cn': 'Jones',
            'clearances': ['U', 'C', 'S'],
            'formal_accesses': [],
            'country': 'NONSUPER',
            'visas': ['NOVEMBER'],
            'duty_org': 'Minitrue',
            'is_org_steward': False,
            'is_apps_mall_steward': False,
            'is_metrics_user': False,
            'is_beta_user': False
        }
        authorization_update_result = self.auth.authorization_update('jones', auth_data, method='test_update_cache')
        self.assertTrue(authorization_update_result)
        # auth_expires should be rest to ~1 day from now
        profile = model_access.get_profile('jones')
        auth_expires_in = profile.auth_expires - datetime.datetime.now(pytz.utc)
        # 86,400 seconds in a day
        min_sec = int(settings.OZP['OZP_AUTHORIZATION']['SECONDS_TO_CACHE_DATA']) - 2
        self.assertTrue(min_sec < auth_expires_in.seconds < 86400)

        # TODO: test access_control

    def test_org_change(self):
        """
        A user's agency (organization) changes
        """
        profile = model_access.get_profile('rutherford')
        profile.auth_expires = datetime.datetime.now(pytz.utc)
        profile.save()
        org = profile.organizations.values_list('title', flat=True)[0]
        self.assertEqual(org, 'Ministry of Plenty')

        auth_data = {
            'dn': 'Rutherford rutherford',
            'cn': 'Rutherford',
            'clearances': ['U', 'C', 'S'],
            'formal_accesses': [],
            'country': 'NONSUPER',
            'visas': [],
            'duty_org': 'Miniluv',
            'is_org_steward': False,
            'is_apps_mall_steward': False,
            'is_metrics_user': False,
            'is_beta_user': False
        }
        self.auth.authorization_update('rutherford', auth_data, method='test_org_change')
        profile = model_access.get_profile('rutherford')
        org = profile.organizations.values_list('title', flat=True)[0]
        self.assertEqual(org, 'Ministry of Love')

    def test_org_steward_to_user(self):
        """
        A user who was an org steward is now a regular user
        """
        profile = model_access.get_profile('wsmith')
        profile.auth_expires = datetime.datetime.now(pytz.utc)
        profile.save()
        stewarded_orgs = profile.stewarded_organizations.values_list('title', flat=True)
        self.assertTrue('Ministry of Truth' in stewarded_orgs)
        self.assertEqual(profile.highest_role(), 'ORG_STEWARD')
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('ORG_STEWARD' in groups)
        auth_data = {
            'dn': 'Winston Smith wsmith',
            'cn': 'Winston Smith',
            'clearances': ['U', 'C', 'S', 'TS'],
            'formal_accesses': [],
            'country': 'NONSUPER',
            'visas': [],
            'duty_org': 'Minitrue',
            'is_org_steward': False,
            'is_apps_mall_steward': False,
            'is_metrics_user': False,
            'is_beta_user': False
        }
        self.auth.authorization_update('wsmith', auth_data, method='test_org_steward_to_user')
        profile = model_access.get_profile('wsmith')
        stewarded_orgs = profile.stewarded_organizations.values_list('title', flat=True)
        self.assertEqual(len(stewarded_orgs), 0)
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('USER' in groups)
        self.assertEqual(len(groups), 1)
        self.assertEqual(profile.highest_role(), 'USER')

    def test_apps_mall_steward_to_user(self):
        """
        A user who was an apps mall steward is now a regular user
        """
        profile = model_access.get_profile('bigbrother')
        profile.auth_expires = datetime.datetime.now(pytz.utc)
        profile.save()

        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('APPS_MALL_STEWARD' in groups)
        self.assertEqual(profile.highest_role(), 'APPS_MALL_STEWARD')
        auth_data = {
            'dn': 'Big Brother bigbrother',
            'cn': 'Big Brother',
            'clearances': ['U', 'C', 'S', 'TS'],
            'formal_accesses': [],
            'country': 'NONSUPER',
            'visas': [],
            'duty_org': 'Minitrue',
            'is_org_steward': False,
            'is_apps_mall_steward': False,
            'is_metrics_user': False,
            'is_beta_user': False
        }
        self.auth.authorization_update('bigbrother', auth_data, method='test_apps_mall_steward_to_user')
        profile = model_access.get_profile('bigbrother')
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('USER' in groups)
        self.assertEqual(len(groups), 1)
        self.assertFalse('APPS_MALL_STEWARD' in groups)
        self.assertEqual(profile.highest_role(), 'USER')

    def test_apps_mall_steward_to_org_steward(self):
        """
        A user who was an apps mall steward is now an org steward
        """
        profile = model_access.get_profile('bigbrother')
        profile.auth_expires = datetime.datetime.now(pytz.utc)
        profile.save()

        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('APPS_MALL_STEWARD' in groups)
        self.assertEqual(profile.highest_role(), 'APPS_MALL_STEWARD')
        auth_data = {
            'dn': 'Big Brother bigbrother',
            'cn': 'Big Brother',
            'clearances': ['U', 'C', 'S', 'TS'],
            'formal_accesses': [],
            'country': 'NONSUPER',
            'visas': [],
            'duty_org': 'Minitrue',
            'is_org_steward': True,
            'is_apps_mall_steward': False,
            'is_metrics_user': False,
            'is_beta_user': False
        }
        self.auth.authorization_update('bigbrother', auth_data, method='test_org_steward_to_apps_mall_steward')
        profile = model_access.get_profile('bigbrother')
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('ORG_STEWARD' in groups)
        self.assertEqual(profile.highest_role(), 'ORG_STEWARD')

    def test_org_steward_to_apps_mall_steward_only(self):
        """
        A user who was an org steward is now an apps mall steward
        """
        profile = model_access.get_profile('wsmith')
        profile.auth_expires = datetime.datetime.now(pytz.utc)
        profile.save()
        stewarded_orgs = profile.stewarded_organizations.values_list('title', flat=True)
        self.assertTrue('Ministry of Truth' in stewarded_orgs)
        self.assertEqual(profile.highest_role(), 'ORG_STEWARD')
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('ORG_STEWARD' in groups)
        auth_data = {
            'dn': 'Winston Smith wsmith',
            'cn': 'Winston Smith',
            'clearances': ['U', 'C', 'S', 'TS'],
            'formal_accesses': [],
            'country': 'NONSUPER',
            'visas': [],
            'duty_org': 'Minitrue',
            'is_org_steward': False,
            'is_apps_mall_steward': True,
            'is_metrics_user': False,
            'is_beta_user': False
        }
        self.assertTrue(self.auth.authorization_update('wsmith', auth_data,
                    method='test_org_steward_to_apps_mall_steward_only'))
        profile = model_access.get_profile('wsmith')
        stewarded_orgs = profile.stewarded_organizations.values_list('title', flat=True)
        self.assertEqual(len(stewarded_orgs), 0)
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('APPS_MALL_STEWARD' in groups)
        self.assertTrue('ORG_STEWARD' not in groups)
        self.assertEqual(profile.highest_role(), 'APPS_MALL_STEWARD')

    def test_org_steward_to_apps_mall_steward(self):
        """
        A user who was an org steward is now also an apps mall steward
        """
        profile = model_access.get_profile('wsmith')
        profile.auth_expires = datetime.datetime.now(pytz.utc)
        profile.save()

        stewarded_orgs = profile.stewarded_organizations.values_list('title', flat=True)
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('Ministry of Truth' in stewarded_orgs)
        self.assertEqual(profile.highest_role(), 'ORG_STEWARD')
        self.assertTrue('ORG_STEWARD' in groups)

        auth_data = {
            'dn': 'Winston Smith wsmith',
            'cn': 'Winston Smith',
            'clearances': ['U', 'C', 'S', 'TS'],
            'formal_accesses': [],
            'country': 'NONSUPER',
            'visas': [],
            'duty_org': 'Minitrue',
            'is_org_steward': True,
            'is_apps_mall_steward': True,
            'is_metrics_user': False,
            'is_beta_user': False,
        }
        self.assertTrue(self.auth.authorization_update('wsmith', auth_data, method='test_org_steward_to_apps_mall_steward'))

        profile = model_access.get_profile('wsmith')
        stewarded_orgs = profile.stewarded_organizations.values_list('title', flat=True)
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('Ministry of Truth' in stewarded_orgs)
        self.assertTrue('APPS_MALL_STEWARD' in groups)
        self.assertTrue('ORG_STEWARD' in groups)
        self.assertEqual(profile.highest_role(), 'APPS_MALL_STEWARD')

    def test_beta_user_to_user(self):
        """
        A user who was a beta user is now a user
        """
        profile = model_access.get_profile('betaraybill')
        profile.auth_expires = datetime.datetime.now(pytz.utc)
        profile.save()

        groups = profile.user.groups.values_list('name', flat=True)
        self.assertEqual(profile.highest_role(), 'USER')
        self.assertTrue('BETA_USER' in groups)

        auth_data = {
            'dn': 'BetaRayBill betaraybill',
            'cn': 'Beta Ray Bill',
            'clearances': ['U', 'C', 'S', 'TS'],
            'formal_accesses': [],
            'country': 'SUPER',
            'visas': [],
            'duty_org': 'Miniluv',
            'is_org_steward': False,
            'is_apps_mall_steward': False,
            'is_metrics_user': False,
            'is_beta_user': False,
        }
        self.assertTrue(self.auth.authorization_update('betaraybill', auth_data, method='test_user_to_beta_user'))

        profile = model_access.get_profile('betaraybill')
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertFalse('BETA_USER' in groups)
        self.assertEqual(profile.highest_role(), 'USER')

    def test_beta_user_apps_mall_steward_to_apps_mall_steward(self):
        """
        A apps mall steward who was a beta user is now a apps mall steward
        """
        profile = model_access.get_profile('bettafish')
        profile.auth_expires = datetime.datetime.now(pytz.utc)
        profile.save()
        self.assertEqual(profile.highest_role(), 'APPS_MALL_STEWARD')
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertTrue('BETA_USER' in groups)
        self.assertEqual(len(groups), 2)
        auth_data = {
            'dn': 'Bettafish bettafish',
            'cn': 'Betta Fish',
            'clearances': ['U', 'C', 'S', 'TS'],
            'formal_accesses': [],
            'country': 'SUPER',
            'visas': [],
            'duty_org': 'Miniluv',
            'is_org_steward': False,
            'is_apps_mall_steward': True,
            'is_metrics_user': False,
            'is_beta_user': False,
        }
        self.auth.authorization_update('betaraybill', auth_data, method='test_beta_user_apps_mall_steward_to_apps_mall_steward')
        profile = model_access.get_profile('betaraybill')
        groups = profile.user.groups.values_list('name', flat=True)
        self.assertFalse('BETA_USER' in groups)
        self.assertEqual(len(groups), 1)
        self.assertEqual(profile.highest_role(), 'APPS_MALL_STEWARD')
