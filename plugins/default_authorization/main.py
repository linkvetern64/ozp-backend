"""
This is the plugin that accesses the Authorization Server

Authorization for OZP using the DemoAuth service

Checks models.Profile.auth_expires. If auth is expired, refresh it.

- models.Profile.user.groups (User, Org Steward, or Apps Mall Steward)
- models.Profile.stewarded_organizations (clear all if user is not an Org Steward)
- models.Profile.organizations
- models.Profile.access_control
- models.Profile.display_name (use CN)
"""
import datetime
import json
import logging
import pytz

from django.conf import settings
from django.contrib.auth.models import Group

from ozpcenter import errors
from ozpcenter import models
from ozpcenter import utils
import ozpcenter.model_access as model_access


logger = logging.getLogger('ozp-center.' + str(__name__))


class PluginMain(object):
    plugin_name = 'default_authorization'
    plugin_description = 'DefaultAuthorizationPlugin'
    plugin_type = 'authorization'

    def __init__(self, settings=None, requests=None):
        '''
        Settings: Object reference to ozp settings
        '''
        self.settings = settings
        self.requests = requests

    def _get_auth_data(self, username):
        """
        Get authorization data for given user

        Return:
        {
            'dn': 'user DN',
            'clearances': ['U', 'S'],
            'formal_accesses': ['AB', 'CD'],
            'visas': ['ABC', 'XYZ'],
            'duty_org': 'org',
            'country': 'USA',
            'is_org_steward': False,
            'is_apps_mall_steward': False,
            'is_metrics_user': True
        }
        """
        profile = model_access.get_profile(username)
        # get user's basic data
        url = self.settings.OZP['OZP_AUTHORIZATION']['USER_INFO_URL'] % (profile.dn, profile.issuer_dn)
        server_crt = self.settings.OZP['OZP_AUTHORIZATION']['SERVER_CRT']
        server_key = self.settings.OZP['OZP_AUTHORIZATION']['SERVER_KEY']
        r = self.requests.get(url, cert=(server_crt, server_key), verify=False)
        # logger.debug('hitting url %s for user with dn %s' % (url, profile.dn), extra={'request':request})

        if r.status_code != 200:
            raise errors.AuthorizationFailure('Error contacting authorization server: {0!s}'.format(r.text))

        user_data = r.json()

        user_json_keys = ['dn', 'formalAccesses', 'clearances', 'dutyorg', 'visas', 'country']
        for user_key in user_json_keys:
            if user_key not in user_data:
                raise ValueError('Endpoint {0!s} not return value output - missing key: {1!s}'.format(url, user_key))

        # convert dutyorg -> duty_org
        user_data['duty_org'] = user_data['dutyorg']
        user_data.pop('dutyorg', None)

        # convert formalAcccesses -> formal_accesses
        user_data['formal_accesses'] = user_data['formalAccesses']
        user_data.pop('formalAccesses', None)

        # get groups for user
        url = self.settings.OZP['OZP_AUTHORIZATION']['USER_GROUPS_URL'] % (profile.dn, self.settings.OZP['OZP_AUTHORIZATION']['PROJECT_NAME'])
        # logger.debug('hitting url %s for user with dn %s for group info' % (url, profile.dn), extra={'request':request})
        r = self.requests.get(url, cert=(server_crt, server_key), verify=False)
        if r.status_code != 200:
            raise errors.AuthorizationFailure('Error contacting authorization server: {0!s}'.format(r.text))

        group_data = r.json()

        if 'groups' not in group_data:
            raise ValueError('Endpoint {0!s} not return value output - missing key: {1!s}'.format(url, 'groups'))

        groups = group_data['groups']
        user_data['is_org_steward'] = False
        user_data['is_apps_mall_steward'] = False
        user_data['is_metrics_user'] = False
        user_data['is_beta_user'] = False

        for g in groups:
            if self.settings.OZP['OZP_AUTHORIZATION']['APPS_MALL_STEWARD_GROUP_NAME'] == utils.find_between(g, 'cn=', ','):
                user_data['is_apps_mall_steward'] = True
            if self.settings.OZP['OZP_AUTHORIZATION']['ORG_STEWARD_GROUP_NAME'] == utils.find_between(g, 'cn=', ','):
                user_data['is_org_steward'] = True
            if self.settings.OZP['OZP_AUTHORIZATION']['METRICS_GROUP_NAME'] == utils.find_between(g, 'cn=', ','):
                user_data['is_org_steward'] = True
            if self.settings.OZP['OZP_AUTHORIZATION']['BETA_USER_GROUP_NAME'] == utils.find_between(g, 'cn=', ','):
                user_data['is_beta_user'] = True
        return user_data

    def authorization_update(self, username, updated_auth_data=None, request=None, method=None):
        """
        Update authorization info for this user

        Args:
            username: username for which to update auth data
            updated_auth_data: for testing purposes - if this is passed in,
                the data is used instead of invoking the parent class's
                get_auth_data() method

        Return True if update succeeds, False otherwise
        """
        if not settings.OZP['USE_AUTH_SERVER']:
            return True

        profile = model_access.get_profile(username)
        if not profile:
            raise errors.NotFound('User {0!s} was not found - cannot update authorization info'.format(username))

        # check profile.auth_expires. if auth_expires - now > 24 hours, raise an
        # exception (auth data should never be cached for more than 24 hours)
        now = datetime.datetime.now(pytz.utc)
        seconds_to_cache_data = int(settings.OZP['OZP_AUTHORIZATION']['SECONDS_TO_CACHE_DATA'])
        if seconds_to_cache_data > 24 * 3600:
            raise errors.AuthorizationFailure('Cannot cache data for more than 1 day')

        expires_in = profile.auth_expires - now
        if expires_in.days >= 1:
            raise errors.AuthorizationFailure('User {0!s} had auth expires set to expire in more than 24 hours'.format(username))

        # if auth_data cache hasn't expired, we're good to go
        # TODO: might want to check and see if auth expires in 12 hours
        # (or something like that)
        # and if so, try to preemptively update user's credentials. This would
        # help to alleviate errors due to the authorization service being down
        # Example: '2016-04-18 15:57:09.275093+00:00' <= '2016-04-18 16:36:05.825269+00:00' = True
        if now <= profile.auth_expires:
            logger.debug('no auth refresh required. Expires in {0!s} seconds'.format(expires_in.seconds),
                         extra={'request': request, 'method': method})
            return True

        # otherwise, auth data must be updated
        if not updated_auth_data:
            updated_auth_data = self._get_auth_data(username)  # , request=request)
            if not updated_auth_data:
                return False

        # update the user's org (profile.organizations) from duty_org
        # validate the org
        duty_org = updated_auth_data['duty_org']
        orgs = models.Agency.objects.values_list('short_name', flat=True)

        if duty_org not in orgs:
            if (hasattr(settings, 'DEFAULT_AGENCY') and (settings.DEFAULT_AGENCY != '')):
                duty_org = settings.DEFAULT_AGENCY
            else:
                raise errors.AuthorizationFailure('User {0!s} has invalid duty org {1!s}'.format(username, duty_org))

        # update the user's org
        try:
            profile.organizations.clear()
            org = models.Agency.objects.get(short_name=duty_org)
            profile.organizations.add(org)
        except Exception as e:
            logger.error('Failed to update organizations for user {0!s}. Error: {1!s}'.format(username, str(e)),
                         extra={'request': request, 'method': method})
            return False

        is_user_flag = True

        if not updated_auth_data['is_org_steward']:
            # remove all profile.stewarded_orgs
            profile.stewarded_organizations.clear()
            # remove ORG_STEWARD from profile.user.groups
            for g in profile.user.groups.all():
                if g.name == 'ORG_STEWARD':
                    profile.user.groups.remove(g)
        else:
            # ensure ORG_STEWARD is in profile.user.groups
            g = Group.objects.get(name='ORG_STEWARD')
            profile.user.groups.add(g)
            is_user_flag = False

        if not updated_auth_data['is_apps_mall_steward']:
            # ensure APPS_MALL_STEWARD is not in profile.user.groups
            for g in profile.user.groups.all():
                if g.name == 'APPS_MALL_STEWARD':
                    profile.user.groups.remove(g)
        else:
            # ensure APPS_MALL_STEWARD is in profile.user.groups
            g = Group.objects.get(name='APPS_MALL_STEWARD')
            profile.user.groups.add(g)
            is_user_flag = False

        if is_user_flag:
            # add to USER group
            g = Group.objects.get(name='USER')
            profile.user.groups.add(g)
        else:
            for g in profile.user.groups.all():
                if g.name == 'USER':
                    profile.user.groups.remove(g)

        # TODO: handle metrics user
        if not updated_auth_data['is_beta_user']:
            # ensure BETA USER is not in profile.user.groups
            for g in profile.user.groups.all():
                if g.name == 'BETA_USER':
                    profile.user.groups.remove(g)
        else:
            # ensure BETA_USER is in profile.user.groups
            g = Group.objects.get(name='BETA_USER')
            profile.user.groups.add(g)

        # update profile.access_control:
        access_control = json.dumps(updated_auth_data)
        profile.access_control = access_control
        # reset profile.auth_expires to now + 24 hours
        profile.auth_expires = now + datetime.timedelta(seconds=seconds_to_cache_data)
        profile.save()
        return True
