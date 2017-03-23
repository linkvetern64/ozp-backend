"""
Notification Serializers
"""
import logging

from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers

from ozpcenter import models
from plugins_util import plugin_manager
from plugins_util.plugin_manager import system_anonymize_identifiable_data
import ozpcenter.api.listing.model_access as listing_model_access
import ozpcenter.api.library.model_access as library_model_access
import ozpcenter.api.agency.model_access as agency_model_access
import ozpcenter.api.notification.model_access as model_access
import ozpcenter.model_access as generic_model_access
import ozpcenter.api.profile.serializers as profile_serializers

# Get an instance of a logger
logger = logging.getLogger('ozp-center.' + str(__name__))


class NotificationListingSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.Listing
        fields = ('id', 'title')

        extra_kwargs = {
            'title': {'validators': []}
        }


class NotificationAgencySerializer(serializers.ModelSerializer):

    class Meta:
        model = models.Agency
        fields = ('id', 'title')

        extra_kwargs = {
            'title': {'validators': []}
        }


class DictField(serializers.ReadOnlyField):
    """
    Read Only Field
    """

    def from_native(self, obj):
        return None


class NotificationSerializer(serializers.ModelSerializer):
    author = profile_serializers.ShortProfileSerializer(required=False)
    listing = NotificationListingSerializer(required=False)
    agency = NotificationAgencySerializer(required=False)

    class Meta:
        model = models.Notification
        fields = ('id', 'created_date', 'expires_date', 'author',
            'message', 'notification_type', 'listing', 'agency', 'entity_id', 'peer', )

        extra_kwargs = {
            'listing': {'validators': []},
            'agency': {'validators': []},
        }

    def to_representation(self, data):
        access_control_instance = plugin_manager.get_system_access_control_plugin()
        ret = super(NotificationSerializer, self).to_representation(data)

        peer = ret['peer']
        if peer and peer.get('_bookmark_listing_ids'):
            del peer['_bookmark_listing_ids']
        # Used to anonymize usernames
        anonymize_identifiable_data = system_anonymize_identifiable_data(self.context['request'].user.username)

        if anonymize_identifiable_data:
            if peer:
                peer['user']['username'] = access_control_instance.anonymize_value('username')
            # TODO: Hide Peer data (erivera 2016-07-29)

        # del ret['agency']
        # del ret['listing']
        return ret

    def validate(self, validated_data):
        """ Responsible of cleaning and validating user input data """
        validated_data['error'] = None
        initial_data = self.initial_data
        username = self.context['request'].user.username

        # Check for notification types
        key_type_list = []

        if 'listing' in initial_data:
            key_type_list.append('listing')

        if 'agency' in initial_data:
            key_type_list.append('agency')

        if 'peer' in initial_data:
            key_type_list.append('peer')

        if len(key_type_list) >= 2:
            raise serializers.ValidationError('Notifications can only be one type. Input: {0}'.format(key_type_list))

        if 'message' not in validated_data and self.context['request'].method == 'POST':
            raise serializers.ValidationError('Messsage field is required for POST Request')

        # TODO: Figure how to get listing data using validated data
        listing = initial_data.get('listing')
        if listing:
            if listing.get('id'):
                try:
                    validated_data['listing'] = listing_model_access.get_listing_by_id(
                        username, initial_data['listing']['id'], True)
                except ObjectDoesNotExist:
                    raise serializers.ValidationError('Could not find listing')
            else:
                raise serializers.ValidationError('Valid Listing ID is required')
        else:
            validated_data['listing'] = None

        # Agency Validation
        agency = initial_data.get('agency')
        if agency:
            if agency.get('id'):
                try:
                    validated_data['agency'] = agency_model_access.get_agency_by_id(
                        initial_data['agency']['id'], True)
                except ObjectDoesNotExist:
                    raise serializers.ValidationError('Could not find agency')
            else:
                raise serializers.ValidationError('Valid Agency ID is required')
        else:
            validated_data['agency'] = None

        # Peer Validation
        peer = initial_data.get('peer')
        if peer:
            temp_peer = {}

            if peer.get('user'):
                temp_peer['user'] = peer.get('user')

            if peer.get('folder_name'):
                temp_peer['folder_name'] = peer.get('folder_name')

            target_username = temp_peer.get('user', {}).get('username')

            if not target_username:
                raise serializers.ValidationError('Valid Username is Required')

            target_username_profile = generic_model_access.get_profile(target_username)

            if not target_username_profile:
                raise serializers.ValidationError('Valid User is Required')

            validated_data['entity_id'] = target_username_profile.pk
            # Folder Validation - Optional Field
            temp_folder_name = temp_peer.get('folder_name')
            if temp_folder_name:
                library_query = library_model_access.get_self_application_library(username, folder_name=temp_folder_name)
                temp_peer['_bookmark_listing_ids'] = [library_query_entry.listing.id for library_query_entry in library_query]

                # temp_peer['_user_folders'] = library_serializers.UserLibrarySerializer(library_query,
                #      many=True, context={'request': self.context['request']}).data

                if len(temp_peer['_bookmark_listing_ids']) == 0:
                    raise serializers.ValidationError('No entries in target folder')

            validated_data['peer'] = temp_peer
        else:
            validated_data['peer'] = None

        return validated_data

    def create(self, validated_data):
        """
        Used to create notifications
        """
        if validated_data['error']:
            raise serializers.ValidationError('{0}'.format(validated_data['error']))

        username = self.context['request'].user.username
        notification = model_access.create_notification(username,
                                                        validated_data['expires_date'],
                                                        validated_data['message'],
                                                        validated_data['listing'],
                                                        validated_data['agency'],
                                                        validated_data['peer'],
                                                        validated_data.get('entity_id'))
        return notification

    def update(self, instance, validated_data):
        """
        This is only used to update the expired_date field (effectively
        deleting a notification while still leaving a record of it)
        """
        if validated_data['error']:
            raise serializers.ValidationError('{0}'.format(validated_data['error']))

        username = self.context['request'].user.username
        notification = model_access.update_notification(username,
                                                        instance,
                                                        validated_data['expires_date'])
        return notification

#
# class NotificationV2Serializer(serializers.ModelSerializer):
#
#     class Meta:
#         model = models.NotificationV2
#         fields = ('id',
#                   'notification_id', 'created_date', 'expires_date', 'author_username',
#                   'message', 'notification_type',
#                   'metadata',
#                     )
#
#     def to_representation(self, data):
#         access_control_instance = plugin_manager.get_system_access_control_plugin()
#         ret = super(NotificationV2Serializer, self).to_representation(data)
#
#         if not ret['metadata']:
#             ret['metadata'] = {}
#
#         metadata = ret['metadata']
#
#         if metadata and metadata.get('_bookmark_listing_ids'):
#             del metadata['_bookmark_listing_ids']
#         # Used to anonymize usernames
#         anonymize_identifiable_data = system_anonymize_identifiable_data(self.context['request'].user.username)
#
#         if anonymize_identifiable_data:
#             if metadata:
#                 metadata['user']['username'] = access_control_instance.anonymize_value('username')
#             # TODO: Hide Peer data (erivera 2016-07-29)
#
#         return ret
#
#     def validate(self, validated_data):
#         """ Responsible of cleaning and validating user input data """
#         validated_data['error'] = None
#         initial_data = self.initial_data
#         username = self.context['request'].user.username
#
#         # Check for notification types
#         key_type_list = []
#
#         if 'listing' in initial_data:
#             key_type_list.append('listing')
#
#         if 'agency' in initial_data:
#             key_type_list.append('agency')
#
#         if 'peer' in initial_data:
#             key_type_list.append('peer')
#
#         if len(key_type_list) >= 2:
#             raise serializers.ValidationError('Notifications can only be one type. Input: {0}'.format(key_type_list))
#
#         if 'message' not in validated_data and self.context['request'].method == 'POST':
#             raise serializers.ValidationError('Messsage field is required for POST Request')
#
#         # TODO: Figure how to get listing data using validated data
#         listing = initial_data.get('listing')
#         if listing:
#             if listing.get('id'):
#                 try:
#                     validated_data['listing'] = listing_model_access.get_listing_by_id(
#                         username, initial_data['listing']['id'], True)
#                 except ObjectDoesNotExist:
#                     raise serializers.ValidationError('Could not find listing')
#             else:
#                 raise serializers.ValidationError('Valid Listing ID is required')
#         else:
#             validated_data['listing'] = None
#
#         # Agency Validation
#         agency = initial_data.get('agency')
#         if agency:
#             if agency.get('id'):
#                 try:
#                     validated_data['agency'] = agency_model_access.get_agency_by_id(
#                         initial_data['agency']['id'], True)
#                 except ObjectDoesNotExist:
#                     raise serializers.ValidationError('Could not find agency')
#             else:
#                 raise serializers.ValidationError('Valid Agency ID is required')
#         else:
#             validated_data['agency'] = None
#
#         # Peer Validation
#         peer = initial_data.get('peer')
#         if peer:
#             temp_peer = {}
#
#             if peer.get('user'):
#                 temp_peer['user'] = peer.get('user')
#
#             if peer.get('folder_name'):
#                 temp_peer['folder_name'] = peer.get('folder_name')
#
#             target_username = temp_peer.get('user', {}).get('username')
#
#             if not target_username:
#                 raise serializers.ValidationError('Valid Username is Required')
#
#             target_username_profile = generic_model_access.get_profile(target_username)
#
#             if not target_username_profile:
#                 raise serializers.ValidationError('Valid User is Required')
#
#             # Folder Validation - Optional Field
#             temp_folder_name = temp_peer.get('folder_name')
#             if temp_folder_name:
#                 library_query = library_model_access.get_self_application_library(username, folder_name=temp_folder_name)
#                 temp_peer['_bookmark_listing_ids'] = [library_query_entry.listing.id for library_query_entry in library_query]
#
#                 # temp_peer['_user_folders'] = library_serializers.UserLibrarySerializer(library_query,
#                 #      many=True, context={'request': self.context['request']}).data
#
#                 if len(temp_peer['_bookmark_listing_ids']) == 0:
#                     raise serializers.ValidationError('No entries in target folder')
#
#             validated_data['peer'] = temp_peer
#         else:
#             validated_data['peer'] = None
#
#         return validated_data
#
#     def create(self, validated_data):
#         """
#         Used to create notifications
#         """
#         raise Exception('Not implement')
#         if validated_data['error']:
#             raise serializers.ValidationError('{0}'.format(validated_data['error']))
#
#         username = self.context['request'].user.username
#         notification = model_access.create_notification(username,
#                                                         validated_data['expires_date'],
#                                                         validated_data['message'],
#                                                         validated_data['listing'],
#                                                         validated_data['agency'],
#                                                         validated_data['peer'])
#         return notification
#
#     def update(self, instance, validated_data):
#         """
#         This is only used to update the expired_date field (effectively
#         deleting a notification while still leaving a record of it)
#         """
#         raise Exception('Not implement')
#
#         if validated_data['error']:
#             raise serializers.ValidationError('{0}'.format(validated_data['error']))
#
#         username = self.context['request'].user.username
#         notification = model_access.update_notification(username,
#                                                         instance,
#                                                         validated_data['expires_date'])
#         return notification
