"""
Library Serializers
"""
import logging

from rest_framework import serializers

from ozpcenter import models
from ozpcenter.api.library import model_access
import ozpcenter.api.listing.model_access as listing_model_access
import ozpcenter.api.image.serializers as image_serializers
import ozpcenter.api.listing.serializers as listing_serializers


logger = logging.getLogger('ozp-center.' + str(__name__))


class LibraryListingSerializer(serializers.HyperlinkedModelSerializer):
    small_icon = image_serializers.ImageSerializer(required=False)
    large_icon = image_serializers.ImageSerializer(required=False)
    banner_icon = image_serializers.ImageSerializer(required=False)
    owners = listing_serializers.CreateListingProfileSerializer(required=False, allow_null=True, many=True)

    class Meta:
        model = models.Listing
        fields = ('id', 'title', 'unique_name', 'launch_url', 'small_icon',
            'large_icon', 'banner_icon', 'owners')
        read_only_fields = ('title', 'unique_name', 'launch_url', 'small_icon',
            'large_icon', 'banner_icon', 'owners')
        # Any AutoFields on your model (which is what the automatically
        # generated id key is) are set to read-only by default when Django
        # REST Framework is creating fields in the background. read-only fields
        # will not be part of validated_data. Override that behavior using the
        # extra_kwargs
        extra_kwargs = {
            "id": {
                "read_only": False,
                "required": False,
            },
        }


class BookmarkParentSerializer(serializers.ModelSerializer):
    """
    Serializer for self/library - owner is always current user
    """
    class Meta:
        model = models.BookmarkEntry
        fields = ('title', 'id')


class DictField(serializers.ReadOnlyField):
    """
    Read Only Field
    """

    def from_native(self, obj):
        return None


class BookmarkSerializer(serializers.ModelSerializer):
    """
    Serializer for self/library - owner is always current user
    """
    listing = LibraryListingSerializer()
    bookmark_parent = BookmarkParentSerializer(many=True)

    class Meta:
        model = models.BookmarkEntry
        fields = ('listing', 'bookmark_parent', 'id', 'type', 'created_date', 'modified_date', 'title')

    # def validate(self, data):
    #     """
    #     Check for listing id
    #     - folder is optional
    #     - position is optional
    #     """
    #     if 'listing' not in data:
    #         raise serializers.ValidationError('No listing provided')
    #
    #     username = self.context['request'].user.username
    #     listing = listing_model_access.get_listing_by_id(username,
    #         data['listing']['id'])
    #
    #     if listing:
    #         if not listing.is_enabled:
    #             raise serializers.ValidationError('Can not bookmark apps that are disabled')
    #     else:
    #         raise serializers.ValidationError('Listing id entry not found')
    #
    #     if 'id' not in data['listing']:
    #         raise serializers.ValidationError('No listing id provided')
    #
    #     if 'folder' in data:
    #         if not data.get('folder'):
    #             data['folder'] = None
    #
    #     if 'position' in data:
    #         try:
    #             position_value = int(data['position'])
    #             data['position'] = position_value
    #         except ValueError:
    #             raise serializers.ValidationError('Position is not a integer')
    #
    #     return data
    #
    # def create(self, validated_data):
    #     username = self.context['request'].user.username
    #     listing_id = validated_data['listing']['id']
    #     folder_name = validated_data.get('folder')
    #     position = validated_data.get('position')
    #     return model_access.create_self_user_library_entry(username, listing_id, folder_name, position)
