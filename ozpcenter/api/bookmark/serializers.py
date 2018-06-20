"""
Bookmark Serializers

http://127.0.0.1:8001/api/bookmark/
"""
import logging

from rest_framework import serializers

import ozpcenter.api.bookmark.model_access as model_access

import ozpcenter.models as models

from ozpcenter.api.bookmark import model_access

import ozpcenter.api.listing.model_access as listing_model_access
import ozpcenter.api.image.serializers as image_serializers
import ozpcenter.api.listing.serializers as listing_serializers

from ozpcenter.pipe import pipes
from ozpcenter.pipe import pipeline
from ozpcenter.recommend import recommend_utils

logger = logging.getLogger('ozp-center.' + str(__name__))


class LibraryListingSerializer(serializers.HyperlinkedModelSerializer):
    small_icon = image_serializers.ImageSerializer(required=False)
    large_icon = image_serializers.ImageSerializer(required=False)
    banner_icon = image_serializers.ImageSerializer(required=False)
    owners = listing_serializers.CreateListingProfileSerializer(required=False, allow_null=True, many=True)

    class Meta:
        model = models.Listing
        fields = ('id', 'title', 'unique_name', 'launch_url', 'small_icon',
            'large_icon', 'banner_icon', 'owners', 'security_marking')
        read_only_fields = ('title', 'unique_name', 'launch_url', 'small_icon',
            'large_icon', 'banner_icon', 'owners', 'security_marking')
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


class BookmarkPermissionSerializer(serializers.ModelSerializer):
    """
    Serializer for api/bookmark/{bookmark_id}/permission - owner is always current user
    """
    profile = listing_serializers.CreateListingProfileSerializer(required=False, allow_null=True, many=False)
    # bookmark = BookmarkSerializer(many=False, required=False)

    class Meta:
        model = models.BookmarkPermission
        fields = ('id', 'profile', 'created_date', 'modified_date', 'user_type',
            # 'bookmark'
        )
        # read_only_fields = ('listing', 'bookmark_parent', 'type', 'created_date', 'modified_date', 'title')

        extra_kwargs = {
            "id": {
                "read_only": False,
                "required": False,
            },
        }


class BookmarkParentSerializer(serializers.ModelSerializer):
    """
    Serializer for /api/bookmark - owner is always current user
    """
    # bookmark_permission = BookmarkPermissionSerializer(many=True, required=False)

    class Meta:
        model = models.BookmarkEntry
        fields = (
            'title', 'id', 'type'  # , 'bookmark_permission'
        )
        read_only_fields = ('listing', 'bookmark_parent', 'type', 'created_date', 'modified_date', 'title')

        extra_kwargs = {
            "id": {
                "read_only": False,
                "required": False,
            },
        }


class DictField(serializers.ReadOnlyField):
    """
    Read Only Field
    """

    def from_native(self, obj):
        return None


class BookmarkSerializer(serializers.ModelSerializer):
    """
    Serializer for /api/bookmark - owner is always current user
    """
    listing = LibraryListingSerializer(required=False)
    bookmark_parent = BookmarkParentSerializer(many=True, required=False)
    bookmark_permission_self = serializers.SerializerMethodField('get_bookmark_permission')

    def get_bookmark_permission(self, container):
        request_profile = self.context['request'].user.profile

        if container.type == 'FOLDER':
            profile_bookmark_permission = container.bookmark_permission.filter(profile=request_profile)
            # profile_bookmark_permission = models.BookmarkPermission.objects.filter(profile=request_profile, bookmark=container).first()
            # print(profile_bookmark_permission)
            # container = BookmarkEntry(40, bookmark_parent,title:InstrumentSharing,type:FOLDER,is_root:False,listing:None)
            return BookmarkPermissionSerializer(profile_bookmark_permission.first(), context={'request': self.context['request']}).data
        else:
            return {}

    class Meta:
        model = models.BookmarkEntry
        fields = (
            'listing', 'bookmark_parent',
            # 'bookmark_permission',  # TODO: Figure out how to do custom queryset for this field, should only show
            'bookmark_permission_self',
            'id', 'type', 'created_date', 'modified_date', 'title'
        )

        extra_kwargs = {
            "listing": {
                "read_only": False,
                "required": False,
            },
            "title": {
                "read_only": False,
                "required": False,
            },
            # Type is a Required Field
            "type": {
                "read_only": False,
                "required": True,
            },
        }

    def to_representation(self, data):
        ret = super(BookmarkSerializer, self).to_representation(data)

        # import pprint
        # print(pprint.pprint(ret))
        # if bookmark_parent length is more than or equal to two, it means that folder is shared between users
        if len(ret['bookmark_parent']) >= 2:
            ret['is_shared'] = True
        else:
            ret['is_shared'] = False

        del ret['bookmark_parent']

        if ret['type'] == models.BookmarkEntry.LISTING:
            del ret['title']  # listing type does not have titles
            del ret['bookmark_permission_self']  # listing type does not have titles
        elif ret['type'] == models.BookmarkEntry.FOLDER:
            del ret['listing']  # folder type does not have listings

        return ret

    def validate(self, data):
        """
        validate
        """
        request_profile = self.context['request'].user.profile
        username = self.context['request'].user.username

        if 'type' not in data:
            raise serializers.ValidationError('No type provided')

        type = data['type']

        if type == models.BookmarkEntry.LISTING:
            listing = listing_model_access.get_listing_by_id(username,
                data['listing']['id'])

            if not listing:
                raise serializers.ValidationError('Listing id entry not found')

            data['listing_object'] = listing
        elif type == models.BookmarkEntry.FOLDER:
            if 'title' not in data:
                raise serializers.ValidationError('No title provided')
        else:
            raise serializers.ValidationError('No valid type provided')

        if 'bookmark_parent' in data:
            if len(data['bookmark_parent']) > 1:
                raise serializers.ValidationError('No valid bookmark_parent')
            bookmark_parent_id = data['bookmark_parent'][0]['id']
            data['bookmark_parent_object'] = model_access.get_bookmark_entry_by_id(request_profile, bookmark_parent_id)

            if data['bookmark_parent_object'].type != 'FOLDER':
                raise serializers.ValidationError('bookmark_parent entry must be FOLDER')

        return data

    def create(self, validated_data):
        username = self.context['request'].user.username
        request_profile = self.context['request'].user.profile
        type = validated_data['type']

        bookmark_parent_object = validated_data.get('bookmark_parent_object')

        if type == models.BookmarkEntry.LISTING:
            return model_access.create_listing_bookmark_for_profile(request_profile, validated_data['listing_object'], bookmark_parent_object)

        elif type == models.BookmarkEntry.FOLDER:
            title = validated_data['title']
            return model_access.create_folder_bookmark_for_profile(request_profile, title, bookmark_parent_object)


def _create_folder_listing_queries_and_serialized(request_profile, request, folder_bookmark_entry, is_parent=None, ordering_fields=None):
    """
    Create queries to get folder and listing data
    """
    is_parent = is_parent if is_parent else False
    ordering_fields = ordering_fields if ordering_fields else ['created_date']

    folder_query = models.BookmarkEntry.objects.filter(
        type=models.BookmarkEntry.FOLDER,
        bookmark_parent__bookmark_permission__profile=request_profile  # Validate to make sure user can see folder
    )

    # for_profile should do `private listing` check for listing
    listing_query = models.BookmarkEntry.objects.for_profile_minus_security_marking(request_profile).filter(
        type=models.BookmarkEntry.LISTING,
        bookmark_parent__bookmark_permission__profile=request_profile  # Validate to make sure user can see folder,
    )

    for ordering_field in ordering_fields:
        if ordering_field in model_access.FOLDER_QUERY_ORDER_MAPPING:
            folder_query = folder_query.order_by(model_access.FOLDER_QUERY_ORDER_MAPPING[ordering_field])

        if ordering_field in model_access.LISTING_QUERY_ORDER_MAPPING:
            listing_query = listing_query.order_by(model_access.LISTING_QUERY_ORDER_MAPPING[ordering_field])

    if is_parent:
        folder_query = folder_query.filter(id=folder_bookmark_entry.id)
        listing_query = listing_query.filter(id=folder_bookmark_entry.id)
    else:
        folder_query = folder_query.filter(bookmark_parent=folder_bookmark_entry)
        listing_query = listing_query.filter(bookmark_parent=folder_bookmark_entry)

    folder_data = BookmarkSerializer(folder_query, many=True, context={'request': request}).data
    listing_data = BookmarkSerializer(listing_query, many=True, context={'request': request}).data

    # Filter out all listings that request_profile does not have access to
    listing_data_after_filter = pipeline.Pipeline(recommend_utils.ListIterator(listing_data),
                                    [pipes.BookmarkListingDictPostSecurityMarkingCheckPipe(request_profile.user.username)]).to_list()

    return {"folder_data": folder_data,
            "listing_data_after_filter": listing_data_after_filter}


# TODO: Combine get_bookmark_tree and _get_nested_bookmarks_tree to reduce code duplication
def get_bookmark_tree(request_profile, request, folder_bookmark_entry=None, is_parent=None, ordering_fields=None):
    """
    Helper Function to get all nested bookmark

    Args:
        request_profile
        request
        folder_bookmark_entry
        is_parent
    """
    folder_bookmark_entry = folder_bookmark_entry if folder_bookmark_entry else model_access.create_get_user_root_bookmark_folder(request_profile)
    is_parent = is_parent if is_parent is not None else False

    bookmarks_dict = _create_folder_listing_queries_and_serialized(
        request_profile, request, folder_bookmark_entry, is_parent, ordering_fields=ordering_fields)

    return {"folders": _get_nested_bookmarks_tree(request_profile, bookmarks_dict['folder_data'], request=request, ordering_fields=ordering_fields),
            "listings": bookmarks_dict['listing_data_after_filter']}


def _get_nested_bookmarks_tree(request_profile, data, serialized=False, request=None, ordering_fields=None):
    """
    Recursive function to get all the nested folder and listings
    """
    output = []
    for current_record in data:
        if current_record.get('type') == 'FOLDER':
            bookmarks_dict = _create_folder_listing_queries_and_serialized(
                request_profile, request, current_record['id'], ordering_fields=ordering_fields)

            current_record['children'] = {
                "folders": _get_nested_bookmarks_tree(request_profile, bookmarks_dict['folder_data'], request=request, ordering_fields=ordering_fields),
                "listings": bookmarks_dict['listing_data_after_filter']
            }

        output.append(current_record)
    return output
