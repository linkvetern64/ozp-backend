"""
Serializers
"""
import logging

from rest_framework import serializers

import ozpcenter.models as models
import ozpcenter.api.access_control.serializers as access_control_serializers

# Get an instance of a logger
logger = logging.getLogger('ozp-center')

class ImageTypeSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.ImageType
        fields = ('name',)

class ImageSerializer(serializers.HyperlinkedModelSerializer):
    access_control = access_control_serializers.AccessControlSerializer()
    class Meta:
        model = models.Image
        fields = ('url', 'id', 'access_control')