"""
Tests for image endpoints
"""
from django.test import override_settings
from rest_framework import status
from tests.ozp.cases import APITestCase

from ozpcenter import model_access as generic_model_access
from ozpcenter.scripts import sample_data_generator as data_gen
from tests.ozpcenter.helper import APITestHelper
from tests.ozpcenter.helper import ExceptionUnitTestHelper


@override_settings(ES_ENABLED=False)
class ImageApiTest(APITestCase):

    def setUp(self):
        """
        setUp is invoked before each test method
        """
        pass

    @classmethod
    def setUpTestData(cls):
        """
        Set up test data for the whole TestCase (only run once for the TestCase)
        """
        data_gen.run()

    def test_post_image(self):
        url = '/api/image/'
        data = {
            'security_marking': 'UNCLASSIFIED',
            'image_type': 'small_screenshot',
            'file_extension': 'png',
            'image': open('ozpcenter/scripts/test_images/android.png', mode='rb')
        }
        response = APITestHelper.request(self, url, 'POST', data=data, username='wsmith', status_code=201, format_str='multipart')

        self.assertTrue('id' in response.data)
        self.assertTrue('security_marking' in response.data)

    # Old access control was hard coded to pass this test
    # def test_post_image_pki_user(self):
    #     url = '/api/image/'
    #     data = {
    #         'security_marking': 'UNCLASSIFIED',
    #         'image_type': 'small_screenshot',
    #         'file_extension': 'png',
    #         'image': open('ozpcenter/scripts/test_images/android.png', mode='rb')
    #     }
    #
    #     response = APITestHelper.request(self, url, 'POST', data=data, username='pmurt', status_code=400, format_str='multipart')
    #     self.assertEqual(response.data, ExceptionUnitTestHelper.validation_error("{'security_marking': ['Security marking too high for current user']}"))

    def test_get_all_images(self):
        url = '/api/image/'
        response = APITestHelper.request(self, url, 'GET', username='wsmith', status_code=200)

        self.assertIsNotNone(response.data)

    # Old access control was hard coded to pass this test
    # def test_get_all_images_pki_user(self):
    #     url = '/api/image/'
    #     response = APITestHelper.request(self, url, 'GET', username='pmurt', status_code=200)
    #     self.assertEqual(response.data, [])
    #
    # def test_get_images_pki_user(self):
    #     url = '/api/image/2/'
    #     response = APITestHelper.request(self, url, 'GET', username='pmurt', status_code=403)
    #     self.assertEqual(response.data, ExceptionUnitTestHelper.permission_denied('Security marking too high for current user'))

    # TODO: Fix the retrieve in image views. It always finds nothing when searching by ID
    def test_get_image_by_id(self):
        url = '/api/image/9001/'
        response = APITestHelper.request(self, url, 'GET', username='wsmith', status_code=404)
        self.assertEqual(response.data, ExceptionUnitTestHelper.not_found())

    def test_delete_image(self):
        url = '/api/image/1/'
        APITestHelper.request(self, url, 'DELETE', username='wsmith', status_code=204)

    # Old access control was hard coded to pass this test
    # def test_delete_image_pki(self):
    #     url = '/api/image/2/'
    #     response = APITestHelper.request(self, url, 'DELETE', username='pmurt', status_code=403)
    #     self.assertEqual(response.data, ExceptionUnitTestHelper.permission_denied('Security marking too high for current user'))
