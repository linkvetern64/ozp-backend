"""
Recommendations Engine
===============
Business Objective:
To recommend applications to users that they might find useful in their everyday objectives

Website Link: https://github.com/aml-development/ozp-documentation/wiki/Recommender-%282017%29

Data that could be used for recommendations
- Listing Bookmarked
- Keep track of folder apps

Recommendations are based on individual users

Assumptions:
    30,000 Users
    300 Listings

Steps:
    - Load Data for each users
    - Process Data with recommendation algorthim
      - Produces a list of listing's id for each profile = Results
    - Iterate through the Results to call add_listing_to_user_profile function
"""
import logging


from django.core.exceptions import ObjectDoesNotExist
from ozpcenter import models
from django.db.models import Count
from ozpcenter.api.listing.model_access_es import check_elasticsearch

from ozpcenter.api.listing import model_access_es

from ozpcenter.recommend import utils


# Get an instance of a logger
logger = logging.getLogger('ozp-center.' + str(__name__))

# Create ES client
es_client = model_access_es.es_client


class Recommender(object):
    """
    This class is to behave like a superclass for recommendation engine

    recommender_result_set: Dictionary with profile id, nested listing id with score pairs
        {
            profile_id#1: {
                listing_id#1: score#1,
                listing_id#2: score#2
            },
            profile_id#2: {
                listing_id#1: score#1,
                listing_id#2: score#2,
                listing_id#3: score#3,
            }
        }
    """
    def __init__(self):
        # Set up variables for processing data
        self.recommender_result_set = {}
        self.initiate()

    def initiate(self):
        """
        This method is used for the subclasses
        It is used for initiating variables, classes, objects, connecting to service
        """
        raise NotImplementedError()

    def recommendation_logic(self):
        """
        This method is used for the subclasses.
        It is used for put the recommendation logic
        """
        raise NotImplementedError()

    def merge(self):
        """
        Purpose is to merge all of the different Recommender's algorthim recommender result together.
        This function is responsible for merging the results of the other Recommender recommender_result_set diction into self recommender_result_set

        Self recommender_result_set
        {
            profile_id#1: {
                listing_id#1: score#1,
                listing_id#2: score#2
            },
            profile_id#2: {
                listing_id#1: score#1,
                listing_id#2: score#2,
                listing_id#3: score#3,
            }
        }

        Other recommender_result_set:
        {
            profile_id#3: {
                listing_id#1: score#1,
                listing_id#2: score#2
            },
            profile_id#1: {
                listing_id#5: score#1,
            }
        }

        Merged recommender_result_set
        {
            profile_id#1: {
                listing_id#1: score#1,
                listing_id#2: score#2,
                listing_id#5: score#1,
            },
            profile_id#2: {
                listing_id#1: score#1,
                listing_id#2: score#2,
                listing_id#3: score#3,
            },
            profile_id#3: {
                listing_id#1: score#1,
                listing_id#2: score#2
            },
        }

        When there is a conflict in the profile/listing/score, average the two scores together
        TODO Implement Code
        """
        pass

    def add_listing_to_user_profile(self, profile_id, listing_id, score, cumulative=False):
        """
        Add listing and score to user profile
        """
        if profile_id in self.recommender_result_set:
            if self.recommender_result_set[profile_id].get(listing_id):
                if cumulative:
                    self.recommender_result_set[profile_id][listing_id] = self.recommender_result_set[profile_id][listing_id] + float(score)
                else:
                    self.recommender_result_set[profile_id][listing_id] = float(score)
            else:
                self.recommender_result_set[profile_id][listing_id] = float(score)
        else:
            self.recommender_result_set[profile_id] = {}
            self.recommender_result_set[profile_id][listing_id] = float(score)

    def recommend(self):
        """
        Execute recommendation logic
        """
        self.recommendation_logic()
        print(self.recommender_result_set)
        self.save_to_db()

    def save_to_db(self):
        """
        This function is responsible for storing the recommendations into the database
        """
        for profile_id in self.recommender_result_set:

            profile = None
            try:
                profile = models.Profile.objects.get(pk=profile_id)
            except ObjectDoesNotExist:
                profile = None

            if profile:
                # Clear Recommendations Entries before putting new ones.
                models.RecommendationsEntry.objects.filter(target_profile=profile).delete()

                listing_ids = self.recommender_result_set[profile_id]

                for current_listing_id in listing_ids:
                    score = listing_ids[current_listing_id]
                    current_listing = None
                    try:
                        current_listing = models.Listing.objects.get(pk=current_listing_id)
                    except ObjectDoesNotExist:
                        current_listing = None

                    if current_listing:
                        recommendations_entry = models.RecommendationsEntry(
                            target_profile=profile,
                            listing=current_listing,
                            score=score)
                        recommendations_entry.save()


class SampleDataRecommender(Recommender):
    """
    Sample Data Recommender
    """
    def initiate(self):
        """
        Initiate any variables needed for recommendation_logic function
        """
        pass

    def recommendation_logic(self):
        """
        Sample Recommendations for all users
        """
        all_profiles = models.Profile.objects.all()
        for profile in all_profiles:
            # Assign Recommendations
            # Get Listings this user can see
            current_listings = None
            try:
                current_listings = models.Listing.objects.for_user(profile.user.username)[:10]
            except ObjectDoesNotExist:
                current_listings = None

            if current_listings:
                for current_listing in current_listings:
                    self.add_listing_to_user_profile(profile.id, current_listing.id, 1.0)


class CustomHybridRecommender(Recommender):
    """
    Custom Hybrid Recommender

    Assumptions:
    - Listing has ratings and possible not to have ratings
    - Listing can be featured
    - User bookmark Listings
    - User have bookmark folder, a collection of listing in a folder.
    - Listing has total_reviews field

    Requirements:
    - Recommendations should be explainable and believable
    - Must respect private apps
    - Does not have to repectborative filtering)
    """
    def initiate(self):
        """
        Initiate any variables needed for recommendation_logic function
        """
        pass

    def recommendation_logic(self):
        """
        Sample Recommendations for all users
        """
        all_profiles = models.Profile.objects.all()

        for profile in all_profiles:
            profile_id = profile.id
            profile_username = profile.user.username
            # Get Featured Listings
            featured_listings = models.Listing.objects.for_user_organization_minus_security_markings(
                profile_username).order_by('-approved_date').filter(
                    is_featured=True,
                    approval_status=models.Listing.APPROVED,
                    is_enabled=True,
                    is_deleted=False)[:36]

            for current_listing in featured_listings:
                self.add_listing_to_user_profile(profile_id, current_listing.id, 3.0, True)

            # Get Recent Listings
            recent_listings = models.Listing.objects.for_user_organization_minus_security_markings(
                profile_username).order_by(
                    '-approved_date').filter(
                        is_featured=False,
                        approval_status=models.Listing.APPROVED,
                        is_enabled=True,
                        is_deleted=False)[:36]

            for current_listing in recent_listings:
                self.add_listing_to_user_profile(profile_id, current_listing.id, 2.0, True)

            # Get most popular listings via a weighted average
            most_popular_listings = models.Listing.objects.for_user_organization_minus_security_markings(
                profile_username).filter(
                    approval_status=models.Listing.APPROVED,
                    is_enabled=True,
                    is_deleted=False).order_by('-avg_rate', '-total_reviews')[:36]

            for current_listing in most_popular_listings:
                if current_listing.avg_rate != 0:
                    self.add_listing_to_user_profile(profile_id, current_listing.id, current_listing.avg_rate, True)

            # Get most popular bookmarked apps for all users
            library_entries = models.ApplicationLibraryEntry.objects.for_user_organization_minus_security_markings(profile_username)
            # library_entries = library_entries.filter(owner__user__username=username)
            library_entries = library_entries.filter(listing__is_enabled=True)
            library_entries = library_entries.filter(listing__is_deleted=False)
            library_entries = library_entries.filter(listing__approval_status=models.Listing.APPROVED)
            library_entries_group_by_count = library_entries.values('listing_id').annotate(count=Count('listing_id')).order_by('count')
            # [{'listing_id': 1, 'count': 1}, {'listing_id': 2, 'count': 1}]

            old_min = 1
            old_max = 1
            new_min = 2
            new_max = 5

            for entry in library_entries_group_by_count:
                count = entry['count']
                if count == 0:
                    continue
                if count > old_max:
                    old_max = count
                if count < old_min:
                    old_min = count

            for entry in library_entries_group_by_count:
                listing_id = entry['listing_id']
                count = entry['count']

                calculation = utils.map_numbers(count, old_min, old_max, new_min, new_max)
                self.add_listing_to_user_profile(profile_id, listing_id, calculation, True)


class ElasticsearchContentBaseRecommender(Recommender):
    """
    Elasticsearch Content based recommendation engine
    """
    def initiate(self):
        """
        Initiate any variables needed for recommendation_logic function
        Make sure the Elasticsearch is up and running
        """
        check_elasticsearch()
        # TODO: Make sure the elasticsearch index is created here with the mappings

    def recommendation_logic(self):
        """
        Recommendation logic

        Template Code to make sure that Elasticsearch client is working
        This code should be replace by real algorthim
        """
        print('Elasticsearch Content Base Recommendation Engine')
        print('Elasticsearch Health : {}'.format(es_client.cluster.health()))


class ElasticsearchUserBaseRecommender(Recommender):
    """
    Elasticsearch User based recommendation engine
    """
    def initiate(self):
        """
        Initiate any variables needed for recommendation_logic function
        Make sure the Elasticsearch is up and running
        """
        check_elasticsearch()
        # TODO: Make sure the elasticsearch index is created here with the mappings

    def recommendation_logic(self):
        """
        Recommendation logic

        Template Code to make sure that Elasticsearch client is working
        This code should be replace by real algorthim
        """
        print('Elasticsearch User Base Recommendation Engine')
        print('Elasticsearch Health : {}'.format(es_client.cluster.health()))


class SurpriseUserBaseRecommender(Recommender):
    """
    Surprise Based Recommendation Engine

    http://surprise.readthedocs.io/en/latest/getting_started.html
    """
    def initiate(self):
        """
        Initiate any variables needed for recommendation_logic function
        """
        pass

    def recommendation_logic(self):
        """
        Recommendation logic
        """
        pass


class RecommenderDirectory(object):
    """
    Wrapper for all Recommenders
    It maps strings to classes.
    """
    def __init__(self):
        self.recommender_classes = {
            'surprise_user_base': SurpriseUserBaseRecommender,
            'elasticsearch_user_base': ElasticsearchUserBaseRecommender,
            'elasticsearch_content_base': ElasticsearchContentBaseRecommender,
            'sample_data': SampleDataRecommender,
            'custom': CustomHybridRecommender
        }

    def recommend(self, recommender_string):
        """
        Creates Recommender Object, and excute the recommend
        """
        if recommender_string not in self.recommender_classes:
            raise Exception('Recommender Engine Not Found')

        recommender_obj = self.recommender_classes[recommender_string]()
        recommender_obj.recommend()
