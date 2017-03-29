"""
Recommendation Engine Runner

settings.py/or this file?
-----
recommendation_engines = ['ElasticsearchUserBaseRecommender', 'ElasticsearchContentBaseRecommender', 'CrabUserBaseRecommender']
----

os.getenv('RECOMMENDATION_ENGINE')


************************************WARNING************************************
Running this script will delete existing Recommendations in database
************************************WARNING************************************
"""
import logging
import sys
import os

sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), '../../')))

from ozpcenter.recommend.recommend import RecommenderDirectory

RECOMMENDATION_ENGINE = os.getenv('RECOMMENDATION_ENGINE', 'custom')

# Get an instance of a logger
logger = logging.getLogger('ozp-center.' + str(__name__))


def run():
    """
    Run the Recommendation Engine
    """
    logger.info('RECOMMENDATION_ENGINE: {}'.format(RECOMMENDATION_ENGINE))

    recommender_wrapper_obj = RecommenderDirectory()
    recommender_wrapper_obj.recommend(RECOMMENDATION_ENGINE)