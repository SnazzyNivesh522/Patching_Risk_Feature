from pymongo import AsyncMongoClient
from config import Config


def get_session():
     
    try:
        return AsyncMongoClient(Config.MONGO_CONN_STR)
        
    except Exception as e:
        raise Exception(e)
