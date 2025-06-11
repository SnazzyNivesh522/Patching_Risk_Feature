from config import Config
from motor.motor_asyncio import AsyncIOMotorClient


def get_session():

    try:
        return AsyncIOMotorClient(Config.MONGO_CONN_STR)

    except Exception as e:
        raise Exception(e)
