import os
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base


# These env variables are the same ones used for the DB container
user = 'postgres'
pwd = 'postgres'
db = 'test_db'
host = 'db' # docker-compose creates a hostname alias with the service name
port = '5432' # default postgres port 
engine = create_engine('postgres://%s:%s@%s:%s/%s' % (user, pwd, host, port, db)) 


Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_db()
    import models
    Base.metadata.create_all(bind=engine)
