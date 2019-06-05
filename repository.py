from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from database_structure import Base, Item, Category

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = scoped_session(DBSession)


# Items --------------------------------------------------------------------- #
def get_item_by_title(item_title):
    return session.query(Item) \
        .filter_by(title=item_title) \
        .first()


def create_item(item):
    session.add(item)
    session.commit()


def delete_item(item):
    session.delete(item)
    session.commit()


# Categories ---------------------------------------------------------------- #
def get_categories():
    return session.query(Category).all()


def get_category_by_name(category_name):
    return session.query(Category) \
        .filter_by(name=category_name) \
        .first()
