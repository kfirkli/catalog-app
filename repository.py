from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from database_structure import Base, Item, Category, User, decode_url_spaces

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = scoped_session(DBSession)


# Items --------------------------------------------------------------------- #
def get_item_by_title(item_title):
    return session.query(Item) \
        .filter_by(title=item_title) \
        .first()


def get_item_by_title_url(item_title_url):
    item_title = decode_url_spaces(item_title_url)
    return get_item_by_title(item_title)


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


def get_category_by_name_url(category_name_url):
    category_name = decode_url_spaces(category_name_url)
    return get_category_by_name(category_name)


# Users --------------------------------------------------------------------- #
def get_user_by_id(id):
    return session.query(User) \
        .filter_by(id=id) \
        .first()


def get_user_by_email(email):
    return session.query(User) \
        .filter_by(email=email.lower()) \
        .first()


def create_user(email, first_name, last_name, password):
    if get_user_by_email(email):
        # User with this email already exists
        return None

    user = User(email=email.lower(), first_name=first_name,
                last_name=last_name)
    user.hash_password(password)

    session.add(user)
    session.commit()
    return user
