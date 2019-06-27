from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from database_structure import Base, Item, Category, User, decode_url_spaces

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = scoped_session(DBSession)


# Items --------------------------------------------------------------------- #
def get_item_by_title(item_title):
    """Gets item from the database with the given title.

    Args:
        item_title: Item title.

    Returns:
        Item object.
    """
    return session.query(Item) \
        .filter_by(title=item_title) \
        .first()


def get_item_by_title_url(item_title_url):
    """Gets item from the database with the given title url.

    Args:
        item_title_url: Item title as url.

    Returns:
        Item object.
    """
    item_title = decode_url_spaces(item_title_url)
    return get_item_by_title(item_title)


def create_item(item):
    """Creates item in the database with the given item object

    Args:
        item: Item.
    """
    session.add(item)
    session.commit()


def delete_item(item):
    """Deletes item from the database with the given item object

    Args:
        item: Item.
    """
    session.delete(item)
    session.commit()


# Categories ---------------------------------------------------------------- #
def get_categories():
    """Gets all categories from the database.

    Returns:
        List of category objects.
    """
    return session.query(Category).all()


def get_category_by_name(category_name):
    """Gets category from the database with the given name.

    Args:
        category_name: Category name.

    Returns:
        Category object.
    """
    return session.query(Category) \
        .filter_by(name=category_name) \
        .first()


def get_category_by_name_url(category_name_url):
    """Gets category from the database with the given name url.

    Args:
        category_name_url: Category name url.

    Returns:
        Category object.
    """
    category_name = decode_url_spaces(category_name_url)
    return get_category_by_name(category_name)


# Users --------------------------------------------------------------------- #
def get_user_by_id(id):
    """Gets user from the database with the given id.

    Args:
        id: User id.

    Returns:
        User object.
    """
    return session.query(User) \
        .filter_by(id=id) \
        .first()


def get_user_by_email(email):
    """Gets user from the database with the email.

    Args:
        email: Email address.

    Returns:
        User object.
    """
    return session.query(User) \
        .filter_by(email=email.lower()) \
        .first()


def create_user(email, first_name, last_name, password):
    """Creates new user in the database with the given parameters

    Args:
        email: Email address.
        first_name: First name.
        last_name: Last name.
        password: Password

    Returns:
        User object or None when the given parameters are invalid
    """
    user = User(email=email.lower(), first_name=first_name,
                last_name=last_name)

    if password:
        user.hash_password(password)

    if not user.is_valid():
        return

    session.add(user)
    session.commit()
    return user
