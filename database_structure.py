import re

from flask_login import UserMixin
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine, \
    DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base, UserMixin):
    """A class that represent a user in the database."""
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    email = Column(String(320), unique=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    password = Column(String(64))
    items = relationship('Item', cascade="all, delete-orphan")

    def is_valid(self):
        """Validate the user's attributes.

        Returning:
            True or False if the user is valid.
        """
        return not (
            not self.email
            or not self.first_name
            or not self.last_name
        )

    def hash_password(self, password):
        """Hash the given password and set it to the user.

        Args:
            password: Password.
        """
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        """Check whether the password is valid or not.

        Args:
            password: Password.

        Returning:
            True or False if the password is valid.
        """
        return pwd_context.verify(password, self.password)


class Category(Base):
    """A class that represent a category in the database."""
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    items = relationship('Item', back_populates='category',
                         cascade="all, delete-orphan")

    def name_url(self):
        """Encode the category name to url title.

        Returning:
            The category name encoded to url title.
        """
        return encode_url_spaces(self.name)

    def is_valid(self):
        """Validate the category's attributes.

        Returning:
            True or False if the category is valid.
        """
        return not (not self.name)

    @property
    def serialize(self):
        """Serialize the category to JSON.

        Returning:
            Category as JSON.
        """
        return {
            'id': self.id,
            'name': self.name,
            'items': [item.serialize for item in self.items]
        }


class Item(Base):
    """A class that represent an item in the database."""
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    title = Column(String(255), unique=True, nullable=False)
    description = Column(String(768), nullable=False)
    category_id = Column(Integer, ForeignKey('category.id'), nullable=False)
    category = relationship(Category, back_populates="items")
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    user = relationship(User)
    added_at = Column(DateTime(timezone=True), server_default=func.now())

    def title_url(self):
        """Encode the item title to url title.

        Returning:
            The item title encoded to url title.
        """
        return encode_url_spaces(self.title)

    def is_valid(self):
        """Validate the item's attributes.

        Returning:
            True or False if the item is valid.
        """
        return not (
            not self.title
            or not self.description
            or (not self.category_id and not self.category)
            or (not self.user_id and not self.user)
        )

    @property
    def serialize(self):
        """Serialize the item to JSON.

        Returning:
            Item as JSON.
        """
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category_id': self.category_id,
            'added_at': self.added_at
        }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)

# Helper functions ---------------------------------------------------------- #
dash_nondash_matcher = re.compile('-([^-])')
nondash_dash_nondash_matcher = re.compile('([^-])-([^-])')


def encode_url_spaces(title):
    """Replaces spaces with one dash.
    Adds one more dash to existing sequence of dashes (Save on the dashes
    during the decoding).

    Examples:
        'Canon EOS 5D Mark IV' -> 'Canon-EOS-5D-Mark-IV'

    Args:
        title: title of an item or any other string.
    """
    return dash_nondash_matcher.sub(r'-\g<0>', title) \
        .replace(' ', '-')


def decode_url_spaces(url_title):
    """
    Replace single dashes with space and remove sequence of dashes.

    Examples:
        'Canon-EOS-5D-Mark-IV' -> 'Canon EOS 5D Mark IV'

    Args:
        url_title: title as url of an item or any other string.
    """
    title = nondash_dash_nondash_matcher.sub(r'\g<1> \g<2>', url_title)
    return dash_nondash_matcher.sub(r'\g<1>', title)
