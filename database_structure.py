import re

from flask_login import UserMixin
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine, \
    DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base, UserMixin):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    email = Column(String(320), unique=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    password = Column(String(64))

    def is_valid(self):
        return not (
            not self.email
            or not self.first_name
            or not self.last_name
        )

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    items = relationship('Item', back_populates='category')

    def name_url(self):
        return encode_url_spaces(self.name)

    def is_valid(self):
        return not (not self.name)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'items': [item.serialize for item in self.items]
        }


class Item(Base):
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
        return encode_url_spaces(self.title)

    def is_valid(self):
        return not (
            not self.title
            or not self.description
            or (not self.category_id and not self.category)
            or (not self.user_id and not self.user)
        )

    @property
    def serialize(self):
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
    """
    Add one more dash to existing sequence of dashes
    (Save on the dashes during the decoding),
    and replace spaces with one dash.
    """
    return dash_nondash_matcher.sub(r'-\g<0>', title) \
        .replace(' ', '-')


def decode_url_spaces(url_title):
    """
    Replace single dashes with space and remove sequence of dashes.
    """
    title = nondash_dash_nondash_matcher.sub(r'\g<1> \g<2>', url_title)
    return dash_nondash_matcher.sub(r'\g<1>', title)
