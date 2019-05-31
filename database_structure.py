from sqlalchemy import Column, ForeignKey, Integer, String, create_engine, \
    DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True)
    items = relationship('Item', back_populates='category')

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
    title = Column(String(255), unique=True)
    description = Column(String(768))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category, back_populates="items")
    added_at = Column(DateTime(timezone=True), server_default=func.now())

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
