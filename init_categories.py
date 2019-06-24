from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_structure import Category, Base

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

session.add(Category(name='Cameras'))
session.add(Category(name='Lenses'))
session.add(Category(name='Flashes'))

session.commit()
print 'Categories successfully added'
