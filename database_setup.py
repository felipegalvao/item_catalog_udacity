from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy import func

Base = declarative_base()

# User class, with name and email fields
class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable = False)
    email = Column(String(250), nullable = False)

# Category class, with a slug field to build the links
class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable = False)
    slug = Column(String(250), nullable = False, unique=True)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'slug'         : self.slug,
       }

# Catalog item class, with slug field and relationship with users and categories
class CatalogItem(Base):
    __tablename__ = 'catalog_item'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable = False)
    description = Column(String(500), nullable = False)
    slug = Column(String(250), nullable = False, unique=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'description'  : self.description,
           'id'           : self.id,
           'slug'         : self.slug,
           'category'     : self.category.name,
           'created_at'   : self.created_at,
       }

engine = create_engine('sqlite:///itemlist.db')

Base.metadata.create_all(engine)
