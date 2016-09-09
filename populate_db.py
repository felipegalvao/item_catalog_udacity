from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, User, CatalogItem

#Connect to Database and create database session
engine = create_engine('sqlite:///itemlist.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

user1 = User(name="Priscilla Bellafronte", email="pribellafronte@gmail.com")
session.add(user1)
session.commit()

category1 = Category(name="Football", slug="football")
session.add(category1)
session.commit()

category2 = Category(name="Basketball", slug="basketball")
session.add(category2)
session.commit()

category3 = Category(name="Tennis", slug="tennis")
session.add(category3)
session.commit()

category4 = Category(name="Surfing", slug="surfing")
session.add(category4)
session.commit()

category5 = Category(name="Skating", slug="skating")
session.add(category5)
session.commit()

category6 = Category(name="Kayaking", slug="kayaking")
session.add(category6)
session.commit()

category7 = Category(name="Rock Climbing", slug="rock-climbing")
session.add(category7)
session.commit()

category8 = Category(name="Table Tennis", slug="table-tennis")
session.add(category8)
session.commit()

item1 = CatalogItem(name="Tennis ball", description="Test description for Tennis Ball bla bla bla bla bla bla bla bla bla",
                    slug="tennis-ball", category_id=3, user_id=1)
session.add(item1)
session.commit()

item2 = CatalogItem(name="Climbing Glove", description="Test description for Climbing Glove bla bla bla bla bla bla bla bla bla",
                    slug="climbing-glove", category_id=7, user_id=1)
session.add(item2)
session.commit()

item3 = CatalogItem(name="Kayak",  description="Test description for Kayak bla bla bla bla bla bla bla bla bla",
                    slug="kayak", category_id=6, user_id=1)
session.add(item3)
session.commit()
