from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship

from back.database import Base, engine


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    items = relationship("ItemModel", back_populates="owner")


class ItemModel(Base):
    __tablename__ = 'items'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    calories = Column(Float)
    date = Column(DateTime)
    owner_id = Column(Integer, ForeignKey('users.id'))

    owner = relationship("User", back_populates="items")


User.metadata.create_all(bind=engine)