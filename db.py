from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey, Date, Text
from sqlalchemy.orm import relationship
from datetime import date


Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), unique=True, nullable=False)
    picture = Column(String(250))


class AssetType(Base):
    __tablename__ = 'assettype'
    assettype = Column(String(250), primary_key=True, nullable=False)
    creatorid = Column(Integer, ForeignKey(User.id))
    username = Column(String(250), nullable=False)
    creator = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'asset type': self.assettype,
            'Creator ID': self.creatorid,
            'Username': self.username,
        }


class Asset(Base):
    __tablename__ = 'assets'

    id = Column(Integer, primary_key=True)
    asset_number = Column(String(250), unique=True, nullable=False)
    asset_type = Column(String(250), nullable=False)
    asset_name = Column(String(250), nullable=False)
    purchase_date = Column(Date, nullable=False)
    cost = Column(Integer, nullable=False)
    managed_by = relationship(User)
    managed_userid = Column(Integer, ForeignKey(User.id), nullable=False)
    username = Column(String(250), nullable=False)
    description = Column(Text, nullable=True)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'asset number': self.asset_number,
            'asset type': self.asset_type,
            'asset name': self.asset_name,
            'purchase date': str(self.purchase_date),
            'cost': self.cost,
            'managed by': self.managed_by.name,
            'managed userid': self.managed_userid,
            'username': self.username,
            'description': self.description,
        }


engine = create_engine('sqlite:///fixedasset.db')
Base.metadata.create_all(engine)






