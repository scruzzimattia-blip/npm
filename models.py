import os
from sqlalchemy import create_engine, Column, String, Integer, DateTime, BigInteger, Boolean, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DB_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/traefik_stats")

Base = declarative_base()

class AccessLog(Base):
    __tablename__ = 'access_logs'
    
    id = Column(Integer, primary_key=True)
    start_local = Column(DateTime, index=True)
    client_addr = Column(String, index=True)
    
    # Geo Data
    country_code = Column(String(5), index=True)
    city_name = Column(String(100))
    asn = Column(String(20), index=True)
    
    # Request Data
    request_method = Column(String(10))
    request_path = Column(String)
    request_host = Column(String, index=True)
    request_protocol = Column(String(10))
    request_referer = Column(String)
    request_user_agent = Column(String)
    
    # Bot Detection
    is_bot = Column(Boolean, default=False, index=True)
    browser_family = Column(String(50))
    os_family = Column(String(50))
    device_family = Column(String(50))

    # Traefik Data
    entry_point = Column(String(50))
    status_code = Column(Integer, index=True)
    duration = Column(BigInteger) # ns
    content_size = Column(BigInteger) # bytes
    
    __table_args__ = (
        UniqueConstraint('start_local', 'client_addr', 'request_path', 'request_method', name='_req_uc'),
    )

engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
