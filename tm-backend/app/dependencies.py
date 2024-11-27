from datetime import datetime
from . import config
from .database import SessionLocal
from typing import Optional
from fastapi import Header, HTTPException, status, Depends
from jose import JWTError, jwt
from pydantic import ValidationError

from passlib.context import CryptContext

from sqlalchemy.orm import Session
from app.core.models import users
from .config import settings

from fastapi.security import OAuth2PasswordBearer

# 添加OAuth2方案
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/users/token")

# 使用的算法是Bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password):
    """
    哈希来自用户的密码
    :param password: 原密码
    :return: 哈希后的密码
    """
    return pwd_context.hash(password)
# 哈希后的密码
# $2b$12$sErK932BEaLyIisz30PubepN7w91RLwkISWbAFYgUgoIqh8goJLEW

def verify_password(plain_password, hashed_password):
    """
    校验接收的密码是否与存储的哈希值匹配
    :param plain_password: 原密码
    :param hashed_password: 哈希后的密码
    :return: 返回值为bool类型，校验成功返回True,反之False
    """
    return pwd_context.verify(plain_password, hashed_password)

async def check_jwt_token(token: str = Depends(oauth2_scheme),db: Session = Depends(get_db)):
    """
    验证token
    :param token: 从 OAuth2 授权中获取的 token
    :param db: 数据库会话
    :return: 返回用户信息
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=settings.ALGORITHM)
        id: str = payload.get("sub")
        # 得到令牌过期时间
        expiration_timestamp = payload.get("exp")
        # 把令牌过期时间转化为人类可读时间信息
        # expiration_time = datetime.fromtimestamp(expiration_timestamp)
        # print(expiration_time)
        # 通过解析得到的username,获取用户信息,并返回
        # return users_db.get(username)
        return db.query(users.Users).filter(users.Users.id== int(id)).first()
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                'code': 5000,
                'message': "Token Error",
                'data': "Token Error",
            }
        )
    
