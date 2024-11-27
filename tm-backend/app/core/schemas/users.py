from typing import Optional
from pydantic import BaseModel, EmailStr

class UserBase(BaseModel):
    id: Optional[int] = False
    username: str = None
    # pip install pydantic[email] 使用email验证的时候需要增加这个库
    email: Optional[EmailStr] = None

    class Config:
        from_attributes = True

class TokenModel(UserBase):
    # 符合 OAuth2 规范的返回格式
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class LoginModel(BaseModel):
    phone: str = None
    password: str = None

    class Config:
        from_attributes = True

class CreateModel(UserBase):
    password: str
