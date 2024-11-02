import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    Request,
)

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from models import TokenTable

from utils import JWT_SECRET_KEY, ALGORITHM

def decodeJWT(jwttoken: str):
    try:
        payload = jwt.decode(jwttoken, JWT_SECRET_KEY, ALGORITHM)
        return payload
    except InvalidTokenError:
        return None
    

class JWTBearer(HTTPBearer):
    def __init__(self, auto_error, bool=True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid Authentication Scheme")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid Token or Expired Token")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid Authorization Code")
    
    def verify_jwt(self, jwttoken: str) -> bool:
        istokenvalid: bool = False
        try:
            payload = decodeJWT(jwttoken)
        except:
            payload = None
        if payload:
            istokenvalid=True
        return istokenvalid
    

jwt_bearer = JWTBearer()
