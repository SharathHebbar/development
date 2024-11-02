import schemas
import models
import jwt
from datetime import datetime
from models import User, TokenTable
from database import Base, engine, SessionLocal
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from auth_bearer import JWTBearer
from functools import wraps
from sqlalchemy.orm import Session
from utils import  JWT_SECRET_KEY, ALGORITHM

from utils import (
    create_access_token,
    create_refresh_token,
    verify_password,
    get_hashed_password
)

Base.metadata.create_all(engine)

def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

app = FastAPI()

@app.post("/register")
def register_user(
    user: schemas.UserCreate,
    session: Session=Depends(get_session)
):
    existing_user = session.query(models.User).filter_by(email=user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email Already Registered")
    
    encrypted_password = get_hashed_password(user.password)

    new_user = models.User(username=user.username, email=user.email, password=encrypted_password)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return {"message": "User Created Successfully"}



@app.post('/login', response_model=schemas.TokenSchema)
def login(request: schemas.requestdetails, db:Session=Depends(get_session)):
    user = db.query(User).filter(User.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect Email")
    hashed_pass = user.password

    if not verify_password(request.password, hashed_pass):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect Password")
    
    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)

    token_db = models.TokenTable(user_id=user.id, access_token=access, refresh_token=refresh, status=True)
    db.add(token_db)
    db.commit()
    db.refresh(token_db)
    return {
        "access_token": access,
        "refresh_token": refresh
    }


@app.get('/getusers')
def getusers(dependencies=Depends(JWTBearer()), session: Session=Depends(get_session)):
    user = session.query(models.User).all()
    return user


@app.post('/change-password')
def change_password(request: schemas.changepassword, db: Session=Depends(get_session)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")
    
    if not verify_password(request.old_password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Password")
    
    encrypted_password = get_hashed_password(request.new_password)
    user.password = encrypted_password

    db.commit()
    return {"message": "password changed successfully"}


@app.post('/logout')
def logout(dependencies=Depends(JWTBearer()), db: Session=Depends(get_session)):
    token = dependencies
    payload = jwt.decode(token, JWT_SECRET_KEY, ALGORITHM)
    user_id = payload['sub']
    token_record = db.query(models.TokenTable).all()
    info = []
    for record in token_record:
        print("Record: ", record)

        if (datetime.utcnow() - record.created_date).days > 1:
            info.append(record.user_id)
    
    if info:
        exisiting_token = db.query(models.TokenTable).where(TokenTable.user_id.in_(info)).delete()
        db.commit()

    exisiting_token = db.query(models.TokenTable).filter(models.TokenTable.user_id == user_id, models.TokenTable.access_token == token).first()
    if exisiting_token:
        exisiting_token.status=False
        db.add(exisiting_token)
        db.commit()
        db.refresh(exisiting_token)

    return {"message": "Logout Successfully"}


def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        payload = jwt.decode(kwargs['dependencies'], JWT_SECRET_KEY, ALGORITHM)
        user_id = payload['sub']
        data = kwargs['session'].query(models.TokenTable).filter_by(
            user_id=user_id,
            access_token=kwargs['dependencies'],
            status=True
        ).first()

        if data:
            return func(kwargs['dependencies'], kwargs['session'])
        return {'msg': "Token Blocked."}
    return wrapper