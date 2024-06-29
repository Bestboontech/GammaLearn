from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from typing import List
from motor.motor_asyncio import AsyncIOMotorClient
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client.gamma_learn

class User(BaseModel):
    fullName: str
    email: str
    password: str

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None

class Comment(BaseModel):
    subjectId: str
    text: str

class Material(BaseModel):
    subjectId: str
    title: str
    content: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = await db.users.find_one({"email": token_data.email})
    if user is None:
        raise credentials_exception
    return user

@app.post("/signup", response_model=User)
async def create_user(user: User):
    user_in_db = await db.users.find_one({"email": user.email})
    if user_in_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = {**user.dict(), "password": hashed_password}
    await db.users.insert_one(new_user)
    return new_user

@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"email": form_data.username})
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/forgot-password")
async def forgot_password(email: str):
    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=400, detail="User with this email does not exist")
    reset_token = create_access_token(data={"sub": user['email']}, expires_delta=timedelta(hours=1))
    await send_reset_email(email, reset_token)
    return {"msg": "Password reset link sent"}

@app.post("/reset-password/{token}")
async def reset_password(token: str, new_password: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        user = await db.users.find_one({"email": email})
        if user is None:
            raise HTTPException(status_code=400, detail="User not found")
        hashed_password = get_password_hash(new_password)
        await db.users.update_one({"email": email}, {"$set": {"password": hashed_password}})
        return {"msg": "Password reset successfully"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

@app.post("/comments")
async def post_comment(comment: Comment, current_user: User = Depends(get_current_user)):
    await db.comments.insert_one(comment.dict())
    return {"msg": "Comment added successfully"}

@app.get("/comments/{subjectId}", response_model=List[Comment])
async def get_comments(subjectId: str):
    comments = await db.comments.find({"subjectId": subjectId}).to_list(None)
    return comments

@app.post("/materials")
async def post_material(material: Material, current_user: User = Depends(get_current_user)):
    await db.materials.insert_one(material.dict())
    return {"msg": "Material added successfully"}

@app.get("/materials/{subjectId}", response_model=List[Material])
async def get_materials(subjectId: str):
    materials = await db.materials.find({"subjectId": subjectId}).to_list(None)
    return materials

async def send_reset_email(email: str, token: str):
    sender_email = "youremail@example.com"
    receiver_email = email
    password = os.getenv("EMAIL_PASSWORD")

    message = MIMEMultipart("alternative")
    message["Subject"] = "Password Reset Request"
    message["From"] = sender_email
    message["To"] = receiver_email

    text = f"Hi,\n\nPlease use the following link to reset your password:\nhttp://localhost:3000/reset-password/{token}\n\nThanks!"
    html = f"""\
    <html>
    <body>
        <p>Hi,<br><br>
        Please use the following link to reset your password:<br>
        <a href="http://localhost:3000/reset-password/{token}">Reset Password</a><br><br>
        Thanks!
        </p>
    </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    message.attach(part1)
    message.attach(part2)

    context = smtplib.ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )
