from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
from datetime import datetime, timedelta
from enum import Enum
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import jwt as pyjwt

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security settings
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Role Enum
class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"

# Database Models
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    full_name = Column(String)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)
    is_active = Column(Boolean, default=True)

class NoteDB(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    content = Column(String)
    owner = Column(String)
    is_private = Column(Boolean, default=True)

class LogDB(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    username = Column(String)
    endpoint = Column(String)
    method = Column(String)
    status_code = Column(Integer)

Base.metadata.create_all(bind=engine)

# Pydantic Models
class User(BaseModel):
    username: str
    full_name: str
    email: str
    hashed_password: str
    role: Role
    is_active: bool

class UserCreate(BaseModel):
    username: str
    full_name: str
    email: str
    password: str
    role: Role

class UserUpdateRole(BaseModel):
    role: Role

class NoteCreate(BaseModel):
    title: str
    content: str
    is_private: bool

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    is_private: Optional[bool] = None

class Note(BaseModel):
    id: int
    title: str
    content: str
    owner: str
    is_private: bool

class Log(BaseModel):
    id: int
    timestamp: datetime
    username: Optional[str]
    endpoint: str
    method: str
    status_code: int

# Utilities
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = pyjwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        return user
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except pyjwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

# Logging Function
def log_activity(request: Request, response_status: int, db: Session, username: Optional[str] = None):
    log_entry = LogDB(
        username=username,
        endpoint=request.url.path,
        method=request.method,
        status_code=response_status
    )
    db.add(log_entry)
    db.commit()

app = FastAPI(title="Notes API", version="1.0.0",servers=[{"url": "http://localhost:8000","description": "Local server"}])

# Add CORS middleware to allow frontend requests
origins = [
    "http://localhost:8080",  # Adjust as needed for deployment environment
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    username = None
    token = request.headers.get("authorization")
    if token:
        token = token.replace("Bearer ", "")
        try:
            payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
        except pyjwt.InvalidTokenError:
            pass
    db = SessionLocal()
    log_activity(request, response.status_code, db, username)
    db.close()
    return response

@app.post("/register", response_model=User)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.username == user.username).first():
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_password = get_password_hash(user.password)
    new_user = UserDB(
        username=user.username,
        full_name=user.full_name,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role.value
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/notes", response_model=Note)
def create_note(note: NoteCreate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    new_note = NoteDB(
        title=note.title,
        content=note.content,
        owner=current_user.username,
        is_private=note.is_private
    )
    db.add(new_note)
    db.commit()
    db.refresh(new_note)
    return new_note

@app.get("/notes", response_model=List[Note])
def get_notes(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    notes = db.query(NoteDB).all()
    result = [
        note for note in notes
        if not note.is_private or note.owner == current_user.username or current_user.role == Role.ADMIN.value
    ]
    return result

@app.delete("/notes/{note_id}", response_model=Note)
def delete_note(note_id: int, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    note = db.query(NoteDB).filter(NoteDB.id == note_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    if note.owner != current_user.username and current_user.role != Role.ADMIN.value:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    db.delete(note)
    db.commit()
    return note

@app.put("/notes/{note_id}", response_model=Note)
def update_note(note_id: int, note_update: NoteUpdate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    note = db.query(NoteDB).filter(NoteDB.id == note_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    if note.owner != current_user.username and current_user.role != Role.ADMIN.value:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    update_data = note_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(note, key, value)
    db.commit()
    db.refresh(note)
    return note

@app.post("/users", response_model=User)
def create_new_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.username == user.username).first():
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_password = get_password_hash(user.password)
    new_user = UserDB(
        username=user.username,
        full_name=user.full_name,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role.value
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.get("/logs", response_model=List[Log])
def get_logs(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != Role.ADMIN.value:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    logs = db.query(LogDB).all()
    return logs

@app.put("/users/{user_name}/deactivate", response_model=User)
def deactivate_user(user_name, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != Role.ADMIN.value:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    user = db.query(UserDB).filter(UserDB.username == user_name).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    db.commit()
    db.refresh(user)
    return user

@app.put("/users/{user_name}/reset_password", response_model=User)
def reset_password(user_name, new_password: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != Role.ADMIN.value:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    user = db.query(UserDB).filter(UserDB.username == user_name).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = get_password_hash(new_password)
    db.commit()
    db.refresh(user)
    return user

@app.put("/users/{user_name}/update_role", response_model=User)
def update_user_role(user_name, user_update_role: UserUpdateRole, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != Role.ADMIN.value:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    user = db.query(UserDB).filter(UserDB.username == user_name).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = user_update_role.role.value
    db.commit()
    db.refresh(user)
    return user

@app.get("/users", response_model=List[User])
def get_all_users(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != Role.ADMIN.value:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    users = db.query(UserDB).all()
    return users

@app.delete("/users/{user_name}", response_model=User)
def delete_user(user_name, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != Role.ADMIN.value:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    user = db.query(UserDB).filter(UserDB.username == user_name).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return user
