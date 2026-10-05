from fastapi.staticfiles import StaticFiles
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from database import engine, Base, SessionLocal
import models
from schemas import (
    UserCreate,
    UserLogin,
    QuestionPaperCreate,
    SyllabusCreate,
    ForgotPasswordRequest,
    ResetPasswordRequest
)
from pwdlib import PasswordHash
import os
import secrets
from datetime import datetime, timedelta

app = FastAPI(title="Question Paper Management System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

password_hash = PasswordHash.recommended()
Base.metadata.create_all(bind=engine)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


# DATABASE
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# HOME
@app.get("/")
def home():
    return FileResponse(FRONTEND_DIR / "index.html")


# REGISTER
@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_username = db.query(models.User).filter(
        models.User.username == user.username
    ).first()

    if existing_username:
        raise HTTPException(status_code=400, detail="Username already exists")

    existing_email = db.query(models.User).filter(
        models.User.email == user.email
    ).first()

    if existing_email:
        raise HTTPException(status_code=400, detail="Email already exists")

    new_user = models.User(
        name=user.name,
        username=user.username,
        email=user.email,
        password=password_hash.hash(user.password),
        user_type=user.user_type
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "Account created successfully",
        "user_id": new_user.id,
        "username": new_user.username,
        "user_type": new_user.user_type
    }


# LOGIN
@app.post("/login")
def login_user(user: UserLogin, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(
        models.User.username == user.username
    ).first()

    if not existing_user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not password_hash.verify(user.password, existing_user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return {
        "message": "Login successful",
        "user_id": existing_user.id,
        "username": existing_user.username,
        "user_type": existing_user.user_type
    }


# USERS
@app.get("/users")
def get_users(db: Session = Depends(get_db)):
    users = db.query(models.User).all()

    return [
        {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "email": user.email,
            "user_type": user.user_type
        }
        for user in users
    ]


# DELETE USER
@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()

    return {"message": "User deleted successfully", "user_id": user_id}


# FORGOT PASSWORD
@app.post("/forgot-password")
def forgot_password(
    request: ForgotPasswordRequest,
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(
        models.User.email == request.email
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="Email address not found")

    old_tokens = db.query(models.PasswordResetToken).filter(
        models.PasswordResetToken.user_id == user.id
    ).all()

    for old_token in old_tokens:
        db.delete(old_token)

    token = secrets.token_urlsafe(32)
    expiry_time = datetime.now() + timedelta(minutes=15)

    reset_token = models.PasswordResetToken(
        user_id=user.id,
        token=token,
        expires_at=expiry_time,
        used=False
    )

    db.add(reset_token)
    db.commit()

    reset_link = "reset_password.html?token=" + token

    return {
        "message": "Password reset link generated successfully.",
        "reset_link": reset_link
    }


# RESET PASSWORD
@app.post("/reset-password")
def reset_password(
    request: ResetPasswordRequest,
    db: Session = Depends(get_db)
):
    reset_token = db.query(models.PasswordResetToken).filter(
        models.PasswordResetToken.token == request.token
    ).first()

    if not reset_token:
        raise HTTPException(status_code=400, detail="Invalid reset link")

    if reset_token.used:
        raise HTTPException(
            status_code=400,
            detail="This reset link has already been used"
        )

    if datetime.now() > reset_token.expires_at:
        raise HTTPException(status_code=400, detail="This reset link has expired")

    user = db.query(models.User).filter(
        models.User.id == reset_token.user_id
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password = password_hash.hash(request.new_password)
    reset_token.used = True
    db.commit()

    return {"message": "Password reset successfully"}


# CREATE QUESTION PAPER
@app.post("/question-papers")
def create_question_paper(
    paper: QuestionPaperCreate,
    db: Session = Depends(get_db)
):
    new_paper = models.QuestionPaper(
        department=paper.department,
        level=paper.level,
        semester=paper.semester,
        subject=paper.subject,
        paper_type=paper.paper_type,
        year=paper.year,
        file_name=paper.file_name,
        file_path=paper.file_path,
        exam_date=paper.exam_date,
        upload_date=paper.upload_date
    )

    db.add(new_paper)
    db.commit()
    db.refresh(new_paper)

    return {
        "message": "Question paper added successfully",
        "paper_id": new_paper.id
    }


# GET QUESTION PAPERS
@app.get("/question-papers")
def get_question_papers(
    department: str | None = None,
    level: str | None = None,
    semester: int | None = None,
    subject: str | None = None,
    paper_type: str | None = None,
    year: int | None = None,
    db: Session = Depends(get_db)
):
    query = db.query(models.QuestionPaper)

    if department:
        query = query.filter(models.QuestionPaper.department == department)
    if level:
        query = query.filter(models.QuestionPaper.level == level)
    if semester:
        query = query.filter(models.QuestionPaper.semester == semester)
    if subject:
        query = query.filter(models.QuestionPaper.subject == subject)
    if paper_type:
        query = query.filter(models.QuestionPaper.paper_type == paper_type)
    if year:
        query = query.filter(models.QuestionPaper.year == year)

    return query.all()


# UPCOMING QUESTION PAPERS
@app.get("/question-papers/upcoming")
def get_upcoming_question_papers(db: Session = Depends(get_db)):
    current_time = datetime.now()

    papers = db.query(models.QuestionPaper).filter(
        models.QuestionPaper.exam_date != None,
        models.QuestionPaper.exam_date > current_time
    ).order_by(models.QuestionPaper.exam_date.asc()).all()

    return papers


# UPLOAD QUESTION PAPER
@app.post("/upload-question-paper")
async def upload_question_paper(
    department: str = Form(...),
    level: str = Form(...),
    semester: int = Form(...),
    subject: str = Form(...),
    paper_type: str = Form(...),
    year: int = Form(...),
    exam_date: datetime | None = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")

    upload_folder = "uploads"
    os.makedirs(upload_folder, exist_ok=True)

    safe_filename = os.path.basename(file.filename)
    file_path = os.path.join(upload_folder, safe_filename)

    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    new_paper = models.QuestionPaper(
        department=department,
        level=level,
        semester=semester,
        subject=subject,
        paper_type=paper_type,
        year=year,
        file_name=safe_filename,
        file_path=file_path,
        exam_date=exam_date,
        upload_date=datetime.now()
    )

    db.add(new_paper)
    db.commit()
    db.refresh(new_paper)

    return {
        "message": "Question paper uploaded successfully",
        "paper_id": new_paper.id,
        "file_name": safe_filename,
        "exam_date": exam_date
    }


# UPDATE QUESTION PAPER
@app.put("/question-papers/{paper_id}")
async def update_question_paper(
    paper_id: int,
    department: str = Form(...),
    level: str = Form(...),
    semester: int = Form(...),
    subject: str = Form(...),
    paper_type: str = Form(...),
    year: int = Form(...),
    exam_date: datetime | None = Form(None),
    file: UploadFile | None = File(None),
    db: Session = Depends(get_db)
):
    paper = db.query(models.QuestionPaper).filter(
        models.QuestionPaper.id == paper_id
    ).first()

    if not paper:
        raise HTTPException(status_code=404, detail="Question paper not found")

    paper.department = department
    paper.level = level
    paper.semester = semester
    paper.subject = subject
    paper.paper_type = paper_type
    paper.year = year
    paper.exam_date = exam_date

    if file is not None:
        if file.content_type != "application/pdf":
            raise HTTPException(
                status_code=400,
                detail="Only PDF files are allowed"
            )

        upload_folder = "uploads"
        os.makedirs(upload_folder, exist_ok=True)

        safe_filename = os.path.basename(file.filename)
        new_file_path = os.path.join(upload_folder, safe_filename)

        with open(new_file_path, "wb") as buffer:
            buffer.write(await file.read())

        if (
            paper.file_path
            and os.path.exists(paper.file_path)
            and paper.file_path != new_file_path
        ):
            os.remove(paper.file_path)

        paper.file_name = safe_filename
        paper.file_path = new_file_path

    db.commit()
    db.refresh(paper)

    return {
        "message": "Question paper updated successfully",
        "paper_id": paper.id,
        "file_name": paper.file_name,
        "exam_date": paper.exam_date
    }


# CHECK PAPER ACCESS
def check_paper_access(paper):
    if paper.exam_date is not None:
        current_time = datetime.now()

        if paper.exam_date > current_time:
            raise HTTPException(
                status_code=403,
                detail="Question paper is locked until the exam date"
            )


# DOWNLOAD QUESTION PAPER
@app.get("/question-papers/{paper_id}/download")
def download_question_paper(
    paper_id: int,
    db: Session = Depends(get_db)
):
    paper = db.query(models.QuestionPaper).filter(
        models.QuestionPaper.id == paper_id
    ).first()

    if not paper:
        raise HTTPException(status_code=404, detail="Question paper not found")

    check_paper_access(paper)

    if not paper.file_path or not os.path.exists(paper.file_path):
        raise HTTPException(
            status_code=404,
            detail="Question paper file not found"
        )

    return FileResponse(
        path=paper.file_path,
        filename=paper.file_name,
        media_type="application/pdf"
    )


# VIEW QUESTION PAPER
@app.get("/question-papers/{paper_id}/view")
def view_question_paper(
    paper_id: int,
    db: Session = Depends(get_db)
):
    paper = db.query(models.QuestionPaper).filter(
        models.QuestionPaper.id == paper_id
    ).first()

    if not paper:
        raise HTTPException(status_code=404, detail="Question paper not found")

    check_paper_access(paper)

    if not paper.file_path or not os.path.exists(paper.file_path):
        raise HTTPException(
            status_code=404,
            detail="Question paper file not found"
        )

    return FileResponse(
        path=paper.file_path,
        media_type="application/pdf",
        content_disposition_type="inline"
    )


# DELETE QUESTION PAPER
@app.delete("/question-papers/{paper_id}")
def delete_question_paper(
    paper_id: int,
    db: Session = Depends(get_db)
):
    paper = db.query(models.QuestionPaper).filter(
        models.QuestionPaper.id == paper_id
    ).first()

    if not paper:
        raise HTTPException(status_code=404, detail="Question paper not found")

    if paper.file_path and os.path.exists(paper.file_path):
        os.remove(paper.file_path)

    db.delete(paper)
    db.commit()

    return {
        "message": "Question paper deleted successfully",
        "paper_id": paper_id
    }


# CREATE SYLLABUS
@app.post("/syllabus")
def create_syllabus(
    syllabus: SyllabusCreate,
    db: Session = Depends(get_db)
):
    new_syllabus = models.Syllabus(
        department=syllabus.department,
        level=syllabus.level,
        semester=syllabus.semester,
        subject=syllabus.subject,
        year=syllabus.year,
        file_name=syllabus.file_name,
        file_path=syllabus.file_path,
        upload_date=syllabus.upload_date
    )

    db.add(new_syllabus)
    db.commit()
    db.refresh(new_syllabus)

    return {
        "message": "Syllabus added successfully",
        "syllabus_id": new_syllabus.id
    }


# GET SYLLABUS
@app.get("/syllabus")
def get_syllabus(
    department: str | None = None,
    level: str | None = None,
    semester: int | None = None,
    subject: str | None = None,
    year: int | None = None,
    db: Session = Depends(get_db)
):
    query = db.query(models.Syllabus)

    if department:
        query = query.filter(models.Syllabus.department == department)
    if level:
        query = query.filter(models.Syllabus.level == level)
    if semester:
        query = query.filter(models.Syllabus.semester == semester)
    if subject:
        query = query.filter(models.Syllabus.subject == subject)
    if year:
        query = query.filter(models.Syllabus.year == year)

    return query.order_by(models.Syllabus.upload_date.desc()).all()


# UPLOAD SYLLABUS
@app.post("/upload-syllabus")
async def upload_syllabus(
    department: str = Form(...),
    level: str = Form(...),
    semester: int = Form(...),
    subject: str = Form(...),
    year: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")

    upload_folder = "uploads"
    os.makedirs(upload_folder, exist_ok=True)

    safe_filename = os.path.basename(file.filename)
    file_path = os.path.join(upload_folder, safe_filename)

    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    new_syllabus = models.Syllabus(
        department=department,
        level=level,
        semester=semester,
        subject=subject,
        year=year,
        file_name=safe_filename,
        file_path=file_path,
        upload_date=datetime.now()
    )

    db.add(new_syllabus)
    db.commit()
    db.refresh(new_syllabus)

    return {
        "message": "Syllabus uploaded successfully",
        "syllabus_id": new_syllabus.id,
        "file_name": safe_filename
    }


# DOWNLOAD SYLLABUS
@app.get("/syllabus/{syllabus_id}/download")
def download_syllabus(
    syllabus_id: int,
    db: Session = Depends(get_db)
):
    syllabus = db.query(models.Syllabus).filter(
        models.Syllabus.id == syllabus_id
    ).first()

    if not syllabus:
        raise HTTPException(status_code=404, detail="Syllabus not found")

    if not syllabus.file_path or not os.path.exists(syllabus.file_path):
        raise HTTPException(status_code=404, detail="Syllabus file not found")

    return FileResponse(
        path=syllabus.file_path,
        filename=syllabus.file_name,
        media_type="application/pdf"
    )


# VIEW SYLLABUS
@app.get("/syllabus/{syllabus_id}/view")
def view_syllabus(
    syllabus_id: int,
    db: Session = Depends(get_db)
):
    syllabus = db.query(models.Syllabus).filter(
        models.Syllabus.id == syllabus_id
    ).first()

    if not syllabus:
        raise HTTPException(status_code=404, detail="Syllabus not found")

    if not syllabus.file_path or not os.path.exists(syllabus.file_path):
        raise HTTPException(status_code=404, detail="Syllabus file not found")

    return FileResponse(
        path=syllabus.file_path,
        media_type="application/pdf",
        content_disposition_type="inline"
    )


# DELETE SYLLABUS
@app.delete("/syllabus/{syllabus_id}")
def delete_syllabus(
    syllabus_id: int,
    db: Session = Depends(get_db)
):
    syllabus = db.query(models.Syllabus).filter(
        models.Syllabus.id == syllabus_id
    ).first()

    if not syllabus:
        raise HTTPException(status_code=404, detail="Syllabus not found")

    if syllabus.file_path and os.path.exists(syllabus.file_path):
        os.remove(syllabus.file_path)

    db.delete(syllabus)
    db.commit()

    return {
        "message": "Syllabus deleted successfully",
        "syllabus_id": syllabus_id
    }


# ADD DEPARTMENT
@app.post("/departments")
def add_department(
    name: str = Form(...),
    db: Session = Depends(get_db)
):
    name = name.strip()

    if not name:
        raise HTTPException(status_code=400, detail="Department name is required")

    existing = db.query(models.Department).filter(
        models.Department.name == name
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="Department already exists")

    department = models.Department(name=name)
    db.add(department)
    db.commit()
    db.refresh(department)

    return {
        "message": "Department added successfully",
        "department_id": department.id,
        "name": department.name
    }


# GET DEPARTMENTS
@app.get("/departments")
def get_departments(db: Session = Depends(get_db)):
    return db.query(models.Department).order_by(
        models.Department.name.asc()
    ).all()


# DELETE DEPARTMENT
@app.delete("/departments/{department_id}")
def delete_department(
    department_id: int,
    db: Session = Depends(get_db)
):
    department = db.query(models.Department).filter(
        models.Department.id == department_id
    ).first()

    if not department:
        raise HTTPException(status_code=404, detail="Department not found")

    db.delete(department)
    db.commit()

    return {"message": "Department deleted successfully"}


# KEEP THIS AT THE VERY BOTTOM
app.mount(
    "/",
    StaticFiles(directory=FRONTEND_DIR, html=True),
    name="frontend"
)