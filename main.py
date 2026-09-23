from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
import sqlite3
import json
import os
import re
import uuid

# ============================================================
# AI RECRUITMENT PLATFORM - SINGLE FILE VERSION
# ============================================================
# Run:
#   pip install fastapi uvicorn python-jose[cryptography] passlib[bcrypt] python-multipart
#   uvicorn main:app --reload
#
# Swagger:
#   http://127.0.0.1:8000/docs
#
# This version keeps the whole assignment in one file for easy
# demonstration. SQLite is used locally so PostgreSQL setup is
# not required for the demo.
# ============================================================

app = FastAPI(
    title="AI Recruitment Platform",
    version="1.0.0",
    description="Five-module AI Recruitment Platform with deterministic matching gate."
)

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key-for-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

DB_FILE = "recruitment.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ============================================================
# DATABASE
# ============================================================

def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS candidate_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        name TEXT,
        location TEXT,
        resume_file TEXT,
        resume_text TEXT,
        structured_profile TEXT,
        confirmed_profile TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS employer_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        company_name TEXT,
        company_info TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employer_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        min_experience REAL DEFAULT 0,
        max_experience REAL DEFAULT 99,
        raw_input TEXT,
        blueprint TEXT,
        syllabus TEXT,
        final_jd TEXT,
        questions TEXT,
        status TEXT DEFAULT 'DRAFT',
        version INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        candidate_id INTEGER NOT NULL,
        job_id INTEGER NOT NULL,
        job_version INTEGER NOT NULL,
        status TEXT DEFAULT 'APPLIED',
        created_at TEXT NOT NULL,
        UNIQUE(candidate_id, job_id, job_version)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS match_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        application_id INTEGER UNIQUE NOT NULL,
        criterion_results TEXT,
        score REAL,
        eligible INTEGER,
        missing_criteria TEXT,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS interview_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        application_id INTEGER UNIQUE NOT NULL,
        status TEXT DEFAULT 'CREATED',
        current_index INTEGER DEFAULT 0,
        started_at TEXT,
        completed_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS interview_answers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        question TEXT NOT NULL,
        answer TEXT NOT NULL,
        evaluation TEXT,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        details TEXT,
        created_at TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


init_db()


# ============================================================
# HELPERS
# ============================================================

def now():
    return datetime.utcnow().isoformat()


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str):
    return pwd_context.verify(password, password_hash)


def create_token(user_id: int, role: str):
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE id=? AND is_active=1",
        (user_id,)
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return dict(user)


def require_role(role: str):
    def checker(user=Depends(get_current_user)):
        if user["role"] != role:
            raise HTTPException(
                status_code=403,
                detail=f"{role} role required"
            )
        return user
    return checker


def audit(user_id: Optional[int], action: str, details: str = ""):
    conn = db()
    conn.execute(
        "INSERT INTO audit_logs(user_id, action, details, created_at) VALUES (?, ?, ?, ?)",
        (user_id, action, details, now())
    )
    conn.commit()
    conn.close()


def get_job_owned(job_id: int, user_id: int):
    conn = db()
    job = conn.execute(
        "SELECT * FROM jobs WHERE id=? AND employer_id=?",
        (job_id, user_id)
    ).fetchone()
    conn.close()

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Job not found or not owned by current employer"
        )
    return dict(job)


def get_candidate_profile(user_id: int):
    conn = db()
    profile = conn.execute(
        "SELECT * FROM candidate_profiles WHERE user_id=?",
        (user_id,)
    ).fetchone()
    conn.close()

    if not profile:
        raise HTTPException(
            status_code=404,
            detail="Candidate profile not found. Upload a resume first."
        )
    return dict(profile)


def safe_json(value, default=None):
    if value is None or value == "":
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


# ============================================================
# AI WRAPPER
# ============================================================
# Provider-agnostic interface required by the assignment.
# For this single-file local demo, deterministic extraction and
# generation are used so the application works without an API key.
#
# The interface can later be replaced by Gemini/Ollama/OpenAI
# without changing the recruitment business logic.
# ============================================================

class LLMWrapper:

    def generate_text(self, task_name: str, variables: Dict[str, Any]) -> str:
        if task_name == "jd_generation":
            title = variables.get("title", "Software Engineer")
            blueprint = variables.get("blueprint", {})
            syllabus = variables.get("syllabus", [])

            skills = blueprint.get("required_skills", [])
            skills_text = ", ".join(skills)

            topics = ", ".join(
                item.get("topic", "")
                for item in syllabus
            )

            return (
                f"We are looking for a {title}. "
                f"The candidate will work on practical software development, "
                f"problem solving and project delivery. "
                f"Required skills include {skills_text}. "
                f"The role expects knowledge of {topics}. "
                f"Candidates should demonstrate relevant experience and "
                f"evidence through their resume and interview."
            )

        return "Generated content"


    def generate_structured(
        self,
        task_name: str,
        variables: Dict[str, Any]
    ) -> Dict[str, Any]:

        if task_name == "resume_profile_extraction":
            text = variables.get("resume_text", "")
            return extract_candidate_profile(text)

        if task_name == "job_blueprint_generation":
            return generate_job_blueprint(
                variables.get("title", ""),
                variables.get("requirements", ""),
                variables.get("min_experience", 0),
                variables.get("max_experience", 99)
            )

        if task_name == "syllabus_generation":
            return generate_syllabus(
                variables.get("blueprint", {})
            )

        if task_name == "question_generation":
            return generate_questions(
                variables.get("syllabus", [])
            )

        if task_name == "answer_evaluation":
            return evaluate_answer(
                variables.get("question", ""),
                variables.get("answer", "")
            )

        raise ValueError(f"Unknown AI task: {task_name}")


    def health_check(self):
        return {
            "provider": "local-demo-wrapper",
            "status": "healthy",
            "mode": "deterministic demo"
        }


llm = LLMWrapper()


# ============================================================
# SIMPLE DOCUMENT PARSER
# ============================================================

def extract_text_from_bytes(filename: str, content: bytes):
    """
    Basic parser for local demo.
    PDF/DOCX extraction is attempted when libraries are installed.
    Plain text is also supported for easy Swagger testing.
    """

    extension = filename.lower().split(".")[-1]

    if extension == "txt":
        return content.decode("utf-8", errors="ignore")

    if extension == "pdf":
        try:
            import fitz
            document = fitz.open(stream=content, filetype="pdf")
            text = "\n".join(page.get_text() for page in document)
            document.close()
            return text
        except Exception:
            return content.decode("utf-8", errors="ignore")

    if extension == "docx":
        try:
            from docx import Document
            import io

            document = Document(io.BytesIO(content))
            return "\n".join(
                paragraph.text
                for paragraph in document.paragraphs
            )
        except Exception:
            return content.decode("utf-8", errors="ignore")

    return content.decode("utf-8", errors="ignore")


# ============================================================
# LOCAL AI-LIKE EXTRACTION
# ============================================================

KNOWN_SKILLS = [
    "python", "fastapi", "sql", "postgresql", "mysql",
    "machine learning", "deep learning", "rag", "llm",
    "openai", "gemini", "ollama", "langchain",
    "git", "github", "docker", "pandas", "numpy",
    "scikit-learn", "tensorflow", "pytorch", "java",
    "javascript", "react", "html", "css", "rest api",
    "api", "power bi", "excel", "sas", "statistics",
    "data analysis", "data science", "nlp"
]


def extract_candidate_profile(text: str):
    lower = text.lower()

    found_skills = []
    for skill in KNOWN_SKILLS:
        if skill in lower:
            found_skills.append(skill)

    experience = 0.0

    experience_patterns = [
        r"(\d+(?:\.\d+)?)\s*\+?\s*years?\s*(?:of)?\s*(?:experience|exp)",
        r"experience\s*[:\-]?\s*(\d+(?:\.\d+)?)\s*years?"
    ]

    for pattern in experience_patterns:
        match = re.search(pattern, lower)
        if match:
            experience = float(match.group(1))
            break

    name = None
    name_match = re.search(
        r"(?:name\s*[:\-]\s*)([A-Za-z ]{2,60})",
        text,
        re.IGNORECASE
    )
    if name_match:
        name = name_match.group(1).strip()

    education = []
    education_keywords = [
        "b.sc", "bsc", "m.sc", "msc", "b.tech", "m.tech",
        "b.e", "m.e", "mba", "phd", "bachelor", "master"
    ]

    for keyword in education_keywords:
        if keyword in lower:
            education.append(keyword.upper())

    projects = []
    for line in text.splitlines():
        if "project" in line.lower():
            clean = line.strip()
            if clean:
                projects.append(clean[:200])

    return {
        "target_roles": [
            "Python Developer",
            "AI/ML Engineer",
            "Data Analyst"
        ],
        "current_roles": [],
        "total_relevant_experience": experience,
        "skills": sorted(set(found_skills)),
        "technologies": sorted(set(found_skills)),
        "projects": projects[:10],
        "education": education,
        "evidence_snippets": [
            line.strip()[:250]
            for line in text.splitlines()
            if line.strip()
        ][:10],
        "missing_or_uncertain_fields": [],
        "source": "resume_text"
    }


def generate_job_blueprint(
    title: str,
    requirements: str,
    min_experience: float,
    max_experience: float
):
    combined = f"{title} {requirements}".lower()

    required_skills = []

    for skill in KNOWN_SKILLS:
        if skill in combined:
            required_skills.append(skill)

    if not required_skills:
        if "engineer" in combined:
            required_skills = ["python", "git", "api"]
        else:
            required_skills = ["python"]

    return {
        "role_purpose": f"Perform responsibilities associated with {title}.",
        "minimum_criteria": [
            f"{min_experience}-{max_experience} years relevant experience"
        ],
        "preferred_criteria": [],
        "required_skills": sorted(set(required_skills)),
        "responsibilities": [
            "Develop and maintain assigned solutions",
            "Work with team members",
            "Apply problem-solving skills",
            "Document and communicate technical work"
        ],
        "education_rules": "Relevant educational background preferred.",
        "experience_rules": {
            "minimum_years": min_experience,
            "maximum_years": max_experience
        },
        "exclusions": [],
        "employer_confirmed": False
    }


def generate_syllabus(blueprint):
    items = []

    for skill in blueprint.get("required_skills", []):
        level = "basic"
        if skill in ["python", "fastapi", "sql", "rest api", "rag", "llm"]:
            level = "intermediate"

        items.append({
            "competency_id": f"C{len(items)+1}",
            "topic": skill,
            "competency": skill,
            "expected_level": level,
            "why_it_matters": f"Required for the {skill} aspects of the role.",
            "mandatory": True,
            "evidence_expected": f"Candidate should demonstrate practical knowledge of {skill}."
        })

    items.append({
        "competency_id": f"C{len(items)+1}",
        "topic": "problem solving",
        "competency": "problem solving",
        "expected_level": "basic",
        "why_it_matters": "Important for practical role execution.",
        "mandatory": True,
        "evidence_expected": "Examples of solving practical problems."
    })

    return items


def generate_questions(syllabus):
    questions = []

    question_templates = {
        "python": "Explain how you would structure a Python application and handle errors.",
        "fastapi": "How would you create and validate a REST API using FastAPI?",
        "sql": "Explain how you would retrieve and filter data using SQL.",
        "postgresql": "What are some important PostgreSQL concepts you have used?",
        "rest api": "What are the main principles of a REST API?",
        "rag": "Explain the basic flow of a Retrieval-Augmented Generation system.",
        "llm": "What is an LLM and how would you use it in an application?",
        "git": "Explain a Git workflow you have used in a project.",
        "api": "How do you design and validate an API endpoint?",
        "machine learning": "Explain a machine learning project you have worked on.",
        "data analysis": "How do you approach data cleaning and analysis?",
        "problem solving": "Describe a technical problem you solved and your approach."
    }

    for index, item in enumerate(syllabus):
        topic = item["topic"].lower()
        question = question_templates.get(
            topic,
            f"Explain your practical knowledge of {item['topic']}."
        )

        questions.append({
            "question_id": index + 1,
            "competency_id": item["competency_id"],
            "question": question,
            "difficulty": "medium",
            "expected_concepts": [item["topic"]],
            "rubric": {
                "0": "No relevant answer",
                "1": "Basic understanding",
                "2": "Good understanding with relevant example",
                "3": "Strong practical explanation with example"
            }
        })

    return questions


def evaluate_answer(question: str, answer: str):
    answer_lower = answer.lower()

    question_words = [
        word for word in re.findall(r"[a-zA-Z]+", question.lower())
        if len(word) > 3
    ]

    matched_concepts = [
        word for word in question_words
        if word in answer_lower
    ]

    if len(answer.strip()) < 20:
        level = 0
    elif len(matched_concepts) >= 3 and len(answer) > 100:
        level = 3
    elif len(matched_concepts) >= 1:
        level = 2
    else:
        level = 1

    feedback = {
        0: "Answer is too short or does not demonstrate the expected concept.",
        1: "Basic response provided. More technical detail is required.",
        2: "Relevant understanding is demonstrated.",
        3: "Strong explanation with relevant technical evidence."
    }[level]

    return {
        "demonstrated_concepts": matched_concepts,
        "missing_concepts": [],
        "evidence": answer[:500],
        "rubric_level": level,
        "feedback": feedback
    }


# ============================================================
# REQUEST SCHEMAS
# ============================================================

class RegisterRequest(BaseModel):
    email: str
    password: str = Field(min_length=6)
    role: str


class LoginRequest(BaseModel):
    email: str
    password: str


class EmployerProfileRequest(BaseModel):
    company_name: str
    company_info: Optional[str] = ""


class CandidateProfileConfirmRequest(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    confirmed_profile: Dict[str, Any]


class JobDraftRequest(BaseModel):
    title: str
    min_experience: float = 0
    max_experience: float = 99
    requirements: str = ""


class JobConfirmRequest(BaseModel):
    confirmed_blueprint: Optional[Dict[str, Any]] = None


class InterviewCreateRequest(BaseModel):
    number_of_questions: int = Field(default=5, ge=1, le=20)


class InterviewAnswerRequest(BaseModel):
    question_id: int
    answer: str


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "project": "AI Recruitment Platform",
        "version": "1.0.0",
        "modules": 5,
        "core_rule": "Interview is available only after MATCHED status.",
        "swagger": "/docs"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "database": "SQLite",
        "llm": llm.health_check()
    }


# ============================================================
# MODULE 1 - RBAC AUTHENTICATION
# ============================================================

@app.post("/auth/register")
def register(request: RegisterRequest):

    role = request.role.upper()

    if role not in ["EMPLOYER", "CANDIDATE"]:
        raise HTTPException(
            status_code=422,
            detail="Role must be EMPLOYER or CANDIDATE"
        )

    conn = db()

    existing = conn.execute(
        "SELECT id FROM users WHERE email=?",
        (request.email.lower(),)
    ).fetchone()

    if existing:
        conn.close()
        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    password_hash = hash_password(request.password)

    cur = conn.execute("""
        INSERT INTO users(email, password_hash, role, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        request.email.lower(),
        password_hash,
        role,
        now()
    ))

    user_id = cur.lastrowid

    if role == "CANDIDATE":
        conn.execute("""
            INSERT INTO candidate_profiles(
                user_id, structured_profile, confirmed_profile
            )
            VALUES (?, ?, ?)
        """, (
            user_id,
            json.dumps({}),
            json.dumps({})
        ))

    else:
        conn.execute("""
            INSERT INTO employer_profiles(
                user_id, company_name, company_info
            )
            VALUES (?, ?, ?)
        """, (
            user_id,
            "",
            ""
        ))

    conn.commit()
    conn.close()

    audit(user_id, "REGISTER", f"Registered as {role}")

    return {
        "message": "Registration successful",
        "user_id": user_id,
        "role": role
    }


@app.post("/auth/login")
def login(request: LoginRequest):

    conn = db()

    user = conn.execute(
        "SELECT * FROM users WHERE email=? AND is_active=1",
        (request.email.lower(),)
    ).fetchone()

    conn.close()

    if not user or not verify_password(
        request.password,
        user["password_hash"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    token = create_token(user["id"], user["role"])

    audit(user["id"], "LOGIN")

    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user["id"],
        "role": user["role"]
    }


@app.post("/auth/refresh")
def refresh(user=Depends(get_current_user)):
    return {
        "access_token": create_token(user["id"], user["role"]),
        "token_type": "bearer"
    }


@app.post("/auth/logout")
def logout(user=Depends(get_current_user)):
    audit(user["id"], "LOGOUT")
    return {"message": "Logged out successfully. Discard the access token."}


@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "is_active": bool(user["is_active"])
    }


# ============================================================
# MODULE 2 - ONBOARDING AND AI UNDERSTANDING
# ============================================================

@app.post("/candidate/onboarding/resume")
async def upload_resume(
    resume: UploadFile = File(...),
    name: Optional[str] = Form(None),
    location: Optional[str] = Form(None),
    user=Depends(require_role("CANDIDATE"))
):

    filename = resume.filename or "resume.txt"
    extension = filename.lower().split(".")[-1]

    allowed = ["pdf", "docx", "txt"]

    if extension not in allowed:
        raise HTTPException(
            status_code=422,
            detail="Only PDF, DOCX or TXT files are supported"
        )

    content = await resume.read()

    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=422,
            detail="File size must be below 5 MB"
        )

    text = extract_text_from_bytes(filename, content)

    if not text.strip():
        raise HTTPException(
            status_code=422,
            detail="No extractable text found in resume"
        )

    generated_name = f"{uuid.uuid4().hex}.{extension}"
    file_path = os.path.join(UPLOAD_DIR, generated_name)

    with open(file_path, "wb") as f:
        f.write(content)

    structured = llm.generate_structured(
        "resume_profile_extraction",
        {"resume_text": text}
    )

    conn = db()

    conn.execute("""
        UPDATE candidate_profiles
        SET name=?,
            location=?,
            resume_file=?,
            resume_text=?,
            structured_profile=?,
            confirmed_profile=?
        WHERE user_id=?
    """, (
        name,
        location,
        generated_name,
        text[:50000],
        json.dumps(structured),
        json.dumps(structured),
        user["id"]
    ))

    conn.commit()
    conn.close()

    audit(user["id"], "RESUME_UPLOADED")

    return {
        "message": "Resume uploaded and structured profile generated",
        "profile": structured,
        "review_required": True
    }


@app.get("/candidate/profile")
def get_candidate_profile_endpoint(
    user=Depends(require_role("CANDIDATE"))
):
    profile = get_candidate_profile(user["id"])

    return {
        "user_id": user["id"],
        "name": profile["name"],
        "location": profile["location"],
        "structured_profile": safe_json(
            profile["structured_profile"], {}
        ),
        "confirmed_profile": safe_json(
            profile["confirmed_profile"], {}
        )
    }


@app.patch("/candidate/profile")
def confirm_candidate_profile(
    request: CandidateProfileConfirmRequest,
    user=Depends(require_role("CANDIDATE"))
):

    get_candidate_profile(user["id"])

    conn = db()

    conn.execute("""
        UPDATE candidate_profiles
        SET name=?,
            location=?,
            confirmed_profile=?
        WHERE user_id=?
    """, (
        request.name,
        request.location,
        json.dumps(request.confirmed_profile),
        user["id"]
    ))

    conn.commit()
    conn.close()

    audit(user["id"], "PROFILE_CONFIRMED")

    return {
        "message": "Candidate profile confirmed",
        "confirmed_profile": request.confirmed_profile
    }


@app.patch("/employer/profile")
def update_employer_profile(
    request: EmployerProfileRequest,
    user=Depends(require_role("EMPLOYER"))
):

    conn = db()

    conn.execute("""
        UPDATE employer_profiles
        SET company_name=?, company_info=?
        WHERE user_id=?
    """, (
        request.company_name,
        request.company_info,
        user["id"]
    ))

    conn.commit()
    conn.close()

    return {
        "message": "Employer profile updated",
        "company_name": request.company_name
    }


@app.post("/employer/jobs/draft")
def create_job_draft(
    request: JobDraftRequest,
    user=Depends(require_role("EMPLOYER"))
):

    blueprint = llm.generate_structured(
        "job_blueprint_generation",
        {
            "title": request.title,
            "requirements": request.requirements,
            "min_experience": request.min_experience,
            "max_experience": request.max_experience
        }
    )

    conn = db()

    cur = conn.execute("""
        INSERT INTO jobs(
            employer_id, title, min_experience, max_experience,
            raw_input, blueprint, status, version, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'DRAFT', 1, ?)
    """, (
        user["id"],
        request.title,
        request.min_experience,
        request.max_experience,
        request.requirements,
        json.dumps(blueprint),
        now()
    ))

    job_id = cur.lastrowid

    conn.commit()
    conn.close()

    audit(user["id"], "JOB_DRAFT_CREATED", str(job_id))

    return {
        "job_id": job_id,
        "status": "DRAFT",
        "blueprint": blueprint,
        "review_required": True
    }


@app.post("/employer/jobs/{job_id}/confirm")
def confirm_job(
    job_id: int,
    request: JobConfirmRequest,
    user=Depends(require_role("EMPLOYER"))
):

    job = get_job_owned(job_id, user["id"])

    blueprint = (
        request.confirmed_blueprint
        if request.confirmed_blueprint
        else safe_json(job["blueprint"], {})
    )

    blueprint["employer_confirmed"] = True

    conn = db()

    conn.execute("""
        UPDATE jobs
        SET blueprint=?
        WHERE id=?
    """, (
        json.dumps(blueprint),
        job_id
    ))

    conn.commit()
    conn.close()

    audit(user["id"], "JOB_BLUEPRINT_CONFIRMED", str(job_id))

    return {
        "message": "Job blueprint confirmed",
        "job_id": job_id,
        "blueprint": blueprint
    }


# ============================================================
# MODULE 3 - JOB INTELLIGENCE
# ============================================================

@app.post("/jobs/{job_id}/generate-syllabus")
def generate_job_syllabus(
    job_id: int,
    user=Depends(require_role("EMPLOYER"))
):

    job = get_job_owned(job_id, user["id"])

    blueprint = safe_json(job["blueprint"], {})

    if not blueprint.get("employer_confirmed"):
        raise HTTPException(
            status_code=409,
            detail="Employer must confirm the job blueprint first"
        )

    syllabus = llm.generate_structured(
        "syllabus_generation",
        {"blueprint": blueprint}
    )

    conn = db()

    conn.execute("""
        UPDATE jobs
        SET syllabus=?
        WHERE id=?
    """, (
        json.dumps(syllabus),
        job_id
    ))

    conn.commit()
    conn.close()

    return {
        "job_id": job_id,
        "syllabus": syllabus
    }


@app.post("/jobs/{job_id}/generate-jd")
def generate_job_jd(
    job_id: int,
    user=Depends(require_role("EMPLOYER"))
):

    job = get_job_owned(job_id, user["id"])

    blueprint = safe_json(job["blueprint"], {})
    syllabus = safe_json(job["syllabus"], [])

    if not blueprint.get("employer_confirmed"):
        raise HTTPException(
            status_code=409,
            detail="Confirm blueprint before generating JD"
        )

    if not syllabus:
        raise HTTPException(
            status_code=409,
            detail="Generate syllabus before generating JD"
        )

    jd = llm.generate_text(
        "jd_generation",
        {
            "title": job["title"],
            "blueprint": blueprint,
            "syllabus": syllabus
        }
    )

    conn = db()

    conn.execute("""
        UPDATE jobs
        SET final_jd=?
        WHERE id=?
    """, (
        jd,
        job_id
    ))

    conn.commit()
    conn.close()

    return {
        "job_id": job_id,
        "final_jd": jd
    }


@app.post("/jobs/{job_id}/generate-questions")
def generate_job_questions(
    job_id: int,
    user=Depends(require_role("EMPLOYER"))
):

    job = get_job_owned(job_id, user["id"])

    syllabus = safe_json(job["syllabus"], [])

    if not syllabus:
        raise HTTPException(
            status_code=409,
            detail="Generate syllabus first"
        )

    questions = llm.generate_structured(
        "question_generation",
        {"syllabus": syllabus}
    )

    conn = db()

    conn.execute("""
        UPDATE jobs
        SET questions=?
        WHERE id=?
    """, (
        json.dumps(questions),
        job_id
    ))

    conn.commit()
    conn.close()

    return {
        "job_id": job_id,
        "question_bank": questions
    }


@app.post("/jobs/{job_id}/publish")
def publish_job(
    job_id: int,
    user=Depends(require_role("EMPLOYER"))
):

    job = get_job_owned(job_id, user["id"])

    blueprint = safe_json(job["blueprint"], {})
    syllabus = safe_json(job["syllabus"], [])
    jd = job["final_jd"]
    questions = safe_json(job["questions"], [])

    if not blueprint.get("employer_confirmed"):
        raise HTTPException(
            status_code=409,
            detail="Job blueprint must be confirmed"
        )

    if not syllabus or not jd or not questions:
        raise HTTPException(
            status_code=409,
            detail="Generate syllabus, JD and questions before publishing"
        )

    conn = db()

    conn.execute("""
        UPDATE jobs
        SET status='PUBLISHED'
        WHERE id=?
    """, (job_id,))

    conn.commit()
    conn.close()

    audit(user["id"], "JOB_PUBLISHED", str(job_id))

    return {
        "message": "Job published successfully",
        "job_id": job_id,
        "status": "PUBLISHED",
        "version": job["version"]
    }


@app.get("/jobs")
def list_jobs(user=Depends(get_current_user)):

    conn = db()

    jobs = conn.execute("""
        SELECT id, employer_id, title, min_experience,
               max_experience, final_jd, status, version
        FROM jobs
        WHERE status='PUBLISHED'
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return {
        "jobs": [dict(job) for job in jobs]
    }


@app.get("/jobs/{job_id}")
def get_job(
    job_id: int,
    user=Depends(get_current_user)
):

    conn = db()

    job = conn.execute(
        "SELECT * FROM jobs WHERE id=? AND status='PUBLISHED'",
        (job_id,)
    ).fetchone()

    conn.close()

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Published job not found"
        )

    data = dict(job)

    data["blueprint"] = safe_json(data["blueprint"], {})
    data["syllabus"] = safe_json(data["syllabus"], [])
    data["questions"] = safe_json(data["questions"], [])

    return data


# ============================================================
# MODULE 4 - JOB PRESENTATION AND MATCHING GATE
# ============================================================

@app.post("/jobs/{job_id}/apply")
def apply_job(
    job_id: int,
    user=Depends(require_role("CANDIDATE"))
):

    get_candidate_profile(user["id"])

    conn = db()

    job = conn.execute("""
        SELECT * FROM jobs
        WHERE id=? AND status='PUBLISHED'
    """, (job_id,)).fetchone()

    if not job:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Published job not found"
        )

    existing = conn.execute("""
        SELECT * FROM applications
        WHERE candidate_id=? AND job_id=? AND job_version=?
    """, (
        user["id"],
        job_id,
        job["version"]
    )).fetchone()

    if existing:
        conn.close()
        raise HTTPException(
            status_code=409,
            detail="Active application already exists for this job version"
        )

    cur = conn.execute("""
        INSERT INTO applications(
            candidate_id, job_id, job_version, status, created_at
        )
        VALUES (?, ?, ?, 'APPLIED', ?)
    """, (
        user["id"],
        job_id,
        job["version"],
        now()
    ))

    application_id = cur.lastrowid

    conn.commit()
    conn.close()

    audit(user["id"], "JOB_APPLIED", str(application_id))

    return {
        "application_id": application_id,
        "job_id": job_id,
        "status": "APPLIED"
    }


def perform_matching(application_id: int, candidate_id: int):

    conn = db()

    application = conn.execute("""
        SELECT * FROM applications WHERE id=?
    """, (application_id,)).fetchone()

    if not application:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Application not found"
        )

    if application["candidate_id"] != candidate_id:
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="You can access only your own application"
        )

    job = conn.execute(
        "SELECT * FROM jobs WHERE id=?",
        (application["job_id"],)
    ).fetchone()

    profile = conn.execute(
        "SELECT * FROM candidate_profiles WHERE user_id=?",
        (candidate_id,)
    ).fetchone()

    conn.close()

    if not profile:
        raise HTTPException(
            status_code=404,
            detail="Candidate profile not found"
        )

    confirmed_profile = safe_json(
        profile["confirmed_profile"],
        {}
    )

    skills = set(
        skill.lower()
        for skill in confirmed_profile.get("skills", [])
    )

    experience = float(
        confirmed_profile.get(
            "total_relevant_experience",
            0
        ) or 0
    )

    blueprint = safe_json(job["blueprint"], {})

    required_skills = [
        skill.lower()
        for skill in blueprint.get("required_skills", [])
    ]

    criterion_results = []
    missing = []

    for skill in required_skills:

        if skill in skills:
            result = "MET"
            evidence = f"Confirmed profile lists {skill}."
        else:
            result = "NOT_MET"
            evidence = f"No confirmed evidence for {skill}."
            missing.append(skill)

        criterion_results.append({
            "criterion": skill,
            "mandatory": True,
            "result": result,
            "evidence": evidence
        })

    min_exp = float(job["min_experience"] or 0)
    max_exp = float(job["max_experience"] or 99)

    if experience < min_exp:
        exp_result = "NOT_MET"
        exp_evidence = (
            f"Candidate has {experience} years; "
            f"minimum is {min_exp}."
        )
        missing.append(f"minimum {min_exp} years experience")

    elif experience > max_exp and max_exp < 99:
        exp_result = "UNKNOWN"
        exp_evidence = (
            f"Candidate has {experience} years; "
            f"job range ends at {max_exp} years."
        )

    else:
        exp_result = "MET"
        exp_evidence = (
            f"Candidate has {experience} years "
            f"within the required range."
        )

    criterion_results.append({
        "criterion": "experience",
        "mandatory": True,
        "result": exp_result,
        "evidence": exp_evidence
    })

    total = len(criterion_results)

    met = sum(
        1 for item in criterion_results
        if item["result"] == "MET"
    )

    score = round((met / total) * 100, 2) if total else 0

    eligible = (
        all(
            item["result"] != "NOT_MET"
            for item in criterion_results
            if item["mandatory"]
        )
        and not missing
    )

    status = "MATCHED" if eligible else "NOT_ELIGIBLE"

    conn = db()

    conn.execute("""
        UPDATE applications
        SET status=?
        WHERE id=?
    """, (
        status,
        application_id
    ))

    conn.execute("""
        INSERT INTO match_results(
            application_id,
            criterion_results,
            score,
            eligible,
            missing_criteria,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(application_id)
        DO UPDATE SET
            criterion_results=excluded.criterion_results,
            score=excluded.score,
            eligible=excluded.eligible,
            missing_criteria=excluded.missing_criteria,
            created_at=excluded.created_at
    """, (
        application_id,
        json.dumps(criterion_results),
        score,
        int(eligible),
        json.dumps(missing),
        now()
    ))

    conn.commit()
    conn.close()

    return {
        "application_id": application_id,
        "status": status,
        "eligible": eligible,
        "score": score,
        "criterion_results": criterion_results,
        "missing_criteria": missing
    }


@app.post("/applications/{application_id}/match")
def match_application(
    application_id: int,
    user=Depends(require_role("CANDIDATE"))
):

    result = perform_matching(
        application_id,
        user["id"]
    )

    audit(
        user["id"],
        "APPLICATION_MATCHED",
        json.dumps({
            "application_id": application_id,
            "status": result["status"]
        })
    )

    return result


@app.get("/applications/{application_id}/match-result")
def get_match_result(
    application_id: int,
    user=Depends(get_current_user)
):

    conn = db()

    application = conn.execute("""
        SELECT * FROM applications WHERE id=?
    """, (application_id,)).fetchone()

    if not application:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Application not found"
        )

    if (
        user["role"] == "CANDIDATE"
        and application["candidate_id"] != user["id"]
    ):
        conn.close()
        raise HTTPException(status_code=403, detail="Access denied")

    if (
        user["role"] == "EMPLOYER"
    ):
        job = conn.execute(
            "SELECT * FROM jobs WHERE id=?",
            (application["job_id"],)
        ).fetchone()

        if not job or job["employer_id"] != user["id"]:
            conn.close()
            raise HTTPException(status_code=403, detail="Access denied")

    result = conn.execute("""
        SELECT * FROM match_results
        WHERE application_id=?
    """, (application_id,)).fetchone()

    conn.close()

    if not result:
        raise HTTPException(
            status_code=404,
            detail="Matching has not been performed yet"
        )

    return {
        "application_id": application_id,
        "application_status": application["status"],
        "criterion_results": safe_json(
            result["criterion_results"],
            []
        ),
        "score": result["score"],
        "eligible": bool(result["eligible"]),
        "missing_criteria": safe_json(
            result["missing_criteria"],
            []
        )
    }


# ============================================================
# MODULE 5 - STRUCTURED AI INTERVIEW
# ============================================================

def get_application_for_user(application_id, user):
    conn = db()

    application = conn.execute(
        "SELECT * FROM applications WHERE id=?",
        (application_id,)
    ).fetchone()

    if not application:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Application not found"
        )

    if user["role"] == "CANDIDATE":
        if application["candidate_id"] != user["id"]:
            conn.close()
            raise HTTPException(
                status_code=403,
                detail="Access denied"
            )

    elif user["role"] == "EMPLOYER":
        job = conn.execute(
            "SELECT * FROM jobs WHERE id=?",
            (application["job_id"],)
        ).fetchone()

        if not job or job["employer_id"] != user["id"]:
            conn.close()
            raise HTTPException(
                status_code=403,
                detail="Access denied"
            )

    conn.close()
    return dict(application)


@app.post("/applications/{application_id}/interview")
def create_interview(
    application_id: int,
    request: InterviewCreateRequest,
    user=Depends(require_role("CANDIDATE"))
):

    application = get_application_for_user(
        application_id,
        user
    )

    # CRITICAL MATCHING GATE
    if application["status"] != "MATCHED":
        raise HTTPException(
            status_code=403,
            detail=(
                "Interview access denied. "
                "Application must have MATCHED status."
            )
        )

    conn = db()

    existing = conn.execute("""
        SELECT * FROM interview_sessions
        WHERE application_id=?
    """, (application_id,)).fetchone()

    if existing:
        conn.close()
        return {
            "message": "Interview session already exists",
            "interview_id": existing["id"],
            "status": existing["status"]
        }

    job = conn.execute(
        "SELECT * FROM jobs WHERE id=?",
        (application["job_id"],)
    ).fetchone()

    questions = safe_json(job["questions"], [])

    questions = questions[:request.number_of_questions]

    # Store selected question set as audit data in session state.
    session_state = {
        "questions": questions
    }

    cur = conn.execute("""
        INSERT INTO interview_sessions(
            application_id, status, current_index, started_at
        )
        VALUES (?, 'IN_PROGRESS', 0, ?)
    """, (
        application_id,
        now()
    ))

    session_id = cur.lastrowid

    conn.commit()
    conn.close()

    audit(
        user["id"],
        "INTERVIEW_CREATED",
        str(session_id)
    )

    return {
        "interview_id": session_id,
        "application_id": application_id,
        "status": "IN_PROGRESS",
        "number_of_questions": len(questions),
        "message": "Interview unlocked because application is MATCHED."
    }


@app.get("/interviews/{interview_id}/next-question")
def next_question(
    interview_id: int,
    user=Depends(require_role("CANDIDATE"))
):

    conn = db()

    session = conn.execute("""
        SELECT i.*, a.candidate_id, a.job_id, a.status AS application_status
        FROM interview_sessions i
        JOIN applications a ON a.id=i.application_id
        WHERE i.id=?
    """, (interview_id,)).fetchone()

    if not session:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Interview session not found"
        )

    if session["candidate_id"] != user["id"]:
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    if session["application_status"] != "MATCHED":
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Interview is locked because application is not MATCHED"
        )

    job = conn.execute(
        "SELECT questions FROM jobs WHERE id=?",
        (session["job_id"],)
    ).fetchone()

    questions = safe_json(job["questions"], [])

    index = session["current_index"]

    if index >= len(questions):
        conn.close()
        return {
            "completed": True,
            "message": "All questions have been answered."
        }

    question = questions[index]

    conn.close()

    return {
        "completed": False,
        "question_number": index + 1,
        "question": question
    }


@app.post("/interviews/{interview_id}/answer")
def submit_interview_answer(
    interview_id: int,
    request: InterviewAnswerRequest,
    user=Depends(require_role("CANDIDATE"))
):

    conn = db()

    session = conn.execute("""
        SELECT i.*, a.candidate_id, a.status AS application_status
        FROM interview_sessions i
        JOIN applications a ON a.id=i.application_id
        WHERE i.id=?
    """, (interview_id,)).fetchone()

    if not session:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Interview not found"
        )

    if session["candidate_id"] != user["id"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Access denied")

    if session["application_status"] != "MATCHED":
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Interview is locked"
        )

    job = conn.execute("""
        SELECT questions FROM jobs
        WHERE id=(
            SELECT job_id FROM applications
            WHERE id=?
        )
    """, (session["application_id"],)).fetchone()

    questions = safe_json(job["questions"], [])

    question = next(
        (
            q for q in questions
            if q["question_id"] == request.question_id
        ),
        None
    )

    if not question:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Question not found"
        )

    evaluation = llm.generate_structured(
        "answer_evaluation",
        {
            "question": question["question"],
            "answer": request.answer
        }
    )

    conn.execute("""
        INSERT INTO interview_answers(
            session_id, question_id, question, answer,
            evaluation, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        interview_id,
        request.question_id,
        question["question"],
        request.answer,
        json.dumps(evaluation),
        now()
    ))

    conn.execute("""
        UPDATE interview_sessions
        SET current_index=current_index+1
        WHERE id=?
    """, (interview_id,))

    conn.commit()
    conn.close()

    return {
        "message": "Answer submitted",
        "question_id": request.question_id,
        "evaluation": evaluation
    }


@app.post("/interviews/{interview_id}/complete")
def complete_interview(
    interview_id: int,
    user=Depends(require_role("CANDIDATE"))
):

    conn = db()

    session = conn.execute("""
        SELECT i.*, a.candidate_id, a.status AS application_status
        FROM interview_sessions i
        JOIN applications a ON a.id=i.application_id
        WHERE i.id=?
    """, (interview_id,)).fetchone()

    if not session:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Interview not found"
        )

    if session["candidate_id"] != user["id"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Access denied")

    if session["application_status"] != "MATCHED":
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Interview is not valid because application is not MATCHED"
        )

    conn.execute("""
        UPDATE interview_sessions
        SET status='COMPLETED', completed_at=?
        WHERE id=?
    """, (
        now(),
        interview_id
    ))

    conn.commit()
    conn.close()

    audit(
        user["id"],
        "INTERVIEW_COMPLETED",
        str(interview_id)
    )

    return {
        "message": "Interview completed",
        "interview_id": interview_id,
        "status": "COMPLETED"
    }


@app.get("/interviews/{interview_id}/report")
def interview_report(
    interview_id: int,
    user=Depends(get_current_user)
):

    conn = db()

    session = conn.execute("""
        SELECT i.*, a.candidate_id, a.job_id
        FROM interview_sessions i
        JOIN applications a ON a.id=i.application_id
        WHERE i.id=?
    """, (interview_id,)).fetchone()

    if not session:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Interview not found"
        )

    if user["role"] == "CANDIDATE":
        if session["candidate_id"] != user["id"]:
            conn.close()
            raise HTTPException(status_code=403, detail="Access denied")

    if user["role"] == "EMPLOYER":
        job = conn.execute(
            "SELECT employer_id FROM jobs WHERE id=?",
            (session["job_id"],)
        ).fetchone()

        if not job or job["employer_id"] != user["id"]:
            conn.close()
            raise HTTPException(status_code=403, detail="Access denied")

    answers = conn.execute("""
        SELECT * FROM interview_answers
        WHERE session_id=?
        ORDER BY id
    """, (interview_id,)).fetchall()

    conn.close()

    evaluations = []

    for answer in answers:
        evaluation = safe_json(
            answer["evaluation"],
            {}
        )

        evaluations.append({
            "question_id": answer["question_id"],
            "question": answer["question"],
            "answer": answer["answer"],
            "evaluation": evaluation
        })

    levels = [
        item["evaluation"].get("rubric_level", 0)
        for item in evaluations
    ]

    average = (
        round(sum(levels) / len(levels), 2)
        if levels else 0
    )

    return {
        "interview_id": interview_id,
        "status": session["status"],
        "total_answers": len(evaluations),
        "average_rubric_level": average,
        "answers": evaluations,
        "employer_facing_summary": (
            "Interview evaluation is based on the stored structured "
            "rubric results. The final aggregate is calculated by "
            "application logic."
        )
    }


# ============================================================
# DEMO / ADMIN INFORMATION
# ============================================================

@app.get("/demo/workflow")
def demo_workflow():

    return {
        "step_1": "Register EMPLOYER and CANDIDATE",
        "step_2": "Login and copy access tokens",
        "step_3": "Employer creates a job draft",
        "step_4": "Employer confirms blueprint",
        "step_5": "Generate syllabus",
        "step_6": "Generate JD",
        "step_7": "Generate questions",
        "step_8": "Publish job",
        "step_9": "Candidate uploads resume",
        "step_10": "Candidate confirms profile",
        "step_11": "Candidate applies",
        "step_12": "Candidate runs matching",
        "step_13": "If NOT_ELIGIBLE -> interview is blocked",
        "step_14": "If MATCHED -> interview is unlocked",
        "step_15": "Answer questions",
        "step_16": "Complete interview",
        "step_17": "View structured interview report"
    }


@app.get("/admin/audit-logs")
def audit_logs(user=Depends(require_role("EMPLOYER"))):

    conn = db()

    logs = conn.execute("""
        SELECT * FROM audit_logs
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    conn.close()

    return {
        "logs": [dict(log) for log in logs]
    }


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
