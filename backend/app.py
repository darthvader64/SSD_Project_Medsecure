from flask import Flask, jsonify, request, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from database.config import SessionLocal, engine, Base
from models.user import User, UserRole
from models.health_record import HealthRecord
from models.consent import Consent
from models.audit_log import AuditLog
from datetime import datetime, timedelta
from access_control.decorators import require_permission, require_record_access
from access_control.rbac import Permission, has_permission
import json
import os
from uuid import uuid4
from access_control.admin import admin_only


app = Flask(__name__)

# Configuration
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "super-secret-key-change-in-production")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False  # For development

# MinIO/S3 Configuration (update these with actual values)
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.environ.get("MINIO_BUCKET", "health-records")
MINIO_USE_SSL = os.environ.get("MINIO_USE_SSL", "false").lower() == "true"

CORS(app)
jwt = JWTManager(app)

# Initialize database on app startup
@app.before_request
def init_db():
    """Create all tables if they don't exist"""
    if not hasattr(app, '_db_initialized'):
        Base.metadata.create_all(bind=engine)
        app._db_initialized = True

# Password hashing
def get_password_hash(password):
    return generate_password_hash(password)

def verify_password(plain_password, hashed_password):
    return check_password_hash(hashed_password, plain_password)

# ==================== PAGE ROUTES ====================

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "message": "Server is running"}), 200

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# ==================== API ROUTES ====================

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "message": "Health Records API is running"})

# ==================== AUTH ROUTES ====================

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()

    print(f"[LOGIN] Login attempt: {email}")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()

        if not user:
            print("[ERROR] USER NOT FOUND")
            return jsonify({"msg": "Invalid credentials"}), 401

        print(f"[OK] USER FOUND: {user.email}")
        
        # Check password
        if not verify_password(password, user.hashed_password):
            print("[ERROR] PASSWORD WRONG")
            return jsonify({"msg": "Invalid credentials"}), 401

        print("[AUTH] Login successful")

        # ✅ FIX: Create JWT token with STRING identity (user ID only)
        token = create_access_token(identity=str(user.id))

        return jsonify({
            "token": token,
            "access_token": token,  # For frontend compatibility
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role.value
            }
        }), 200

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return jsonify({"msg": "Login failed", "error": str(e)}), 500
    finally:
        db.close()

@app.route("/auth/register", methods=["POST"])
def register():
    print("[AUTH] Registration started")
    
    try:
        data = request.get_json()
        print(f"[DATA] Received data: {data}")
        
        if not data:
            return jsonify({"msg": "No JSON data received"}), 400
            
        email = data.get("email", "").strip()
        password = data.get("password", "").strip()
        role = data.get("role", "PATIENT").upper()

        print(f"[EMAIL] Email: {email}")
        print(f"[PASSWORD] Password: {password}")
        print(f"[ROLE] Role: {role}")

        db = SessionLocal()
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            print("[ERROR] USER ALREADY EXISTS")
            return jsonify({"msg": "User already exists"}), 400

        print("[OK] Creating new user...")
        
        # Create new user
        hashed_password = get_password_hash(password)
        print(f"[SECURITY] Hashed password: {hashed_password}")

        new_user = User(
            email=email,
            hashed_password=hashed_password,
            role=UserRole(role),
            is_active=True,
            created_at=datetime.now()
        )

        db.add(new_user)
        db.commit()
        
        user_id = new_user.id
        print(f"[OK] USER CREATED SUCCESSFULLY: ID {user_id}")

        db.close()
        
        return jsonify({
            "msg": "User created successfully",
            "user_id": user_id
        }), 201
        
    except Exception as e:
        print(f"[ERROR] Registration: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"msg": "Registration failed", "error": str(e)}), 500

@app.route("/auth/me", methods=["GET"])
@jwt_required()
def auth_me():
    """Get current user info"""
    user_id_str = get_jwt_identity()
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == int(user_id_str)).first()
        if user:
            return jsonify({
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "role": user.role.value
                }
            }), 200
        return jsonify({"msg": "User not found"}), 404
    finally:
        db.close()

@app.route("/auth/validate", methods=["GET"])
@jwt_required()
def validate_token():
    """Validate token and return user info"""
    user_id_str = get_jwt_identity()
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == int(user_id_str)).first()
        if user:
            return jsonify({
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "role": user.role.value
                }
            }), 200
        return jsonify({"msg": "User not found"}), 404
    finally:
        db.close()

@app.route("/doctor/create-patient-history", methods=["POST"])
@jwt_required()
def doctor_create_patient_history():
    """Doctor creates a new history record that is owned by the patient."""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)

    db = SessionLocal()
    try:
        # 1) Ensure current user is a doctor
        doctor = db.query(User).filter(User.id == user_id).first()
        if not doctor:
            return jsonify({"msg": "User not found"}), 404

        if doctor.role != UserRole.DOCTOR:
            return jsonify({"msg": "Only doctors can create patient histories."}), 403

        # 2) Parse body
        data = request.get_json() or {}
        patient_email = (data.get("patient_email") or "").strip().lower()
        title         = (data.get("title") or "").strip()
        notes         = (data.get("notes") or "").strip()

        if not patient_email or not title or not notes:
            return jsonify({"msg": "patient_email, title and notes are required."}), 400

        # 3) Look up patient (must be PATIENT role)
        patient = (
            db.query(User)
            .filter(User.email == patient_email, User.role == UserRole.PATIENT)
            .first()
        )
        if not patient:
            return jsonify({"msg": "Patient not found."}), 404

        # 4) Create a HealthRecord belonging to the patient
        approx_size = max(256, len(title) + len(notes))

        new_record = HealthRecord(
            patient_id=patient.id,
            file_name=title,
            file_size=approx_size,
            # For the assignment we just store a dummy URI + crypto params
            storage_uri=f"doctor-history://{patient.id}/{uuid4().hex}",
            encrypted_key="doctor_history_placeholder",
            iv="doctor_history_iv",
            salt="",
            algorithm="AES-256-GCM",
            created_at=datetime.now(),
        )

        db.add(new_record)
        db.flush()  # get ID

        # 5) Automatically grant consent for this doctor to see that record
        new_consent = Consent(
            patient_id=patient.id,
            doctor_id=doctor.id,
            record_id=new_record.id,
            is_active=True,
            granted_at=datetime.now(),
            wrapped_key="doctor_history_placeholder",
        )
        db.add(new_consent)

        # 6) Audit logs (both doctor + patient get an entry)
        doctor_log = AuditLog(
            user_id=doctor.id,
            action="create_patient_history",
            record_id=new_record.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            timestamp=datetime.now(),
            status="success",
        )
        patient_log = AuditLog(
            user_id=patient.id,
            action="history_created_by_doctor",
            record_id=new_record.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            timestamp=datetime.now(),
            status="success",
        )
        db.add(doctor_log)
        db.add(patient_log)

        db.commit()

        return jsonify(
            {
                "msg": "History record created.",
                "record_id": new_record.id,
                "patient_id": patient.id,
                "patient_email": patient.email,
            }
        ), 201

    except Exception as e:
        db.rollback()
        return jsonify({"msg": "Failed to create history", "error": str(e)}), 500
    finally:
        db.close()
# ==================== ADMIN ROUTES ====================

@app.route("/admin/audit-logs", methods=["GET"])
@jwt_required()
@admin_only
def admin_audit_logs():
    """Admin: view system-wide audit logs."""
    db = SessionLocal()
    try:
        logs = (
            db.query(AuditLog)
            .order_by(AuditLog.timestamp.desc())
            .limit(200)
            .all()
        )

        result = []
        for log in logs:
            user_email = None
            if log.user_id:
                u = db.query(User).filter(User.id == log.user_id).first()
                user_email = u.email if u else None

            result.append(
                {
                    "id": log.id,
                    "user_id": log.user_id,
                    "user_email": user_email,
                    "action": log.action,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "status": log.status,
                }
            )

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@app.route("/admin/records-overview", methods=["GET"])
@jwt_required()
@admin_only
def admin_records_overview():
    """Admin: view all patient records with basic details and consent count."""
    db = SessionLocal()
    try:
        records = (
            db.query(HealthRecord)
            .order_by(HealthRecord.created_at.desc())
            .limit(200)
            .all()
        )

        result = []
        for r in records:
            patient = db.query(User).filter(User.id == r.patient_id).first()
            consent_count = (
                db.query(Consent)
                .filter(Consent.record_id == r.id, Consent.is_active == True)
                .count()
            )

            result.append(
                {
                    "id": r.id,
                    "file_name": r.file_name,
                    "file_size": r.file_size,
                    "patient_id": r.patient_id,
                    "patient_email": patient.email if patient else None,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "active_consents": consent_count,
                }
            )

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@app.route("/admin/doctor-access", methods=["GET"])
@jwt_required()
@admin_only
def admin_doctor_access():
    """Admin: overview of doctor access via active consents."""
    db = SessionLocal()
    try:
        consents = (
            db.query(Consent)
            .filter(Consent.is_active == True)
            .order_by(Consent.granted_at.desc())
            .limit(200)
            .all()
        )

        result = []
        for c in consents:
            patient = db.query(User).filter(User.id == c.patient_id).first()
            doctor = db.query(User).filter(User.id == c.doctor_id).first()
            record = db.query(HealthRecord).filter(HealthRecord.id == c.record_id).first()

            result.append(
                {
                    "consent_id": c.id,
                    "record_id": c.record_id,
                    "record_name": record.file_name if record else None,
                    "patient_id": c.patient_id,
                    "patient_email": patient.email if patient else None,
                    "doctor_id": c.doctor_id,
                    "doctor_email": doctor.email if doctor else None,
                    "granted_at": c.granted_at.isoformat() if c.granted_at else None,
                    "is_active": c.is_active,
                }
            )

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()



# ==================== ENCRYPTION & KEY MANAGEMENT ====================

@app.route("/keys/public/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user_public_key(user_id):
    """Get user's RSA public key for key wrapping"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"msg": "User not found"}), 404
        
        if not user.public_key:
            return jsonify({
                "msg": "User has not generated RSA key pair",
                "user_id": user_id,
                "email": user.email
            }), 404
        
        return jsonify({
            "user_id": user.id,
            "email": user.email,
            "public_key": user.public_key,
            "key_type": "RSA-4096",
            "algorithm": "RSA-OAEP"
        }), 200
    except Exception as e:
        return jsonify({"msg": "Failed to fetch public key", "error": str(e)}), 500
    finally:
        db.close()

@app.route("/keys/generate", methods=["POST"])
@jwt_required()
def generate_user_keys():
    """Generate RSA key pair for current user"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    data = request.get_json()
    public_key_pem = data.get("public_key")
    
    if not public_key_pem:
        return jsonify({"msg": "Public key PEM is required"}), 400
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"msg": "User not found"}), 404
        
        user.public_key = public_key_pem
        db.commit()
        
        print(f"[KEYS] RSA keys for user {user_id}")
        
        return jsonify({
            "msg": "RSA key pair generated and stored",
            "user_id": user.id,
            "email": user.email
        }), 201
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Keys: {str(e)}")
        return jsonify({"msg": "Failed to generate keys", "error": str(e)}), 500
    finally:
        db.close()

@app.route("/records/presign", methods=["POST"])
@jwt_required()
@require_permission(Permission.CREATE_RECORD)
def presign_upload():
    """Get presigned URL for uploading encrypted file to MinIO"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    data = request.get_json()
    filename = data.get("filename", "")
    content_type = data.get("content_type", "application/octet-stream")
    
    if not filename:
        return jsonify({"msg": "Filename is required"}), 400
    
    try:
        # Generate unique object key
        file_extension = filename.split('.')[-1] if '.' in filename else 'bin'
        object_key = f"{user_id}/{uuid4().hex}.{file_extension}"
        
        # TODO: Implement actual MinIO presigned URL generation
        # For now, return placeholder URL structure
        # In production, use boto3 or minio-py client
        
        presigned_url = f"https://{MINIO_ENDPOINT}/{MINIO_BUCKET}/{object_key}"
        file_uri = f"s3://{MINIO_BUCKET}/{object_key}"
        
        print(f"[STORAGE] Upload URL for user {user_id}")
        
        return jsonify({
            "upload_url": presigned_url,
            "file_uri": file_uri,
            "object_key": object_key,
            "bucket": MINIO_BUCKET,
            "expires_in": 3600
        }), 200
    except Exception as e:
        print(f"[ERROR] URL: {str(e)}")
        return jsonify({"msg": "Failed to generate upload URL", "error": str(e)}), 500

@app.route("/records/download-url/<int:record_id>", methods=["GET"])
@jwt_required()
@require_record_access(Permission.READ_RECORD)
def get_download_url(record_id):
    """Get presigned URL for downloading encrypted file from MinIO"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    db = SessionLocal()
    try:
        record = db.query(HealthRecord).filter(HealthRecord.id == record_id).first()
        if not record:
            return jsonify({"msg": "Record not found"}), 404
        
        # Extract object key from storage URI
        # Format: s3://bucket/path/to/object
        if record.storage_uri.startswith("s3://"):
            object_key = record.storage_uri.replace(f"s3://{MINIO_BUCKET}/", "")
        else:
            object_key = record.storage_uri
        
        # TODO: Implement actual MinIO presigned URL generation
        # In production, use boto3 or minio-py client
        
        download_url = f"https://{MINIO_ENDPOINT}/{MINIO_BUCKET}/{object_key}"
        
        print(f"[STORAGE] Download URL for user {user_id}")
        
        return jsonify({
            "download_url": download_url,
            "file_uri": record.storage_uri,
            "object_key": object_key,
            "filename": record.file_name,
            "expires_in": 3600
        }), 200
    except Exception as e:
        print(f"[ERROR] Download: {str(e)}")
        return jsonify({"msg": "Failed to generate download URL", "error": str(e)}), 500
    finally:
        db.close()

# ==================== ENHANCED RECORD MANAGEMENT ====================

@app.route("/records/upload-metadata", methods=["POST"])
@jwt_required()
@require_permission(Permission.CREATE_RECORD)
def upload_record_metadata():
    """Save encrypted file metadata (called after upload to MinIO)"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    data = request.get_json()
    filename = data.get("filename", "")
    file_uri = data.get("file_uri", "")
    iv = data.get("iv", "")  # Base64 encoded
    algorithm = data.get("algorithm", "AES-256-GCM")
    patient_wrap = data.get("patient_wrap", "")  # Base64 encoded wrapped key
    salt = data.get("salt", "")  # Base64 encoded
    kdf_params = data.get("kdf_params", {})
    file_size = data.get("file_size", 0)
    
    if not all([filename, file_uri, iv, patient_wrap, salt]):
        return jsonify({
            "msg": "Missing required encryption parameters",
            "required": ["filename", "file_uri", "iv", "patient_wrap", "salt"]
        }), 400
    
    db = SessionLocal()
    try:
        # Create record with full encryption metadata
        new_record = HealthRecord(
            patient_id=user_id,
            file_name=filename,
            file_size=file_size,
            storage_uri=file_uri,
            encrypted_key=patient_wrap,  # Store wrapped key
            iv=iv,
            salt=salt,  # Store salt for key derivation
            algorithm=algorithm,
            created_at=datetime.now()
        )
        
        db.add(new_record)
        db.flush()  # Get the ID before commit
        record_id = new_record.id
        db.commit()
        
        print(f"[STORAGE] Saved metadata: {record_id}")
        
        # Log the action
        audit_log = AuditLog(
            user_id=user_id,
            action="upload_record",
            record_id=record_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            timestamp=datetime.now(),
            status="success"
        )
        db.add(audit_log)
        db.commit()
        
        return jsonify({
            "msg": "Record metadata saved successfully",
            "record_id": record_id,
            "file_uri": file_uri,
            "algorithm": algorithm,
            "created_at": new_record.created_at.isoformat()
        }), 201
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Metadata: {str(e)}")
        return jsonify({"msg": "Failed to save record metadata", "error": str(e)}), 500
    finally:
        db.close()

# ==================== RECORDS ROUTES ====================

@app.route("/records", methods=["GET"])
@jwt_required()
@require_permission(Permission.LIST_RECORDS)
def get_records():
    """Get all records for current user"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    db = SessionLocal()
    try:
        # Get user to determine role
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"msg": "User not found"}), 404
            
        user_role = user.role.value

        # Get records where user is owner or has consent
        if user_role == "patient":
            records = db.query(HealthRecord).filter(HealthRecord.patient_id == user_id).all()
        else:  # doctor
            # FIXED: Explicit join condition
            records = db.query(HealthRecord).join(
                Consent, HealthRecord.id == Consent.record_id
            ).filter(
                Consent.doctor_id == user_id,
                Consent.is_active == True
            ).all()

        print(f"🔍 User {user_id} ({user_role}) found {len(records)} records")
        
        return jsonify([
            {
                "id": record.id,
                "file_name": record.file_name,
                "file_size": record.file_size,
                "created_at": record.created_at.isoformat() if record.created_at else None,
                "patient_id": record.patient_id,
                "iv": record.iv,
                "encrypted_key": record.encrypted_key,
                "salt": record.salt,
                "algorithm": record.algorithm
            } for record in records
        ]), 200
    except Exception as e:
        print(f"[ERROR] Records: {str(e)}")
        return jsonify({"msg": "Failed to fetch records", "error": str(e)}), 500
    finally:
        db.close()

@app.route("/records", methods=["POST"])
@jwt_required()
@require_permission(Permission.CREATE_RECORD)
def create_record():
    """Create a new health record"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    data = request.get_json()
    file_name = data.get("file_name", "")
    file_size = data.get("file_size", 0)

    db = SessionLocal()
    try:
        # Create new health record
        new_record = HealthRecord(
            patient_id=user_id,
            file_name=file_name,
            file_size=file_size,
            storage_uri=f"minio://records/{user_id}/{file_name}",
            encrypted_key='test_key',
            iv='test_iv',
            algorithm='AES-256-GCM',
            created_at=datetime.now()
        )

        db.add(new_record)
        db.commit()

        # Log the action
        audit_log = AuditLog(
            user_id=user_id,
            action="create_record",
            record_id=new_record.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            timestamp=datetime.now(),
            status="success"
        )
        db.add(audit_log)
        db.commit()

        return jsonify({
            "msg": "Record created successfully",
            "record_id": new_record.id
        }), 201
    except Exception as e:
        db.rollback()
        return jsonify({"msg": "Failed to create record", "error": str(e)}), 500
    finally:
        db.close()

@app.route("/records/<int:record_id>", methods=["GET"])
@jwt_required()
@require_record_access(Permission.READ_RECORD)
def get_record(record_id):
    """Get specific record with access control"""
    db = SessionLocal()
    try:
        record = db.query(HealthRecord).filter(HealthRecord.id == record_id).first()
        if record:
            return jsonify({
                "id": record.id,
                "file_name": record.file_name,
                "file_size": record.file_size,
                "created_at": record.created_at.isoformat() if record.created_at else None,
                "iv": record.iv,
                "encrypted_key": record.encrypted_key,
                "salt": record.salt,
                "algorithm": record.algorithm
            }), 200
        return jsonify({"msg": "Record not found"}), 404
    finally:
        db.close()

# ==================== CONSENT ROUTES ====================

@app.route("/consents", methods=["POST"])
@jwt_required()
@require_permission(Permission.GRANT_CONSENT)
def grant_consent():
    """Grant consent with better error handling"""
    user_id_str = get_jwt_identity()
    patient_id = int(user_id_str)
    
    data = request.get_json()
    doctor_id = data.get("doctor_id")
    record_id = data.get("record_id")

    print(f"🔍 Granting consent - Patient: {patient_id}, Doctor: {doctor_id}, Record: {record_id}")

    # Validate input
    if not doctor_id or not record_id:
        return jsonify({"msg": "Doctor ID and Record ID are required"}), 400

    db = SessionLocal()
    try:
        # Verify the patient exists and is a patient
        patient = db.query(User).filter(User.id == patient_id, User.role == UserRole.PATIENT).first()
        if not patient:
            return jsonify({"msg": "Patient not found or invalid role"}), 404

        # Verify the doctor exists and is a doctor
        doctor = db.query(User).filter(User.id == doctor_id, User.role == UserRole.DOCTOR).first()
        if not doctor:
            return jsonify({"msg": "Doctor not found or invalid role"}), 404

        # Verify the record belongs to the patient
        record = db.query(HealthRecord).filter(
            HealthRecord.id == record_id,
            HealthRecord.patient_id == patient_id
        ).first()
        
        if not record:
            return jsonify({"msg": "Record not found or access denied"}), 404

        # Check if consent already exists and is active
        existing_consent = db.query(Consent).filter(
            Consent.patient_id == patient_id,
            Consent.doctor_id == doctor_id,
            Consent.record_id == record_id,
            Consent.is_active == True
        ).first()
        
        if existing_consent:
            return jsonify({"msg": "Consent already granted for this record"}), 400

        # Create consent
        wrapped_key = data.get('wrapped_key', '')  # Accept wrapped key from client
        if not wrapped_key:
            return jsonify({"msg": "Wrapped key is required for consent"}), 400
        
        new_consent = Consent(
            patient_id=patient_id,
            doctor_id=doctor_id,
            record_id=record_id,
            wrapped_key=wrapped_key,  # Store the wrapped key from client
            is_active=True,
            granted_at=datetime.now()
        )

        db.add(new_consent)
        db.commit()
        db.refresh(new_consent)

        print(f"✅ Consent granted successfully: {new_consent.id}")

        # Log the action
        audit_log = AuditLog(
            user_id=patient_id,
            action="grant_consent",
            record_id=record_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            timestamp=datetime.now(),
            status="success"
        )
        db.add(audit_log)
        db.commit()

        return jsonify({
            "msg": "Consent granted successfully",
            "consent_id": new_consent.id,
            "doctor_email": doctor.email,
            "record_name": record.file_name
        }), 201
        
    except Exception as e:
        db.rollback()
        print(f"💥 Failed to grant consent: {str(e)}")
        return jsonify({"msg": "Failed to grant consent", "error": str(e)}), 500
    finally:
        db.close()

@app.route("/consents/active", methods=["GET"])
@jwt_required()
@require_permission(Permission.LIST_CONSENTS)
def get_active_consents():
    """Get active consents for current user"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    db = SessionLocal()
    try:
        consents = db.query(Consent).filter(
            Consent.patient_id == user_id,
            Consent.is_active == True
        ).all()
        
        return jsonify([
            {
                "id": consent.id,
                "doctor_id": consent.doctor_id,
                "record_id": consent.record_id,
                "granted_at": consent.granted_at.isoformat() if consent.granted_at else None
            } for consent in consents
        ]), 200
    except Exception as e:
        return jsonify({"msg": "Failed to fetch consents", "error": str(e)}), 500
    finally:
        db.close()

@app.route("/consents/<int:consent_id>", methods=["DELETE"])
@jwt_required()
@require_permission(Permission.REVOKE_CONSENT)
def revoke_consent(consent_id):
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)

    db = SessionLocal()
    try:
        # Find consent and verify ownership
        consent = db.query(Consent).filter(
            Consent.id == consent_id,
            Consent.patient_id == user_id
        ).first()
        
        if not consent:
            return jsonify({"msg": "Consent not found or access denied"}), 404

        # Revoke consent (soft delete)
        consent.is_active = False
        db.commit()

        # Log the action
        audit_log = AuditLog(
            user_id=user_id,
            action="revoke_consent",
            record_id=consent.record_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            timestamp=datetime.now(),
            status="success"
        )
        db.add(audit_log)
        db.commit()

        return jsonify({"msg": "Consent revoked successfully", "consent_id": consent_id}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"msg": "Failed to revoke consent", "error": str(e)}), 500
    finally:
        db.close()

# ==================== AUDIT LOGS ROUTES ====================

@app.route("/audit-logs", methods=["GET"])
@jwt_required()
@require_permission(Permission.VIEW_AUDIT_LOGS)
def get_audit_logs():
    """Get audit logs for current user"""
    try:
        user_id_str = get_jwt_identity()
        user_id = int(user_id_str)
        
        print(f"🔍 Fetching audit logs for user ID: {user_id}")
        
        db = SessionLocal()
        
        # Check if user exists
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            print(f"❌ User {user_id} not found")
            return jsonify({"error": "User not found"}), 404
            
        print(f"✅ User found: {user.email}")
        
        # Get audit logs
        logs = db.query(AuditLog).filter(
            AuditLog.user_id == user_id
        ).order_by(AuditLog.timestamp.desc()).limit(50).all()
        
        print(f"✅ Found {len(logs)} audit logs")
        
        result = []
        for log in logs:
            log_data = {
                "id": log.id,
                "action": log.action,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "ip_address": log.ip_address,
                "status": log.status
            }
            result.append(log_data)
        
        db.close()
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"[ERROR] Audit: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/test-audit", methods=["POST"])
@jwt_required()
def test_audit():
    """Create test audit logs"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    db = SessionLocal()
    try:
        # Create some test audit logs
        test_actions = ["login", "view_record", "create_record", "logout", "test_access"]
        
        for action in test_actions:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                record_id=None,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                timestamp=datetime.now(),
                status="success"
            )
            db.add(audit_log)
        
        db.commit()
        return jsonify({"msg": "Test audit logs created"}), 201
        
    except Exception as e:
        return jsonify({"msg": "Failed to create test logs", "error": str(e)}), 500
    finally:
        db.close()

# ==================== USER ROUTES ====================

@app.route("/users/doctors", methods=["GET"])
@jwt_required()
@require_permission(Permission.VIEW_DOCTORS_LIST)
def get_doctors():
    """Get list of all doctors"""
    db = SessionLocal()
    try:
        doctors = db.query(User).filter(User.role == UserRole.DOCTOR, User.is_active == True).all()
        
        return jsonify([
            {
                "id": doctor.id,
                "email": doctor.email
            } for doctor in doctors
        ]), 200
    except Exception as e:
        return jsonify({"msg": "Failed to fetch doctors", "error": str(e)}), 500
    finally:
        db.close()

# ==================== UI-FRIENDLY ENDPOINTS ====================

@app.route("/ui/doctors-list", methods=["GET"])
@jwt_required()
def ui_doctors_list():
    """Simple endpoint for frontend to get doctors list"""
    db = SessionLocal()
    try:
        doctors = db.query(User).filter(User.role == UserRole.DOCTOR, User.is_active == True).all()
        
        return jsonify({
            "doctors": [
                {
                    "id": doctor.id,
                    "email": doctor.email,
                    "display_name": f"Dr. {doctor.email.split('@')[0].title()}"
                } for doctor in doctors
            ]
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/ui/my-records", methods=["GET"])
@jwt_required()
def ui_my_records():
    """Simple endpoint for frontend to get patient's records"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        if user.role != UserRole.PATIENT:
            return jsonify({"error": "Only patients can access this endpoint"}), 403
            
        records = db.query(HealthRecord).filter(HealthRecord.patient_id == user_id).all()
        
        return jsonify({
            "records": [
                {
                    "id": record.id,
                    "file_name": record.file_name,
                    "file_size": record.file_size,
                    "created_at": record.created_at.isoformat() if record.created_at else None
                } for record in records
            ]
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/ui/active-consents", methods=["GET"])
@jwt_required()
def ui_active_consents():
    """Get active consents for UI"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        if user.role != UserRole.PATIENT:
            return jsonify({"error": "Only patients can access this endpoint"}), 403
            
        consents = db.query(Consent).filter(
            Consent.patient_id == user_id,
            Consent.is_active == True
        ).all()
        
        # Get detailed consent information
        detailed_consents = []
        for consent in consents:
            doctor = db.query(User).filter(User.id == consent.doctor_id).first()
            record = db.query(HealthRecord).filter(HealthRecord.id == consent.record_id).first()
            
            detailed_consents.append({
                "consent_id": consent.id,
                "doctor_email": doctor.email if doctor else "Unknown",
                "record_name": record.file_name if record else "Unknown",
                "granted_at": consent.granted_at.isoformat() if consent.granted_at else None
            })
        
        return jsonify({
            "consents": detailed_consents
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/ui/grant-consent", methods=["POST"])
@jwt_required()
def ui_grant_consent():
    """UI-friendly consent granting endpoint"""
    user_id_str = get_jwt_identity()
    patient_id = int(user_id_str)

    data = request.get_json() or {}

    try:
        doctor_id = int(data.get("doctor_id"))
        record_id = int(data.get("record_id"))
    except (TypeError, ValueError):
        return jsonify({"success": False, "msg": "Invalid doctor or record selected"}), 400

    print(f"🔍 UI Granting consent - Patient: {patient_id}, Doctor: {doctor_id}, Record: {record_id}")


    # Validate input
    if not doctor_id or not record_id:
        return jsonify({"success": False, "msg": "Doctor and Record are required"}), 400

    db = SessionLocal()
    try:
        # Verify the patient exists and is a patient
        patient = db.query(User).filter(User.id == patient_id, User.role == UserRole.PATIENT).first()
        if not patient:
            return jsonify({"success": False, "msg": "Only patients can grant consent"}), 403

        # Verify the doctor exists and is a doctor
        doctor = db.query(User).filter(User.id == doctor_id, User.role == UserRole.DOCTOR).first()
        if not doctor:
            return jsonify({"success": False, "msg": "Selected doctor not found"}), 404

        # Verify the record belongs to the patient
        record = db.query(HealthRecord).filter(
            HealthRecord.id == record_id,
            HealthRecord.patient_id == patient_id
        ).first()
        
        if not record:
            return jsonify({"success": False, "msg": "Record not found"}), 404

        # Check if consent already exists and is active
        existing_consent = db.query(Consent).filter(
            Consent.patient_id == patient_id,
            Consent.doctor_id == doctor_id,
            Consent.record_id == record_id,
            Consent.is_active == True
        ).first()
        
        if existing_consent:
            return jsonify({"success": False, "msg": "Consent already granted for this record"}), 400

        # Create consent
        new_consent = Consent(
            patient_id=patient_id,
            doctor_id=doctor_id,
            record_id=record_id,
            wrapped_key='wrapped_key_test',
            is_active=True,
            granted_at=datetime.now()
        )

        db.add(new_consent)
        db.commit()
        db.refresh(new_consent)

        print(f"✅ Consent granted successfully: {new_consent.id}")

        # Log the action
        audit_log = AuditLog(
            user_id=patient_id,
            action="grant_consent",
            record_id=record_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            timestamp=datetime.now(),
            status="success"
        )
        db.add(audit_log)
        db.commit()

        return jsonify({
            "success": True,
            "msg": f"Access granted to Dr. {doctor.email.split('@')[0].title()} for {record.file_name}",
            "consent_id": new_consent.id,
            "doctor_email": doctor.email,
            "record_name": record.file_name
        }), 201
        
    except Exception as e:
        db.rollback()
        print(f"💥 Failed to grant consent: {str(e)}")
        return jsonify({"success": False, "msg": "Failed to grant consent", "error": str(e)}), 500
    finally:
        db.close()

@app.route("/ui/doctor-dashboard", methods=["GET"])
@jwt_required()
def ui_doctor_dashboard():
    """Doctor dashboard data"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        if user.role != UserRole.DOCTOR:
            return jsonify({"error": "Only doctors can access this endpoint"}), 403
        
        # Get accessible records via consents
        accessible_records = db.query(HealthRecord).join(
            Consent, HealthRecord.id == Consent.record_id
        ).filter(
            Consent.doctor_id == user_id,
            Consent.is_active == True
        ).all()
        
        # Get consent details
        consents = db.query(Consent).filter(
            Consent.doctor_id == user_id,
            Consent.is_active == True
        ).all()
        
        detailed_records = []
        for record in accessible_records:
            patient = db.query(User).filter(User.id == record.patient_id).first()
            consent = db.query(Consent).filter(
                Consent.record_id == record.id,
                Consent.doctor_id == user_id
            ).first()
            
            detailed_records.append({
                "record_id": record.id,
                "file_name": record.file_name,
                "file_size": record.file_size,
                "created_at": record.created_at.isoformat() if record.created_at else None,
                "patient_email": patient.email if patient else "Unknown",
                "consent_granted_at": consent.granted_at.isoformat() if consent and consent.granted_at else None
            })
        
        return jsonify({
            "doctor_info": {
                "id": user.id,
                "email": user.email,
                "display_name": f"Dr. {user.email.split('@')[0].title()}"
            },
            "accessible_records": detailed_records,
            "total_accessible_records": len(detailed_records)
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

# ==================== DEBUG & ACCESS CONTROL TESTING ROUTES ====================

@app.route("/debug/my-accessible-records", methods=["GET"])
@jwt_required()
def debug_my_accessible_records():
    """Debug endpoint to see what records current user can access"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        user_role = user.role.value
        
        result = {
            "user_id": user_id,
            "user_role": user_role,
            "user_email": user.email,
            "accessible_records": []
        }
        
        if user_role == "patient":
            # Patient sees their own records
            records = db.query(HealthRecord).filter(HealthRecord.patient_id == user_id).all()
            result["record_type"] = "owned_records"
            result["record_count"] = len(records)
        else:
            # Doctor sees consented records
            records = db.query(HealthRecord).join(
                Consent, HealthRecord.id == Consent.record_id
            ).filter(
                Consent.doctor_id == user_id,
                Consent.is_active == True
            ).all()
            result["record_type"] = "consented_records"
            result["record_count"] = len(records)
            
            # Also show active consents
            consents = db.query(Consent).filter(
                Consent.doctor_id == user_id,
                Consent.is_active == True
            ).all()
            
            result["active_consents"] = [
                {
                    "consent_id": c.id,
                    "record_id": c.record_id,
                    "patient_id": c.patient_id,
                    "granted_at": c.granted_at.isoformat() if c.granted_at else None
                } for c in consents
            ]
        
        result["accessible_records"] = [
            {
                "record_id": r.id,
                "file_name": r.file_name,
                "patient_id": r.patient_id,
                "created_at": r.created_at.isoformat() if r.created_at else None
            } for r in records
        ]
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/debug/full-system-status", methods=["GET"])
@jwt_required()
def debug_full_system_status():
    """Comprehensive debug endpoint to see all system status"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        user_role = user.role.value
        
        result = {
            "current_user": {
                "id": user.id,
                "email": user.email,
                "role": user_role,
                "is_active": user.is_active
            },
            "system_status": {}
        }
        
        # Get all users in system
        all_users = db.query(User).all()
        result["system_status"]["all_users"] = [
            {
                "id": u.id,
                "email": u.email,
                "role": u.role.value,
                "is_active": u.is_active
            } for u in all_users
        ]
        
        # Get all doctors
        doctors = db.query(User).filter(User.role == UserRole.DOCTOR).all()
        result["system_status"]["doctors"] = [
            {
                "id": d.id,
                "email": d.email,
                "is_active": d.is_active
            } for d in doctors
        ]
        
        # Get all patients
        patients = db.query(User).filter(User.role == UserRole.PATIENT).all()
        result["system_status"]["patients"] = [
            {
                "id": p.id,
                "email": p.email,
                "is_active": p.is_active
            } for p in patients
        ]
        
        # Get current user's records
        user_records = db.query(HealthRecord).filter(HealthRecord.patient_id == user_id).all()
        result["system_status"]["my_records"] = [
            {
                "id": r.id,
                "file_name": r.file_name,
                "patient_id": r.patient_id,
                "created_at": r.created_at.isoformat() if r.created_at else None
            } for r in user_records
        ]
        
        # Get all consents
        all_consents = db.query(Consent).all()
        result["system_status"]["all_consents"] = [
            {
                "id": c.id,
                "patient_id": c.patient_id,
                "doctor_id": c.doctor_id,
                "record_id": c.record_id,
                "is_active": c.is_active,
                "granted_at": c.granted_at.isoformat() if c.granted_at else None
            } for c in all_consents
        ]
        
        # Check permissions for current user
        from access_control.rbac import get_role_permissions
        result["system_status"]["my_permissions"] = [
            perm.value for perm in get_role_permissions(user_role)
        ]
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/debug/create-doctor-test-data", methods=["POST"])
def create_doctor_test_data():
    """Create test data for doctor access testing"""
    try:
        db = SessionLocal()
        
        # Create test patient
        test_patient = db.query(User).filter(User.email == "patient@test.com").first()
        if not test_patient:
            test_patient = User(
                email="patient@test.com",
                hashed_password=generate_password_hash("password123"),
                role=UserRole.PATIENT,
                is_active=True,
                created_at=datetime.now()
            )
            db.add(test_patient)
            db.commit()
            db.refresh(test_patient)
            print(f"✅ Created test patient: {test_patient.id}")
        
        # Create test doctor
        test_doctor = db.query(User).filter(User.email == "doctor@test.com").first()
        if not test_doctor:
            test_doctor = User(
                email="doctor@test.com", 
                hashed_password=generate_password_hash("password123"),
                role=UserRole.DOCTOR,
                is_active=True,
                created_at=datetime.now()
            )
            db.add(test_doctor)
            db.commit()
            db.refresh(test_doctor)
            print(f"✅ Created test doctor: {test_doctor.id}")
        
        # Create test record for patient
        test_record = HealthRecord(
            patient_id=test_patient.id,
            file_name="test_medical_report.pdf",
            file_size=1024,
            storage_uri="minio://records/test/report.pdf",
            encrypted_key='test_key',
            iv='test_iv', 
            algorithm='AES-256-GCM',
            created_at=datetime.now()
        )
        db.add(test_record)
        db.commit()
        db.refresh(test_record)
        print(f"✅ Created test record: {test_record.id}")
        
        # Create consent for doctor to access the record
        test_consent = Consent(
            patient_id=test_patient.id,
            doctor_id=test_doctor.id,
            record_id=test_record.id,
            wrapped_key='wrapped_key_test',
            is_active=True,
            granted_at=datetime.now()
        )
        db.add(test_consent)
        db.commit()
        
        db.close()
        
        return jsonify({
            "message": "Doctor test data created successfully",
            "patient": {
                "id": test_patient.id,
                "email": test_patient.email
            },
            "doctor": {
                "id": test_doctor.id,
                "email": test_doctor.email  
            },
            "record": {
                "id": test_record.id,
                "file_name": test_record.file_name
            },
            "consent_id": test_consent.id
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/debug/create-test-doctors", methods=["POST"])
def create_test_doctors():
    """Create test doctors if none exist"""
    try:
        db = SessionLocal()
        
        test_doctors = [
            {"email": "dr.smith@hospital.com", "name": "Dr. Smith"},
            {"email": "dr.jones@hospital.com", "name": "Dr. Jones"},
            {"email": "dr.wilson@hospital.com", "name": "Dr. Wilson"}
        ]
        
        created_doctors = []
        for doctor_data in test_doctors:
            existing_doctor = db.query(User).filter(User.email == doctor_data["email"]).first()
            if not existing_doctor:
                new_doctor = User(
                    email=doctor_data["email"],
                    hashed_password=generate_password_hash("password123"),
                    role=UserRole.DOCTOR,
                    is_active=True,
                    created_at=datetime.now()
                )
                db.add(new_doctor)
                created_doctors.append(doctor_data["name"])
        
        db.commit()
        
        return jsonify({
            "message": "Test doctors created if needed",
            "created_doctors": created_doctors,
            "total_doctors_now": db.query(User).filter(User.role == UserRole.DOCTOR).count()
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/debug/permissions-test", methods=["GET"])
@jwt_required()
def debug_permissions_test():
    """Test all permissions for current user"""
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        user_role = user.role.value
        
        # Test each permission
        permissions_test = {
            "user_info": {
                "id": user.id,
                "email": user.email,
                "role": user_role
            },
            "permissions_test": {
                "create_record": has_permission(user_role, Permission.CREATE_RECORD),
                "view_records": has_permission(user_role, Permission.LIST_RECORDS),
                "view_audit_logs": has_permission(user_role, Permission.VIEW_AUDIT_LOGS),
                "view_doctors_list": has_permission(user_role, Permission.VIEW_DOCTORS_LIST),
                "grant_consent": has_permission(user_role, Permission.GRANT_CONSENT),
                "revoke_consent": has_permission(user_role, Permission.REVOKE_CONSENT)
            }
        }
        
        return jsonify(permissions_test), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/debug/status", methods=["GET"])
def debug_status():
    """Comprehensive debug endpoint"""
    db = SessionLocal()
    
    try:
        # Check database tables
        from sqlalchemy import inspect
        inspector = inspect(db.bind)
        tables = inspector.get_table_names()
        
        # Check table counts
        table_counts = {}
        for table in tables:
            if table == 'users':
                table_counts[table] = db.query(User).count()
            elif table == 'health_records':
                table_counts[table] = db.query(HealthRecord).count()
            elif table == 'consents':
                table_counts[table] = db.query(Consent).count()
            elif table == 'audit_logs':
                table_counts[table] = db.query(AuditLog).count()
        
        return jsonify({
            "status": "online",
            "tables": tables,
            "record_counts": table_counts,
            "total_audit_logs": table_counts.get('audit_logs', 0)
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/debug-check-token", methods=["GET"])
def debug_check_token():
    """Debug endpoint to check token without validation"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return jsonify({"error": "No token provided"}), 401
    
    return jsonify({
        "token_received": bool(token),
        "token_length": len(token),
        "token_prefix": token[:20] + "..." if len(token) > 20 else token
    }), 200

@app.route("/debug-audit-no-auth", methods=["GET"])
def debug_audit_no_auth():
    """Debug endpoint - no authentication required"""
    try:
        db = SessionLocal()
        # Count total logs
        total_logs = db.query(AuditLog).count()
        
        # Get some sample logs
        logs = db.query(AuditLog).limit(5).all()
        
        result = []
        for log in logs:
            result.append({
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "timestamp": str(log.timestamp),
                "status": log.status
            })
        
        db.close()
        return jsonify({
            "total_logs_in_database": total_logs,
            "sample_logs": result
        }), 200
        
    except Exception as e:
        return jsonify({"msg": "Failed to fetch audit logs", "error": str(e)}), 500

@app.route("/debug/create-test-data", methods=["POST"])
def create_test_data():
    """Create comprehensive test data"""
    try:
        db = SessionLocal()
        
        # Create test user if doesn't exist
        test_user = db.query(User).filter(User.email == "test@example.com").first()
        if not test_user:
            from werkzeug.security import generate_password_hash
            test_user = User(
                email="test@example.com",
                hashed_password=generate_password_hash("password123"),
                role=UserRole.PATIENT,
                is_active=True
            )
            db.add(test_user)
            db.commit()
            db.refresh(test_user)
            print(f"✅ Created test user: {test_user.id}")
        
        # Create test audit logs
        from datetime import datetime, timedelta
        import random
        
        actions = ["login", "view_record", "upload_file", "download_file", "view_dashboard"]
        statuses = ["success", "failed"]
        
        test_logs = []
        for i in range(10):
            log = AuditLog(
                user_id=test_user.id,
                action=random.choice(actions),
                ip_address=f"192.168.1.{random.randint(1, 255)}",
                user_agent="Mozilla/5.0 (Test Browser)",
                timestamp=datetime.now() - timedelta(hours=random.randint(1, 24)),
                status=random.choice(statuses)
            )
            test_logs.append(log)
        
        db.bulk_save_objects(test_logs)
        db.commit()
        
        db.close()
        
        return jsonify({
            "message": "Test data created successfully",
            "user_id": test_user.id,
            "logs_created": len(test_logs)
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/debug-db", methods=["GET"])
def debug_db():
    """Check database status"""
    try:
        db = SessionLocal()
        
        # Check tables
        from sqlalchemy import inspect
        inspector = inspect(db.bind)
        tables = inspector.get_table_names()
        
        # Check if we can query each table
        table_status = {}
        for table in tables:
            try:
                if table == 'users':
                    count = db.query(User).count()
                elif table == 'health_records':
                    count = db.query(HealthRecord).count()
                elif table == 'consents':
                    count = db.query(Consent).count()
                elif table == 'audit_logs':
                    count = db.query(AuditLog).count()
                else:
                    count = 0
                table_status[table] = f"✅ Accessible ({count} records)"
            except Exception as e:
                table_status[table] = f"❌ Error: {str(e)}"
        
        db.close()
        
        return jsonify({
            "tables": tables,
            "table_status": table_status
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
