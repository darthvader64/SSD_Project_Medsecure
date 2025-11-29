from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity
from database.config import SessionLocal
from models.user import User
from .authorization import check_record_access, check_audit_access
from .rbac import has_permission, Permission

def require_permission(permission):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id_str = get_jwt_identity()
            user_id = int(user_id_str)
            
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.id == user_id).first()
                if not user:
                    return jsonify({"msg": "User not found"}), 404
                    
                user_role = user.role.value
                
                if not has_permission(user_role, permission):
                    print(f"❌ Permission denied: {user_role} cannot {permission.value}")
                    return jsonify({"msg": "Insufficient permissions"}), 403
                    
                print(f"✅ Permission granted: {user_role} can {permission.value}")
                return f(*args, **kwargs)
            except Exception as e:
                print(f"💥 Error in require_permission: {str(e)}")
                return jsonify({"msg": "Authorization error", "error": str(e)}), 500
            finally:
                db.close()
        return decorated_function
    return decorator

def require_record_access(action):
    """Decorator to require record access for specific action"""
    def decorator(f):
        @wraps(f)
        def decorated_function(record_id, *args, **kwargs):
            user_id_str = get_jwt_identity()
            user_id = int(user_id_str)
            
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.id == user_id).first()
                if not user:
                    return jsonify({"msg": "User not found"}), 404
                    
                user_role = user.role.value
                
                has_access, reason = check_record_access(user_id, user_role, record_id, action)
                
                if not has_access:
                    print(f"❌ Record access denied: {reason}")
                    return jsonify({"msg": f"Access denied: {reason}"}), 403
                    
                print(f"✅ Record access granted: {reason}")
                return f(record_id, *args, **kwargs)
            except Exception as e:
                print(f"💥 Error in require_record_access: {str(e)}")
                return jsonify({"msg": "Authorization error", "error": str(e)}), 500
            finally:
                db.close()
        return decorated_function
    return decorator