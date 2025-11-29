import os
from functools import wraps

from flask import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database.config import SessionLocal
from models.user import User

# -------------------------------------------------------------------
# Simple admin model:
# One special email address gets "admin" powers (for viewing system
# debug info, all audit logs, etc.). Everyone else is treated as a
# normal user.
#
# You can override this from .env:
#   ADMIN_EMAIL=admin@medsecure.local
# -------------------------------------------------------------------
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@medsecure.local")


def is_admin_user(user: User | None) -> bool:
  """Return True if the given user is the hard-coded admin."""
  if not user:
      return False
  return user.email.lower() == ADMIN_EMAIL.lower()


def admin_only(fn):
  """
  Decorator for routes that should only be visible to the admin user.
  Uses JWT to get the current user and checks their email against
  ADMIN_EMAIL.
  """
  @wraps(fn)
  @jwt_required()
  def wrapper(*args, **kwargs):
      db = SessionLocal()
      try:
          user_id = get_jwt_identity()
          user = db.query(User).filter(User.id == user_id).first()
          if not is_admin_user(user):
              return jsonify({"msg": "Admin access required"}), 403
          return fn(*args, **kwargs)
      finally:
          db.close()
  return wrapper


# -------------------------------------------------------------------
# Existing helper functions (unchanged behaviour)
# -------------------------------------------------------------------
def get_user_permissions(user_id):
    """Get all permissions for a specific user"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            from .rbac import get_role_permissions
            return get_role_permissions(user.role.value)
        return []
    finally:
        db.close()


def can_user_access_record(user_id, record_id, action):
    """Check if user can access a record"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False

        from .authorization import check_record_access
        has_access, reason = check_record_access(
            user_id,
            user.role.value,
            record_id,
            action,
        )
        return has_access
    finally:
        db.close()
