from sqlalchemy import (
    Column,
    Index,
    Integer,
    String,
    Boolean,
    
    ForeignKey,
    Enum,
    DECIMAL,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
import enum

Base = declarative_base()


class AuthenticationTypeEnum(enum.Enum):
    phone = "phone"
    google = "google"
    apple = "apple"
    email = "email"


class User(Base):
    __tablename__ = "user"

    # Status constants
    STATUS_DEACTIVE = 0
    STATUS_ACTIVE = 1
    STATUS_REGISTER = 2

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=True)
    mobile = Column(String(20), nullable=True)
    country_code = Column(String(10), nullable=True)
    email_verification_code = Column(String(10), nullable=True)
    is_verified = Column(Boolean, default=False)
    profile = Column(String(255), nullable=True)  # Path to image file stored as string
    balance = Column(DECIMAL(10, 2), default=0)
    referral_code = Column(String(10), nullable=True)
    friends_code = Column(String(10), nullable=True)
    type = Column(Enum(AuthenticationTypeEnum), default=AuthenticationTypeEnum.email)
    status = Column(Integer, default=STATUS_ACTIVE)

    def to_dict(self):
        """Convert user object to a dictionary for API response"""
        return {
            "id": self.id,
            "name": self.name,
            "email": self.country_code,  # Adjust as per your application's data needs
            "country_code": self.country_code or "",
            "mobile": self.mobile or "",
            "profile": self.profile,
            "balance": float(self.balance),
            "referral_code": self.referral_code or "",
            "status": self.status,
            "type": self.type.value,
        }


class UserToken(Base):
    __tablename__ = "user_token"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=True)
    type = Column(String(20), default="customer")
    fcm_token = Column(String(255), nullable=False)
    platform = Column(String(20), nullable=True)

    # Constraints and Indexes
    __table_args__ = (
        UniqueConstraint("fcm_token", name="unique_fcm_token"),
        Index("idx_user", "user_id"),
    )

    def __str__(self):
        user_identifier = f"User ID {self.user_id}" if self.user_id else "No User"
        return f"Token for {user_identifier} ({self.platform or 'Unknown Platform'}) {self.fcm_token[:20]}..."
