from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
import random
import os
import re
import requests
from dotenv import load_dotenv
from database import engine, Base, get_db
import models
from pwdlib import PasswordHash
import secrets
import hmac
import hashlib
import jwt
from datetime import datetime, timedelta, timezone
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

load_dotenv()
password_hash = PasswordHash.recommended()
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

security = HTTPBearer()
def create_access_token(user_id: int, role: str):
    if not JWT_SECRET_KEY:
        raise HTTPException(
            status_code=500,
            detail="JWT secret key is not configured"
        )

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=JWT_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )

        user_id = int(payload.get("sub"))

    except (jwt.InvalidTokenError, TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token"
        )

    user = db.query(models.User).filter(
        models.User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user
app = FastAPI(title="Nigeria Solar PAYGO API")
Base.metadata.create_all(bind=engine)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "https://imadavid1.github.io,http://localhost:5001,http://localhost:8080",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class PaymentConfirmation(BaseModel):
     reference: str

class CreatePaymentRequest(BaseModel):
    device_id: str
    amount_paid: float = Field(gt=0)

class UserCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str
    password: str = Field(min_length=8, max_length=128)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str):
        return " ".join(value.strip().split())

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str):
        email = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError("Enter a valid email address")
        return email

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str):
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain an uppercase letter")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain a lowercase letter")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain a number")
        return value

class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str):
        return value.strip().lower()

class DeviceCreate(BaseModel):
    device_code: str
    customer_id: int
    device_name: str = "Solar Device"
class DeviceAssignment(BaseModel):
    customer_id: int

class TokenValidationRequest(BaseModel):
    device_id: str
    token: str
class ActivationReportRequest(BaseModel):
    device_id: str
    token: str
    remaining_credit: float
    device_status: str
    signature: str   
def generate_token(device_secret: str, device_id: str, days: int, counter: int):
    message = f"{device_id}:{days}:{counter}".encode()

    digest = hmac.new(
        device_secret.encode(),
        message,
        hashlib.sha256
    ).hexdigest()

    mac = str(int(digest[:12], 16) % 100000000).zfill(8)

    return f"{counter:04d}{days:02d}{mac}"

@app.get("/")
def home():
    return {"message": "Solar Backend is Running"}
@app.post("/users")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(
        models.User.email == user.email
    ).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = models.User(
        name=user.name,
        email=user.email,
        password_hash=password_hash.hash(user.password),
        role="customer",
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "id": new_user.id,
        "name": new_user.name,
        "email": new_user.email,
        "role": new_user.role,
    }
@app.post("/login")
def login_user(login: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(
        models.User.email == login.email
    ).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    try:
        password_ok = password_hash.verify(
            login.password,
            user.password_hash
        )
    except Exception:
        password_ok = False

    if not password_ok:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(
        user_id=user.id,
        role=user.role
)

    return {
        "status": "success",
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role
}

@app.post("/devices")
def create_device(
    device: DeviceCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if current_user.role != "provider":
      raise HTTPException(
        status_code=403,
        detail="Provider access required"
    )
    customer = db.query(models.User).filter(
        models.User.id == device.customer_id
    ).first()

    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    if customer.role != "customer":
        raise HTTPException(status_code=400, detail="Device owner must be a customer")

    existing_device = db.query(models.Device).filter(
        models.Device.device_code == device.device_code
    ).first()

    if existing_device:
        raise HTTPException(status_code=400, detail="Device already registered")

    new_device = models.Device(
        device_code=device.device_code,
        customer_id=device.customer_id,
        device_name=device.device_name,
        device_secret=secrets.token_hex(32),
        token_counter=0,
    )

    db.add(new_device)
    db.commit()
    db.refresh(new_device)

    return {
        "id": new_device.id,
        "device_code": new_device.device_code,
        "customer_id": new_device.customer_id,
        "device_name": new_device.device_name,
        "status": new_device.status,
        "remaining_credit": new_device.remaining_credit,
    }
@app.patch("/provider/devices/{device_id}/assign")
def assign_device(
    device_id: int,
    assignment: DeviceAssignment,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if current_user.role != "provider":
        raise HTTPException(
            status_code=403,
            detail="Provider access required",
        )

    device_record = db.query(models.Device).filter(
        models.Device.id == device_id
    ).first()

    if not device_record:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    customer = db.query(models.User).filter(
        models.User.id == assignment.customer_id,
        models.User.role == "customer",
    ).first()

    if not customer:
        raise HTTPException(
            status_code=404,
            detail="Customer not found",
        )

    device_record.customer_id = customer.id
    db.commit()
    db.refresh(device_record)

    return {
        "message": "Device assigned successfully",
        "device_id": device_record.id,
        "customer_id": customer.id,
    }

@app.get("/users/{user_id}/devices")
def get_user_devices(
    user_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if current_user.role != "customer":
        raise HTTPException(
            status_code=403,
            detail="Customer access required"
    )

    if current_user.id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You can only access your own devices"
    )
    user = db.query(models.User).filter(
        models.User.id == user_id
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    devices = db.query(models.Device).filter(
        models.Device.customer_id == user_id
    ).all()

    return {
        "user_id": user.id,
        "name": user.name,
        "devices": [
            {
                "id": device.id,
                "device_code": device.device_code,
                "device_name": device.device_name,
                "status": device.status,
                "remaining_credit": device.remaining_credit,
            }
            for device in devices
        ],
    }
@app.get("/provider/customers")
def get_provider_customers(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if current_user.role != "provider":
        raise HTTPException(
            status_code=403,
            detail="Provider access required"
        )

    customers = db.query(models.User).filter(
        models.User.role == "customer"
    ).all()

    return {
        "customers": [
            {
                "id": customer.id,
                "name": customer.name,
                "email": customer.email
            }
            for customer in customers
        ]
    }
@app.get("/provider/devices")
def get_provider_devices(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if current_user.role != "provider":
        raise HTTPException(
            status_code=403,
            detail="Provider access required"
        )

    devices = db.query(models.Device).all()

    return {
        "devices": [
            {
                "id": device.id,
                "device_code": device.device_code,
                "customer_id": device.customer_id,
                "device_name": device.device_name,
                "status": device.status,
                "remaining_credit": device.remaining_credit
            }
            for device in devices
        ]
    }
@app.get("/provider/payments")
def get_provider_payments(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if current_user.role != "provider":
        raise HTTPException(
            status_code=403,
            detail="Provider access required"
        )

    payments = db.query(models.Payment).order_by(
        models.Payment.created_at.desc()
    ).all()

    return {
        "payments": [
            {
                "id": payment.id,
                "reference": payment.reference,
                "customer_id": payment.customer_id,
                "device_id": payment.device_id,
                "amount": payment.amount,
                "status": payment.status,
                "fulfilled": payment.fulfilled,
                "created_at": payment.created_at
            }
            for payment in payments
        ]
    }
@app.get("/provider/summary")
def get_provider_summary(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if current_user.role != "provider":
        raise HTTPException(
            status_code=403,
            detail="Provider access required"
        )

    total_customers = db.query(models.User).filter(
        models.User.role == "customer"
    ).count()

    total_devices = db.query(models.Device).count()

    active_devices = db.query(models.Device).filter(
        models.Device.status == "active"
    ).count()

    locked_devices = db.query(models.Device).filter(
        models.Device.status == "locked"
    ).count()

    successful_payments = db.query(models.Payment).filter(
        models.Payment.status == "success"
    ).count()

    return {
        "total_customers": total_customers,
        "total_devices": total_devices,
        "active_devices": active_devices,
        "locked_devices": locked_devices,
        "successful_payments": successful_payments
    }
@app.get("/customers/{user_id}/payments")
def get_customer_payments(
    user_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if current_user.role != "customer":
        raise HTTPException(
            status_code=403,
            detail="Customer access required"
        )

    if current_user.id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You can only access your own payments"
        )

    payments = db.query(models.Payment).filter(
        models.Payment.customer_id == user_id
    ).order_by(
        models.Payment.created_at.desc()
    ).all()

    return {
        "payments": [
            {
                "id": payment.id,
                "reference": payment.reference,
                "device_id": payment.device_id,
                "amount": payment.amount,
                "status": payment.status,
                "fulfilled": payment.fulfilled,
                "created_at": payment.created_at
            }
            for payment in payments
        ]
    }
@app.get("/customers/{user_id}/summary")
def get_customer_summary(
    user_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if current_user.role != "customer":
        raise HTTPException(
            status_code=403,
            detail="Customer access required"
        )

    if current_user.id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You can only access your own summary"
        )

    devices = db.query(models.Device).filter(
        models.Device.customer_id == user_id
    ).all()

    total_devices = len(devices)

    active_devices = sum(
        1 for device in devices
        if device.status == "active"
    )

    locked_devices = sum(
        1 for device in devices
        if device.status == "locked"
    )

    total_remaining_credit = sum(
        device.remaining_credit for device in devices
    )

    successful_payments = db.query(models.Payment).filter(
        models.Payment.customer_id == user_id,
        models.Payment.status == "success"
    ).count()

    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "locked_devices": locked_devices,
        "remaining_credit": total_remaining_credit,
        "successful_payments": successful_payments
    }
@app.get("/customers/{user_id}/tokens")
def get_customer_tokens(
    user_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if current_user.role != "customer":
        raise HTTPException(
            status_code=403,
            detail="Customer access required"
        )

    if current_user.id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You can only access your own tokens"
        )

    devices = db.query(models.Device).filter(
        models.Device.customer_id == user_id
    ).all()

    device_ids = [device.id for device in devices]

    tokens = db.query(models.Token).filter(
        models.Token.device_id.in_(device_ids)
    ).all()

    return {
        "tokens": [
            {
                "id": token.id,
                "payment_id": token.payment_id,
                "device_id": token.device_id,
                "token": token.token_value,
                "credit_days": token.credit_days,
                "token_counter": token.token_counter,
                "used": token.used
            }
            for token in tokens
        ]
    }
@app.post("/create-payment")
def create_payment(
    payment: CreatePaymentRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if not PAYSTACK_SECRET_KEY:
        raise HTTPException(
            status_code=500,
            detail="Paystack secret key not configured"
        )

    reference = f"REF-{random.randint(1000000000, 9999999999)}"

    device = db.query(models.Device).filter(
        models.Device.device_code == payment.device_id
    ).first()

    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found"
        )
    if  current_user.role != "customer":
        raise HTTPException(
            status_code=403,
            detail="Customer access required"
    )

    if device.customer_id != current_user.id:
       raise HTTPException(
        status_code=403,
        detail="You can only purchase power for your own device"
    )

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "email": current_user.email,
        "amount": int(payment.amount_paid * 100),
        "currency": "NGN",
        "reference": reference,
        "callback_url": "https://imadavid1.github.io/solar_paygo_app/",
        "metadata": {
            "device_id": payment.device_id,
            "amount_paid": payment.amount_paid,
        },
    }

    response = requests.post(
        "https://api.paystack.co/transaction/initialize",
        headers=headers,
        json=payload,
    )

    data = response.json()

    if not data.get("status"):
        raise HTTPException(
            status_code=400,
            detail=data.get("message", "Could not create payment"),
        )

    new_payment = models.Payment(
        reference=reference,
        customer_id=device.customer_id,
        device_id=device.id,
        amount=payment.amount_paid,
        status="pending",
        fulfilled=False,
    )

    db.add(new_payment)
    db.commit()
    db.refresh(new_payment)

    return {
        "authorization_url": data["data"]["authorization_url"],
        "reference": reference,
    }
     

@app.post("/verify-payment")
async def verify_payment(
    data: PaymentConfirmation,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    payment_record = db.query(models.Payment).filter(
        models.Payment.reference == data.reference
    ).first()

    if not payment_record:
        raise HTTPException(
            status_code=404,
            detail="Payment record not found"
        )

    if current_user.role != "customer":
        raise HTTPException(
            status_code=403,
            detail="Customer access required"
        )

    if payment_record.customer_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You can only verify your own payment"
        )

    if payment_record.fulfilled:
        existing_token = db.query(models.Token).filter(
            models.Token.payment_id == payment_record.id
        ).first()

        if not existing_token:
            raise HTTPException(
                status_code=409,
                detail="Payment was fulfilled but its token was not found"
            )

        return {
            "status": "success",
            "token": existing_token.token_value,
            "days_added": existing_token.credit_days,
            "message": (
                "Payment was already verified. "
                f"Enter this code on your solar device: {existing_token.token_value}"
            ),
        }

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
    }

    response = requests.get(
        f"https://api.paystack.co/transaction/verify/{data.reference}",
        headers=headers,
    )

    paystack_data = response.json()

    if not paystack_data.get("status"):
        raise HTTPException(
            status_code=400,
            detail="Payment verification failed"
        )

    if paystack_data["data"]["status"] != "success":
        raise HTTPException(
            status_code=400,
            detail="Payment was not successful"
        )

    paystack_amount = paystack_data["data"].get("amount")

    if paystack_amount is None:
        raise HTTPException(
            status_code=400,
            detail="Payment amount missing"
        )

    paystack_amount_naira = paystack_amount / 100

    if paystack_amount_naira != payment_record.amount:
        raise HTTPException(
            status_code=400,
            detail="Payment amount does not match"
        )

    device = db.query(models.Device).filter(
        models.Device.id == payment_record.device_id
    ).first()

    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found"
        )

    amount_paid = int(payment_record.amount)

    if amount_paid == 1000:
        days_to_add = 1
    elif amount_paid == 7000:
        days_to_add = 7
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid Amount Sent"
        )

    if days_to_add < 1:
        raise HTTPException(
            status_code=400,
            detail="Amount too low for power"
        )

    next_counter = device.token_counter + 1

    token = generate_token(
        device.device_secret,
        device.device_code,
        days_to_add,
        next_counter
    )

    device.token_counter = next_counter

    new_token = models.Token(
        payment_id=payment_record.id,
        device_id=device.id,
        token_value=token,
        credit_days=days_to_add,
        token_counter=next_counter,
        used=False,
    )

    db.add(new_token)

    payment_record.status = "success"
    payment_record.fulfilled = True

    db.commit()
    db.refresh(payment_record)
    db.refresh(new_token)

    return {
        "status": "success",
        "token": token,
        "days_added": days_to_add,
        "message": f"Enter this code on your solar device: {token}",
    }
@app.post("/validate-token")
def validate_token(
    data: TokenValidationRequest,
    db: Session = Depends(get_db)
):
    device = db.query(models.Device).filter(
        models.Device.device_code == data.device_id
    ).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    token_record = db.query(models.Token).filter(
        models.Token.token_value == data.token
    ).first()

    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid token")

    if token_record.device_id != device.id:
        raise HTTPException(
            status_code=400,
            detail="Token does not belong to this device"
        )

    if token_record.used:
        raise HTTPException(
            status_code=409,
            detail="Token has already been used"
        )
    expected_token = generate_token(
    device.device_secret,
    device.device_code,
    token_record.credit_days,
    token_record.token_counter
)

    if not hmac.compare_digest(expected_token, data.token):
        raise HTTPException(
            status_code=400,
            detail="Token failed cryptographic verification"
        )

    token_record.used = True
    device.status = "active"
    device.remaining_credit += token_record.credit_days

    db.commit()
    db.refresh(token_record)
    db.refresh(device)

    return {
        "status": "success",
        "message": "Token accepted. Solar device activated.",
        "device_id": device.device_code,
        "credit_days_added": token_record.credit_days,
        "remaining_credit": device.remaining_credit,
        "device_status": device.status
    }
@app.post("/activation-report")
def activation_report(
    data: ActivationReportRequest,
    db: Session = Depends(get_db)
):
    device = db.query(models.Device).filter(
        models.Device.device_code == data.device_id
    ).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    message = (
        f"{data.device_id}:{data.token}:"
        f"{data.remaining_credit:g}:{data.device_status}"
    ).encode()

    expected_signature = hmac.new(
        device.device_secret.encode(),
        message,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, data.signature):
        raise HTTPException(
            status_code=403,
            detail="Invalid device signature"
        )

    token_record = db.query(models.Token).filter(
        models.Token.token_value == data.token,
        models.Token.device_id == device.id
    ).first()

    if not token_record:
        raise HTTPException(
            status_code=404,
            detail="Token record not found"
        )

    token_record.used = True
    device.remaining_credit = data.remaining_credit
    device.status = data.device_status.lower()

    db.commit()

    return {
        "status": "success",
        "message": "Activation report recorded"
    }
@app.get("/history")
def get_history(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    if current_user.role != "customer":
        raise HTTPException(
            status_code=403,
            detail="Customer access required"
        )

    payments = db.query(models.Payment).filter(
        models.Payment.customer_id == current_user.id
    ).order_by(
        models.Payment.created_at.desc()
    ).all()

    history = []

    for payment in payments:
        device = db.query(models.Device).filter(
            models.Device.id == payment.device_id
        ).first()

        token_record = db.query(models.Token).filter(
            models.Token.payment_id == payment.id
        ).first()

        history.append({
            "reference": payment.reference,
            "device_id": device.device_code if device else None,
            "amount_paid": payment.amount,
            "status": payment.status,
            "token": token_record.token_value if token_record else None,
            "days_added": token_record.credit_days if token_record else None,
            "used": token_record.used if token_record else None,
            "created_at": payment.created_at,
        })

    return {"history": history}
