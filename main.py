from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import random
import os
import requests
from dotenv import load_dotenv

load_dotenv()
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")

app = FastAPI(title="Nigeria Solar PAYGO API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

mock_db = {
    "devices": {
        "DEV001": {"secret_key": "abc123xyz", "last_count": 1}
    },
    "history": []
}

class PaymentConfirmation(BaseModel):
     reference: str

class CreatePaymentRequest(BaseModel):
    device_id: str
    amount_paid: float

def generate_token(device_id: str, days: int):
    prefix = "2026"
    random_part = str(random.randint(1000, 9999))
    days_part = str(days).zfill(2)
    checksum = "5"
    return f"{prefix}{random_part}{days_part}{checksum}"

@app.get("/")
def home():
    return {"message": "Solar Backend is Running"}
@app.post("/create-payment")
def create_payment(payment: CreatePaymentRequest):
    if not PAYSTACK_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Paystack secret key not configured")

    reference = f"REF-{random.randint(1000000000, 9999999999)}"

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
    "email": "customer@example.com",
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
        raise HTTPException(status_code=400, detail=data.get("message", "Could not create payment"))

    return {
        "authorization_url": data["data"]["authorization_url"],
        "reference": reference,
    }
@app.post("/verify-payment")
async def verify_payment(data: PaymentConfirmation):
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
    }

    response = requests.get(
        f"https://api.paystack.co/transaction/verify/{data.reference}",
        headers=headers,
    )

    paystack_data = response.json()

    if not paystack_data.get("status"):
        raise HTTPException(status_code=400, detail="Payment verification failed")

    if paystack_data["data"]["status"] != "success":
        raise HTTPException(status_code=400, detail="Payment was not successful")

    metadata = paystack_data["data"].get("metadata", {})
    device_id = metadata.get("device_id")
    amount_paid = metadata.get("amount_paid")

    if device_id not in mock_db["devices"]:
        raise HTTPException(status_code=404, detail="Device not found")

    try:
        amount_paid = int(float(amount_paid))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid Amount Sent")

    if amount_paid == 1000:
        days_to_add = 1
    elif amount_paid == 7000:
        days_to_add = 7
    else:
        raise HTTPException(status_code=400, detail="Invalid Amount Sent")

    if days_to_add < 1:
        raise HTTPException(status_code=400, detail="Amount too low for power")

    token = generate_token(device_id, days_to_add)
       
    mock_db["history"].append({
    "device_id": device_id,
    "amount_paid": amount_paid,
    "reference": data.reference,
    "token": token,
    "days_added": days_to_add,
})

    return {
        "status": "success",
        "token": token,
        "days_added": days_to_add,
        "message": f"Enter this code on your solar device: {token}",
    }
@app.get("/history")
def get_history():
 return {
     "history": mock_db["history"]
    }