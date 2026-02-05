"""Test API server for fuzzing"""

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
import re

app = FastAPI(title="Buggy API", version="1.0.0")

# In-memory "database"
users = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.com"},
}


def _validate_name(v: str) -> str:
    if not v or not v.strip():
        raise ValueError("Name must not be empty")
    if len(v) > 255:
        raise ValueError("Name too long (max 255)")
    if not re.match(r'^[\w\s\-\.]+$', v):
        raise ValueError("Name contains invalid characters")
    return v.strip()


class UserCreate(BaseModel):
    name: str
    email: EmailStr

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        return _validate_name(v)


class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _validate_name(v)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/users")
def list_users():
    return list(users.values())


@app.get("/users/{user_id}", responses={404: {"description": "User not found"}})
def get_user(user_id: int):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    return users[user_id]


@app.post("/users", responses={400: {"description": "Invalid input"}})
def create_user(user: UserCreate):
    # Pydantic validates name/email before reaching here

    new_id = max(users.keys()) + 1
    users[new_id] = {"id": new_id, "name": user.name, "email": user.email}
    return users[new_id]


@app.put(
    "/users/{user_id}",
    responses={
        400: {"description": "Invalid input"},
        404: {"description": "User not found"},
    },
)
def update_user(user_id: int, user: UserUpdate):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")

    if user.name and "crash" in user.name.lower():
        raise HTTPException(status_code=400, detail="Invalid name")

    if user.name:
        users[user_id]["name"] = user.name
    if user.email:
        users[user_id]["email"] = user.email
    return users[user_id]


@app.delete(
    "/users/{user_id}",
    responses={
        401: {"description": "Authentication required"},
        404: {"description": "User not found"},
    },
)
def delete_user(user_id: int, x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")

    del users[user_id]
    return {"deleted": user_id}


@app.get(
    "/admin/stats",
    responses={401: {"description": "Authentication required"}},
)
def admin_stats(x_admin_token: str = Header(None)):
    if x_admin_token != "secret":
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"total_users": len(users)}


# =============================================================
# Buggy endpoints — intentionally broken for fuzz testing
# =============================================================

class OrderCreate(BaseModel):
    product: str
    quantity: int
    note: Optional[str] = None


@app.post("/orders", responses={200: {"description": "Order created"}})
def create_order(order: OrderCreate):
    """Bug: division by zero when quantity is 0"""
    unit_price = 1000
    price_per_item = unit_price / order.quantity  # ZeroDivisionError
    return {"total": price_per_item * order.quantity}


@app.get("/search", responses={200: {"description": "Search results"}})
def search(q: str, limit: int = 10):
    """Bug: crashes on large limit (OOM-style) and empty q"""
    if limit > 1000:
        raise RuntimeError("limit too large, server choked")
    results = [q] * limit
    return {"results": results, "count": len(results)}


@app.post(
    "/webhook",
    responses={200: {"description": "Webhook processed"}},
)
def webhook(payload: dict):
    """Bug: KeyError when expected field is missing"""
    event_type = payload["event"]  # KeyError if no "event" key
    return {"processed": event_type}


@app.get("/compute/{value}", responses={200: {"description": "Computed"}})
def compute(value: int):
    """Bug: negative values cause panic in sqrt-like logic"""
    if value < 0:
        raise RuntimeError(f"Cannot compute sqrt of negative: {value}")
    import math
    return {"result": math.isqrt(value)}


# =============================================================
# New buggy endpoints — added for clean-state detection test
# =============================================================

class PaymentCreate(BaseModel):
    amount: float
    currency: str
    description: Optional[str] = None


@app.post("/payments", responses={200: {"description": "Payment processed"}})
def create_payment(payment: PaymentCreate):
    """Bug 1: amount=0 → ZeroDivisionError in fee calc
    Bug 2: amount<0 not validated → negative fee"""
    fee_rate = 0.03
    fee = (payment.amount * fee_rate)
    installments = int(payment.amount / (fee + payment.amount))  # ZeroDivision when amount=0
    rates = {"USD": 1.0, "EUR": 0.85, "JPY": 110.0}
    converted = payment.amount * rates[payment.currency]  # KeyError on unknown currency
    return {"fee": fee, "installments": installments, "converted": converted}


@app.get(
    "/products/{product_id}/reviews",
    responses={200: {"description": "Product reviews"}},
)
def get_reviews(product_id: int, page: int = 1, sort_by: str = "date"):
    """Bug: page<=0 causes negative index; unknown sort_by → KeyError"""
    all_reviews = [
        {"id": i, "text": f"Review {i}", "rating": (i % 5) + 1, "date": "2024-01-01"}
        for i in range(1, 51)
    ]
    page_size = 10
    start = (page - 1) * page_size  # page=0 → start=-10, page=-1 → start=-20
    end = start + page_size

    sort_keys = {"date": "date", "rating": "rating"}
    key = sort_keys[sort_by]  # KeyError on unknown sort_by

    result = sorted(all_reviews, key=lambda r: r[key])[start:end]
    return {"reviews": result, "page": page, "total": len(all_reviews)}


class ConfigUpdate(BaseModel):
    theme: Optional[dict] = None
    notifications: Optional[dict] = None
    profile: Optional[dict] = None


@app.put("/config", responses={200: {"description": "Config updated"}})
def update_config(config: ConfigUpdate):
    """Bug: accessing nested keys without null check"""
    result = {}
    if config.theme is not None:
        # Bug: assumes 'primary' key exists in theme dict
        result["color"] = config.theme["primary"]  # KeyError
    if config.notifications is not None:
        # Bug: assumes 'email' is bool, crashes if wrong type
        if config.notifications["email"]:  # KeyError if no 'email' key
            result["notify"] = True
    if config.profile is not None:
        # Bug: assumes 'name' key always present
        result["display_name"] = config.profile["name"].upper()  # KeyError or AttributeError
    return {"updated": result}


class TransformRequest(BaseModel):
    values: list
    operation: str


@app.post("/transform", responses={200: {"description": "Transformed"}})
def transform(req: TransformRequest):
    """Bug 1: empty values list → IndexError
    Bug 2: unknown operation → KeyError
    Bug 3: non-numeric values → TypeError on sum/avg"""
    ops = {
        "sum": lambda v: sum(v),
        "avg": lambda v: sum(v) / len(v),  # ZeroDivision on empty
        "first": lambda v: v[0],  # IndexError on empty
        "max": lambda v: max(v),  # ValueError on empty
    }
    fn = ops[req.operation]  # KeyError on unknown operation
    result = fn(req.values)
    return {"result": result, "count": len(req.values)}


@app.get("/report", responses={200: {"description": "Report generated"}})
def generate_report(year: int, month: int = 1):
    """Bug: year out of range crashes datetime; month>12 or month<1 crashes"""
    import datetime
    # Bug: no validation on year/month range
    start = datetime.date(year, month, 1)  # ValueError on invalid date
    if month == 12:
        end = datetime.date(year + 1, 1, 1)  # overflow if year=9999
    else:
        end = datetime.date(year, month + 1, 1)
    days = (end - start).days
    return {"start": str(start), "end": str(end), "days": days}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
