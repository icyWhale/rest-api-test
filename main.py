from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, constr
from typing import Optional, Dict
import base64

app = FastAPI()

# in‐memory storage: key=user_id → {password, nickname, comment}
users: Dict[str, Dict[str, Optional[str]]] = {}

# ─── リクエストモデル ────────────────────────────────────
class SignupReq(BaseModel):
    user_id: constr(min_length=6, max_length=20, pattern="^[a-zA-Z0-9]+$")
    password: constr(min_length=8, max_length=20)

class UpdateReq(BaseModel):
    nickname: Optional[constr(max_length=30)]
    comment:  Optional[constr(max_length=100)]

# ─── Basic 認証ヘルパー ─────────────────────────────────
def basic_auth(authorization: str = Header(None)) -> str:
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(401, detail={"message": "Authentication failed"})
    token = authorization.split()[1]
    try:
        decoded = base64.b64decode(token).decode()
        uid, pw = decoded.split(":", 1)
    except Exception:
        raise HTTPException(401, detail={"message": "Authentication failed"})
    user = users.get(uid)
    if not user or user["password"] != pw:
        raise HTTPException(401, detail={"message": "Authentication failed"})
    return uid

# ─── POST /signup ──────────────────────────────────────
@app.post("/signup")
def signup(req: SignupReq):
    uid, pw = req.user_id, req.password
    if uid in users:
        raise HTTPException(400, detail={
            "message": "Account creation failed",
            "cause": "Already same user_id is used"
        })
    users[uid] = {"password": pw, "nickname": uid, "comment": None}
    return {
        "message": "Account successfully created",
        "user": {"user_id": uid, "nickname": uid}
    }

# ─── GET /users/{user_id} ─────────────────────────────────
@app.get("/users/{user_id}")
def get_user(user_id: str, auth_uid: str = Depends(basic_auth)):
    if user_id not in users:
        raise HTTPException(404, detail={"message": "No user found"})
    u = users[user_id]
    data = {"user_id": user_id, "nickname": u["nickname"]}
    if u["comment"] is not None:
        data["comment"] = u["comment"]
    return {"message": "User details by user_id", "user": data}

# ─── PATCH /users/{user_id} ───────────────────────────────
@app.patch("/users/{user_id}")
def update_user(user_id: str, req: UpdateReq, auth_uid: str = Depends(basic_auth)):
    if user_id not in users:
        raise HTTPException(404, detail={"message": "No user found"})
    if auth_uid != user_id:
        raise HTTPException(403, detail={"message": "No permission for update"})
    if req.nickname is None and req.comment is None:
        raise HTTPException(400, detail={
            "message": "User updation failed",
            "cause": "Required nickname or comment"
        })
    if req.nickname is not None:
        users[user_id]["nickname"] = req.nickname or user_id
    if req.comment is not None:
        users[user_id]["comment"] = req.comment or None
    u = users[user_id]
    return {"message": "User successfully updated", "user": {
        "nickname": u["nickname"],
        "comment": u["comment"]
    }}

# ─── POST /close ────────────────────────────────────────
@app.post("/close")
def close_account(auth_uid: str = Depends(basic_auth)):
    users.pop(auth_uid, None)
    return {"message": "Account and user successfully deleted"}

