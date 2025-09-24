from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "certs.db"
FRONTEND_DIR = BASE_DIR.parent / "frontend"
INDEX_FILE = FRONTEND_DIR / "index.html"
CFSSL_ENDPOINT = os.getenv(
    "CFSSL_ENDPOINT", "http://localhost:8888/api/v1/cfssl/newcert"
)
VALIDITY_OPTIONS_DAYS = {
    "1y": 365,
    "3y": 365 * 3,
    "5y": 365 * 5,
    "10y": 365 * 10,
}


def init_db() -> None:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cn TEXT NOT NULL,
                sans TEXT NOT NULL,
                serial_number TEXT,
                profile TEXT,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                certificate_pem TEXT NOT NULL,
                private_key_pem TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        try:
            conn.execute(
                "ALTER TABLE certificates ADD COLUMN validity_days INTEGER"
            )
        except sqlite3.OperationalError:
            # Column already exists
            pass
        conn.commit()


@contextmanager
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


class CertCreate(BaseModel):
    cn: str = Field(..., description="Common Name")
    sans: List[str] = Field(default_factory=list, description="Subject Alternative Names")
    profile: Optional[str] = Field(default=None, description="CFSSL profile name")
    country: Optional[str] = Field(default=None, description="Country code")
    organization: Optional[str] = Field(default=None, description="Organization name")
    organizational_unit: Optional[str] = Field(default=None, description="Organizational unit")
    locality: Optional[str] = Field(default=None, description="City or locality")
    province: Optional[str] = Field(default=None, description="State or province")
    key_algo: str = Field(default="rsa", description="Key algorithm")
    key_size: int = Field(default=2048, description="Key size in bits")
    validity_option: str = Field(
        default="1y",
        description="Validity preset: 1y, 3y, 5y, 10y, custom",
    )
    validity_days: Optional[int] = Field(
        default=None,
        description="Custom validity in days when validity_option=custom",
        ge=1,
    )


class CertOut(BaseModel):
    id: int
    cn: str
    sans: List[str]
    serial_number: Optional[str]
    profile: Optional[str]
    issued_at: datetime
    expires_at: datetime
    status: str
    certificate_pem: str
    has_private_key: bool
    validity_days: Optional[int]


class CertCreateResponse(CertOut):
    private_key_pem: str


app = FastAPI(title="Internal PKI Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    if not INDEX_FILE.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return HTMLResponse(INDEX_FILE.read_text(encoding="utf-8"))


def resolve_validity_days(payload: CertCreate) -> int:
    option = (payload.validity_option or "1y").lower()
    if option in VALIDITY_OPTIONS_DAYS:
        return VALIDITY_OPTIONS_DAYS[option]
    if option == "custom":
        if not payload.validity_days or payload.validity_days <= 0:
            raise HTTPException(
                status_code=400,
                detail="请提供大于 0 的自定义有效期天数",
            )
        return payload.validity_days
    raise HTTPException(status_code=400, detail="无效的有效期选项")


@app.get("/certs", response_model=List[CertOut])
def list_certs() -> List[CertOut]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, cn, sans, serial_number, profile, issued_at, expires_at, validity_days, status, certificate_pem,
                   CASE WHEN private_key_pem IS NULL OR private_key_pem = '' THEN 0 ELSE 1 END AS has_private_key
            FROM certificates
            ORDER BY id DESC
            """
        ).fetchall()

    certs: List[CertOut] = []
    for row in rows:
        certs.append(
            CertOut(
                id=row["id"],
                cn=row["cn"],
                sans=json.loads(row["sans"]),
                serial_number=row["serial_number"],
                profile=row["profile"],
                issued_at=datetime.fromisoformat(row["issued_at"]),
                expires_at=datetime.fromisoformat(row["expires_at"]),
                status=row["status"],
                certificate_pem=row["certificate_pem"],
                has_private_key=bool(row["has_private_key"]),
                validity_days=row["validity_days"],
            )
        )
    return certs


@app.post("/certs", response_model=CertCreateResponse)
def create_cert(payload: CertCreate) -> CertCreateResponse:
    issued_at = datetime.utcnow()
    validity_days = resolve_validity_days(payload)
    expires_at = issued_at + timedelta(days=validity_days)

    names: List[Dict[str, str]] = []
    name_entry: Dict[str, str] = {}
    if payload.country:
        name_entry["C"] = payload.country
    if payload.province:
        name_entry["ST"] = payload.province
    if payload.locality:
        name_entry["L"] = payload.locality
    if payload.organization:
        name_entry["O"] = payload.organization
    if payload.organizational_unit:
        name_entry["OU"] = payload.organizational_unit
    if name_entry:
        names.append(name_entry)

    cfssl_request: Dict[str, Any] = {
        "request": {
            "CN": payload.cn,
            "hosts": payload.sans or [payload.cn],
            "key": {
                "algo": payload.key_algo,
                "size": payload.key_size,
            },
        }
    }
    if names:
        cfssl_request["request"]["names"] = names
    if payload.profile:
        cfssl_request["profile"] = payload.profile

    try:
        response = requests.post(CFSSL_ENDPOINT, json=cfssl_request, timeout=10)
    except requests.RequestException as exc:  # pragma: no cover
        raise HTTPException(status_code=502, detail=f"Failed to reach CFSSL: {exc}")

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"CFSSL error: {response.text}")

    body = response.json()
    if not body.get("success"):
        raise HTTPException(status_code=502, detail=body.get("errors", "CFSSL request failed"))

    result = body.get("result", {})
    certificate_pem = result.get("certificate")
    private_key_pem = result.get("private_key")
    serial_number = result.get("serial_number")

    if not certificate_pem or not private_key_pem:
        raise HTTPException(status_code=500, detail="CFSSL response missing certificate or key")

    with get_db() as conn:
        cur = conn.execute(
            """
            INSERT INTO certificates (
                cn,
                sans,
                serial_number,
                profile,
                issued_at,
                expires_at,
                validity_days,
                status,
                certificate_pem,
                private_key_pem,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.cn,
                json.dumps(payload.sans or [payload.cn]),
                serial_number,
                payload.profile,
                issued_at.isoformat(),
                expires_at.isoformat(),
                validity_days,
                "valid",
                certificate_pem,
                private_key_pem,
                issued_at.isoformat(),
            ),
        )
        cert_id = cur.lastrowid

    return CertCreateResponse(
        id=cert_id,
        cn=payload.cn,
        sans=payload.sans or [payload.cn],
        serial_number=serial_number,
        profile=payload.profile,
        issued_at=issued_at,
        expires_at=expires_at,
        status="valid",
        certificate_pem=certificate_pem,
        has_private_key=True,
        validity_days=validity_days,
        private_key_pem=private_key_pem,
    )


def _get_certificate_row(cert_id: int) -> sqlite3.Row:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return row


@app.get("/certs/{cert_id}/download.pem")
def download_pem(cert_id: int) -> StreamingResponse:
    row = _get_certificate_row(cert_id)
    bundle = f"{row['certificate_pem']}\n{row['private_key_pem']}\n"
    filename = f"cert_{cert_id}_{row['cn'].replace('.', '_')}.pem"
    return StreamingResponse(
        iter([bundle.encode("utf-8")]),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/certs/{cert_id}/download.p12")
def download_p12(cert_id: int, password: Optional[str] = None) -> StreamingResponse:
    row = _get_certificate_row(cert_id)
    if not row["private_key_pem"]:
        raise HTTPException(status_code=404, detail="Private key not available")

    certificate = x509.load_pem_x509_certificate(row["certificate_pem"].encode("utf-8"))
    private_key = serialization.load_pem_private_key(
        row["private_key_pem"].encode("utf-8"), password=None
    )

    if password:
        encryption = BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = NoEncryption()

    pkcs12_bytes = serialize_key_and_certificates(
        name=row["cn"].encode("utf-8"),
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=encryption,
    )

    filename = f"cert_{cert_id}_{row['cn'].replace('.', '_')}.p12"
    return StreamingResponse(
        iter([pkcs12_bytes]),
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
