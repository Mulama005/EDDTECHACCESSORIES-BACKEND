from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
import json
import os
import jwt
import random
import re
import secrets
import string
from difflib import SequenceMatcher
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# ── OTP Store (in-memory) ──
# { email: { "otp": "123456", "expires": datetime } }
otp_store = {}

# ─────────────────────────────
# INIT
# ─────────────────────────────
load_dotenv()

app = Flask(__name__)
CORS(app,
     origins=[os.getenv("FRONTEND_URL", "http://localhost:5173")],
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# ── DB ──
DATABASE_URL = os.getenv("POSTGRES_URL_NON_POOLING")

if not DATABASE_URL:
    raise RuntimeError("POSTGRES_URL_NON_POOLING is not set in environment variables.")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ── MAIL ──
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

mail = Mail(app)
bcrypt = Bcrypt(app)

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")


# ─────────────────────────────
# PRODUCT LOADING
# ─────────────────────────────

# Maps each JSON filename → category key (must match CATEGORY_ROUTES in React)
FILE_CATEGORY_MAP = {
    "iphoneProducts.json":           "iphone",
    "infinixProducts.json":          "infinix",
    "tecnoProducts.json":            "tecno",
    "samsungProducts.json":          "samsung",
    "headphonesProducts.json":       "headphones",
    "earbudsProducts.json":          "earbuds",
    "earphonesProducts.json":        "earphones",
    "laptopchargersProducts.json":   "laptopchargers",
    "laptopProducts.json":           "laptop",
    "phonechargersProducts.json":    "phonechargers",
    "powerbankProducts.json":        "powerbank",
    "tabletProducts.json":           "tablet",
    "speakersProducts.json":         "speakers",
    "phoneCaseProducts.json":        "phonecases",
    "screenprotectorsProducts.json": "screenprotectors",
}


def load_products():
    """Load all products without category stamping (used by existing code)."""
    all_products = []
    for file_name in FILE_CATEGORY_MAP:
        file_path = os.path.join(DATA_DIR, file_name)
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                products = json.load(file)
                if isinstance(products, list):
                    all_products.extend(products)
                else:
                    print(f"WARNING: {file_name} does not contain a list")
        except FileNotFoundError:
            print(f"FILE NOT FOUND: {file_name}")
        except json.JSONDecodeError as e:
            print(f"INVALID JSON IN: {file_name} — {e}")
        except Exception as e:
            print(f"UNEXPECTED ERROR IN: {file_name} — {e}")
    return all_products


def load_products_with_category():
    """Load all products and stamp each with its category key."""
    all_products = []
    for file_name, category in FILE_CATEGORY_MAP.items():
        file_path = os.path.join(DATA_DIR, file_name)
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                products = json.load(file)
                if isinstance(products, list):
                    for p in products:
                        p["category"] = category
                    all_products.extend(products)
                else:
                    print(f"WARNING: {file_name} does not contain a list")
        except FileNotFoundError:
            print(f"FILE NOT FOUND: {file_name}")
        except json.JSONDecodeError as e:
            print(f"INVALID JSON IN: {file_name} — {e}")
        except Exception as e:
            print(f"UNEXPECTED ERROR IN: {file_name} — {e}")
    return all_products


# ─────────────────────────────
# SEARCH HELPERS
# ─────────────────────────────

def tokenize(text):
    """Lowercase and split into alphanumeric tokens."""
    return re.findall(r"[a-z0-9]+", text.lower())


def fuzzy_score(a, b):
    return SequenceMatcher(None, a, b).ratio()


def product_matches(product, query_tokens):
    name   = product.get("name", "")
    name_l = name.lower()
    tokens = tokenize(name)

    for qt in query_tokens:
        # 1. Direct substring — catches "iphone 15", "note 40 pro", etc.
        if qt in name_l:
            return True
        # 2. Prefix match — catches "infin" → Infinix, "sam" → Samsung
        if any(word.startswith(qt) for word in tokens):
            return True
        # 3. Fuzzy match — catches typos like "samsng", "infenix"
        if any(fuzzy_score(qt, word) >= 0.75 for word in tokens):
            return True
    return False


# ─────────────────────────────
# AUTH DECORATOR
# ─────────────────────────────
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization")
            if not token:
                return jsonify({"error": "Token missing"}), 401
            try:
                token = token.split(" ")[1]
                decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                if decoded["role"] != required_role:
                    return jsonify({"error": "Access denied"}), 403
            except Exception as e:
                print("JWT ERROR:", e)
                return jsonify({"error": "Invalid token"}), 401
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────
# OTP HELPERS
# ─────────────────────────────
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


def build_otp_email(otp):
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:32px 0;">
    <tr><td align="center">
      <table width="500" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <tr>
          <td style="background:#111827;padding:28px 32px;text-align:center;">
            <h1 style="margin:0;font-size:20px;font-weight:700;color:#fff;letter-spacing:-0.5px;">
              EDD TECH<span style="opacity:0.45;">&amp;ACCESSORIES</span>
            </h1>
            <p style="margin:8px 0 0;font-size:11px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1.5px;">
              Two-Factor Authentication
            </p>
          </td>
        </tr>

        <tr>
          <td style="padding:36px 32px;text-align:center;">
            <p style="font-size:15px;color:#374151;margin:0 0 24px;">
              Your one-time login code is:
            </p>

            <div style="display:inline-block;background:#f3f4f6;border:2px dashed #e5e7eb;border-radius:12px;padding:20px 40px;margin-bottom:24px;">
              <span style="font-size:36px;font-weight:700;color:#111827;letter-spacing:10px;">{otp}</span>
            </div>

            <p style="font-size:13px;color:#6b7280;margin:0 0 8px;">
              This code expires in <strong>5 minutes</strong>.
            </p>
            <p style="font-size:13px;color:#6b7280;margin:0;">
              If you didn't request this, please ignore this email.
            </p>
          </td>
        </tr>

        <tr>
          <td style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;">
            <p style="margin:0;font-size:12px;color:#9ca3af;">EDD Tech &amp; Accessories &bull; Nairobi, Kenya</p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


# ─────────────────────────────
# EMAIL HELPERS
# ─────────────────────────────
def build_owner_email(order):
    notes_row = ""
    if order.notes:
        notes_row = f"""
        <tr><td colspan="3" style="padding-top:12px;">
          <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Notes</p>
          <p style="margin:0;font-size:14px;color:#374151;line-height:1.6;border-left:3px solid #111827;padding-left:10px;">{order.notes}</p>
        </td></tr>
        """

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <style>
    @media only screen and (max-width:600px){{
      .container{{width:100%!important;border-radius:0!important;}}
      .body-pad{{padding:24px 16px!important;}}
      .header-pad{{padding:24px 16px!important;}}
      .two-col{{width:100%!important;display:block!important;padding:4px 0!important;}}
      .spacer{{display:none!important;}}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:32px 0;">
    <tr><td align="center" style="padding:0 12px;">
      <table class="container" width="600" cellpadding="0" cellspacing="0"
        style="background:#fff;border-radius:12px;overflow:hidden;max-width:600px;width:100%;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <tr>
          <td class="header-pad" style="background:#111827;padding:28px 32px;text-align:center;">
            <h1 style="margin:0;font-size:22px;font-weight:700;color:#fff;letter-spacing:-0.5px;">
              EDD TECH<span style="opacity:0.45;">&amp;ACCESSORIES</span>
            </h1>
            <p style="margin:8px 0 0;font-size:11px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1.5px;">
              New Order Received
            </p>
          </td>
        </tr>

        <tr>
          <td style="background:#1f2937;padding:12px 32px;text-align:center;">
            <p style="margin:0;font-size:13px;color:#9ca3af;">
              &#128230; You have a new order from your website
            </p>
          </td>
        </tr>

        <tr>
          <td class="body-pad" style="padding:32px;">
            <p style="margin:0 0 24px;font-size:15px;color:#374151;line-height:1.6;">
              Hi <strong>EDD TECH Team</strong>, a new order has just been placed. Here are the details:
            </p>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:6px;">
              <tr>
                <td style="background:#111827;padding:10px 16px;border-radius:8px 8px 0 0;">
                  <p style="margin:0;font-size:11px;color:rgba(255,255,255,0.6);text-transform:uppercase;letter-spacing:1px;">
                    &#128230; Order Details
                  </p>
                </td>
              </tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px;">
              <tr>
                <td style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:0 0 8px 8px;padding:16px;">
                  <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                      <td class="two-col" width="48%" style="padding:4px 8px 4px 0;vertical-align:top;">
                        <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Product</p>
                        <p style="margin:0;font-size:14px;font-weight:600;color:#111827;">{order.product_name}</p>
                      </td>
                      <td class="spacer" width="4%"></td>
                      <td class="two-col" width="48%" style="padding:4px 0 4px 8px;vertical-align:top;">
                        <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Price</p>
                        <p style="margin:0;font-size:14px;font-weight:700;color:#111827;">{order.price}</p>
                      </td>
                    </tr>
                    <tr><td colspan="3" style="padding-top:12px;">
                      <table width="100%" cellpadding="0" cellspacing="0">
                        <tr>
                          <td class="two-col" width="48%" style="padding:4px 8px 4px 0;vertical-align:top;">
                            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Storage</p>
                            <p style="margin:0;font-size:14px;font-weight:600;color:#111827;">{order.storage or "N/A"}</p>
                          </td>
                          <td class="spacer" width="4%"></td>
                          <td class="two-col" width="48%" style="padding:4px 0 4px 8px;vertical-align:top;">
                            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Color</p>
                            <p style="margin:0;font-size:14px;font-weight:600;color:#111827;">{order.color or "N/A"}</p>
                          </td>
                        </tr>
                      </table>
                    </td></tr>
                    <tr><td colspan="3" style="padding-top:12px;">
                      <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Quantity</p>
                      <p style="margin:0;font-size:14px;font-weight:600;color:#111827;">{order.quantity}</p>
                    </td></tr>
                  </table>
                </td>
              </tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:6px;">
              <tr>
                <td style="background:#111827;padding:10px 16px;border-radius:8px 8px 0 0;">
                  <p style="margin:0;font-size:11px;color:rgba(255,255,255,0.6);text-transform:uppercase;letter-spacing:1px;">
                    &#128100; Customer Details
                  </p>
                </td>
              </tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
              <tr>
                <td style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:0 0 8px 8px;padding:16px;">
                  <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                      <td class="two-col" width="48%" style="padding:4px 8px 4px 0;vertical-align:top;">
                        <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Full Name</p>
                        <p style="margin:0;font-size:14px;font-weight:600;color:#111827;">{order.full_name}</p>
                      </td>
                      <td class="spacer" width="4%"></td>
                      <td class="two-col" width="48%" style="padding:4px 0 4px 8px;vertical-align:top;">
                        <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Phone</p>
                        <p style="margin:0;font-size:14px;font-weight:600;color:#111827;word-break:break-all;">{order.phone}</p>
                      </td>
                    </tr>
                    <tr><td colspan="3" style="padding-top:12px;">
                      <table width="100%" cellpadding="0" cellspacing="0">
                        <tr>
                          <td class="two-col" width="48%" style="padding:4px 8px 4px 0;vertical-align:top;">
                            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Email</p>
                            <p style="margin:0;font-size:14px;font-weight:600;color:#111827;word-break:break-all;">{order.email}</p>
                          </td>
                          <td class="spacer" width="4%"></td>
                          <td class="two-col" width="48%" style="padding:4px 0 4px 8px;vertical-align:top;">
                            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Location</p>
                            <p style="margin:0;font-size:14px;font-weight:600;color:#111827;">{order.location}</p>
                          </td>
                        </tr>
                      </table>
                    </td></tr>
                    {notes_row}
                  </table>
                </td>
              </tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0">
              <tr><td align="center">
                <a href="mailto:{order.email}"
                  style="display:inline-block;background:#111827;color:#fff;font-size:14px;font-weight:600;padding:13px 32px;border-radius:8px;text-decoration:none;">
                  Contact {order.full_name} &#8594;
                </a>
              </td></tr>
            </table>
          </td>
        </tr>

        <tr>
          <td style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;">
            <p style="margin:0;font-size:12px;color:#9ca3af;">EDD Tech &amp; Accessories &bull; Nairobi, Kenya</p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def build_customer_email(order):
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <style>
    @media only screen and (max-width:600px){{
      .container{{width:100%!important;border-radius:0!important;}}
      .body-pad{{padding:24px 16px!important;}}
      .header-pad{{padding:24px 16px!important;}}
      .two-col{{width:100%!important;display:block!important;padding:4px 0!important;}}
      .spacer{{display:none!important;}}
      .btn-col{{width:100%!important;display:block!important;padding:4px 0!important;}}
      .btn-spacer{{display:none!important;}}
      .social-td{{display:block!important;padding:4px 0!important;text-align:center!important;}}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:32px 0;">
    <tr><td align="center" style="padding:0 12px;">
      <table class="container" width="600" cellpadding="0" cellspacing="0"
        style="background:#fff;border-radius:12px;overflow:hidden;max-width:600px;width:100%;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <tr>
          <td class="header-pad" style="background:#111827;padding:32px;text-align:center;">
            <h1 style="margin:0 0 6px;font-size:22px;font-weight:700;color:#fff;letter-spacing:-0.5px;">
              EDD TECH<span style="opacity:0.45;">&amp;ACCESSORIES</span>
            </h1>
            <p style="margin:0;font-size:11px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1.5px;">
              Your trusted tech partner in Kenya
            </p>
          </td>
        </tr>

        <tr>
          <td class="body-pad" style="padding:36px 32px 0;text-align:center;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr><td align="center" style="padding-bottom:16px;">
                <table cellpadding="0" cellspacing="0" style="margin:0 auto;">
                  <tr>
                    <td style="width:60px;height:60px;background:#f0fdf4;border-radius:50%;text-align:center;vertical-align:middle;font-size:28px;line-height:60px;">
                      &#10003;
                    </td>
                  </tr>
                </table>
              </td></tr>
              <tr><td align="center">
                <h2 style="margin:0 0 10px;font-size:22px;font-weight:700;color:#111827;">Order Confirmed!</h2>
              </td></tr>
              <tr><td align="center" style="padding:0 8px 28px;">
                <p style="margin:0 auto;font-size:14px;color:#6b7280;line-height:1.7;max-width:420px;">
                  Hi <strong style="color:#111827;">{order.full_name}</strong>, thank you for your order!
                  We've received it and will contact you shortly to confirm delivery details.
                </p>
              </td></tr>
            </table>
          </td>
        </tr>

        <tr>
          <td class="body-pad" style="padding:0 32px 28px;">
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:6px;">
              <tr>
                <td style="background:#111827;padding:10px 16px;border-radius:8px 8px 0 0;">
                  <p style="margin:0;font-size:11px;color:rgba(255,255,255,0.6);text-transform:uppercase;letter-spacing:1px;">
                    &#128230; Your Order Summary
                  </p>
                </td>
              </tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
              <tr>
                <td style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:0 0 8px 8px;padding:16px;">
                  <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                      <td class="two-col" width="48%" style="padding:4px 8px 4px 0;vertical-align:top;">
                        <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Product</p>
                        <p style="margin:0;font-size:14px;font-weight:600;color:#111827;">{order.product_name}</p>
                      </td>
                      <td class="spacer" width="4%"></td>
                      <td class="two-col" width="48%" style="padding:4px 0 4px 8px;vertical-align:top;">
                        <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Total</p>
                        <p style="margin:0;font-size:16px;font-weight:700;color:#111827;">{order.price}</p>
                      </td>
                    </tr>
                    <tr><td colspan="3" style="padding-top:12px;">
                      <table width="100%" cellpadding="0" cellspacing="0">
                        <tr>
                          <td class="two-col" width="30%" style="padding:4px 8px 4px 0;vertical-align:top;">
                            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Storage</p>
                            <p style="margin:0;font-size:13px;font-weight:600;color:#374151;">{order.storage or "N/A"}</p>
                          </td>
                          <td class="spacer" width="4%"></td>
                          <td class="two-col" width="30%" style="padding:4px 8px;vertical-align:top;">
                            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Color</p>
                            <p style="margin:0;font-size:13px;font-weight:600;color:#374151;">{order.color or "N/A"}</p>
                          </td>
                          <td class="spacer" width="4%"></td>
                          <td class="two-col" width="30%" style="padding:4px 0 4px 8px;vertical-align:top;">
                            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Qty</p>
                            <p style="margin:0;font-size:13px;font-weight:600;color:#374151;">{order.quantity}</p>
                          </td>
                        </tr>
                      </table>
                    </td></tr>
                    <tr><td colspan="3" style="padding-top:12px;">
                      <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Delivery Location</p>
                      <p style="margin:0;font-size:13px;font-weight:600;color:#374151;">&#128205; {order.location}</p>
                    </td></tr>
                    <tr><td colspan="3" style="padding-top:12px;">
                      <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Payment Method</p>
                      <p style="margin:0;font-size:13px;font-weight:600;color:#374151;">&#128181; Cash on Delivery</p>
                    </td></tr>
                  </table>
                </td>
              </tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
              <tr>
                <td style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:16px;">
                  <p style="margin:0 0 8px;font-size:12px;color:#92400e;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;">What happens next?</p>
                  <p style="margin:0 0 6px;font-size:13px;color:#78350f;">&#128222; We'll call or WhatsApp you to confirm your order.</p>
                  <p style="margin:0 0 6px;font-size:13px;color:#78350f;">&#128230; Your item will be prepared and shipped to your location.</p>
                  <p style="margin:0;font-size:13px;color:#78350f;">&#128181; Payment is collected on delivery.</p>
                </td>
              </tr>
            </table>

            <p style="margin:0 0 12px;font-size:13px;color:#9ca3af;text-align:center;">Need help? Reach us directly:</p>
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
              <tr>
                <td class="btn-col" width="48%" align="center" style="padding:4px;vertical-align:top;">
                  <a href="https://wa.me/254758743522"
                    style="display:block;background:#25d366;color:#fff;font-size:13px;font-weight:600;padding:12px 0;border-radius:8px;text-decoration:none;text-align:center;">
                    &#128172; WhatsApp Us
                  </a>
                </td>
                <td class="btn-spacer" width="4%"></td>
                <td class="btn-col" width="48%" align="center" style="padding:4px;vertical-align:top;">
                  <a href="tel:0118396533"
                    style="display:block;background:#f3f4f6;color:#111827;font-size:13px;font-weight:600;padding:12px 0;border-radius:8px;text-decoration:none;text-align:center;">
                    &#128222; Call Us
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <tr>
          <td style="padding:0 32px;">
            <hr style="border:none;border-top:1px solid #e5e7eb;margin:0;"/>
          </td>
        </tr>

        <tr>
          <td style="padding:20px 32px;text-align:center;">
            <p style="margin:0 0 12px;font-size:13px;color:#9ca3af;">Follow us</p>
            <table cellpadding="0" cellspacing="0" style="margin:0 auto 16px;">
              <tr>
                <td class="social-td" style="padding:0 4px;">
                  <a href="https://facebook.com/yourpage"
                    style="display:inline-block;background:#1877f2;color:#fff;font-size:12px;font-weight:600;padding:7px 16px;border-radius:6px;text-decoration:none;">
                    Facebook
                  </a>
                </td>
                <td class="social-td" style="padding:0 4px;">
                  <a href="https://instagram.com/yourpage"
                    style="display:inline-block;background:#e1306c;color:#fff;font-size:12px;font-weight:600;padding:7px 16px;border-radius:6px;text-decoration:none;">
                    Instagram
                  </a>
                </td>
                <td class="social-td" style="padding:0 4px;">
                  <a href="https://wa.me/254758743522"
                    style="display:inline-block;background:#25d366;color:#fff;font-size:12px;font-weight:600;padding:7px 16px;border-radius:6px;text-decoration:none;">
                    WhatsApp
                  </a>
                </td>
              </tr>
            </table>
            <p style="margin:0;font-size:11px;color:#d1d5db;">&#169; 2026 EDD Tech &amp; Accessories. Nairobi, Kenya.</p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def build_welcome_email(email):
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <style>
    @media only screen and (max-width:600px){{
      .container{{width:100%!important;border-radius:0!important;}}
      .body-pad{{padding:24px 16px!important;}}
      .header-pad{{padding:24px 16px!important;}}
      .btn-col{{width:100%!important;display:block!important;padding:4px 0!important;}}
      .btn-spacer{{display:none!important;}}
      .social-td{{display:block!important;padding:4px 0!important;text-align:center!important;}}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:32px 0;">
    <tr><td align="center" style="padding:0 12px;">
      <table class="container" width="600" cellpadding="0" cellspacing="0"
        style="background:#fff;border-radius:12px;overflow:hidden;max-width:600px;width:100%;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <tr>
          <td class="header-pad" style="background:#111827;padding:32px;text-align:center;">
            <h1 style="margin:0 0 6px;font-size:22px;font-weight:700;color:#fff;letter-spacing:-0.5px;">
              EDD TECH<span style="opacity:0.45;">&amp;ACCESSORIES</span>
            </h1>
            <p style="margin:0;font-size:11px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1.5px;">
              Your trusted tech partner in Kenya
            </p>
          </td>
        </tr>

        <tr>
          <td class="body-pad" style="padding:36px 32px;text-align:center;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr><td align="center" style="padding-bottom:16px;">
                <table cellpadding="0" cellspacing="0" style="margin:0 auto;">
                  <tr>
                    <td style="width:64px;height:64px;background:#f0fdf4;border-radius:50%;text-align:center;vertical-align:middle;font-size:30px;line-height:64px;">
                      &#127881;
                    </td>
                  </tr>
                </table>
              </td></tr>
              <tr><td align="center">
                <h2 style="margin:0 0 10px;font-size:22px;font-weight:700;color:#111827;">
                  You're subscribed!
                </h2>
              </td></tr>
              <tr><td align="center" style="padding:0 8px 24px;">
                <p style="margin:0 auto;font-size:14px;color:#6b7280;line-height:1.8;max-width:420px;">
                  Welcome to the EDD Tech &amp; Accessories newsletter!
                  You'll be the first to know about new arrivals, exclusive deals, and special offers.
                </p>
              </td></tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0" style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;margin-bottom:24px;">
              <tr>
                <td style="background:#111827;padding:10px 16px;border-radius:10px 10px 0 0;">
                  <p style="margin:0;font-size:11px;color:rgba(255,255,255,0.6);text-transform:uppercase;letter-spacing:1px;">
                    &#127775; What to expect
                  </p>
                </td>
              </tr>
              <tr>
                <td style="padding:16px 20px;">
                  <p style="margin:0 0 10px;font-size:13px;color:#374151;">&#128241; New phone arrivals — iPhones, Tecno, Samsung &amp; more</p>
                  <p style="margin:0 0 10px;font-size:13px;color:#374151;">&#127381; Exclusive subscriber-only discounts</p>
                  <p style="margin:0 0 10px;font-size:13px;color:#374151;">&#128083; Flash sales and seasonal deals</p>
                  <p style="margin:0;font-size:13px;color:#374151;">&#128295; Tech tips and product highlights</p>
                </td>
              </tr>
            </table>

            <a href="{FRONTEND_URL}"
              style="display:inline-block;background:#111827;color:#fff;font-size:14px;font-weight:600;padding:13px 32px;border-radius:8px;text-decoration:none;margin-bottom:24px;">
              Shop Now &#8594;
            </a>

            <hr style="border:none;border-top:1px solid #e5e7eb;margin:0 0 20px;"/>

            <p style="margin:0 0 12px;font-size:13px;color:#9ca3af;">Follow us</p>
            <table cellpadding="0" cellspacing="0" style="margin:0 auto 16px;">
              <tr>
                <td class="social-td" style="padding:0 4px;">
                  <a href="https://facebook.com/yourpage"
                    style="display:inline-block;background:#1877f2;color:#fff;font-size:12px;font-weight:600;padding:7px 16px;border-radius:6px;text-decoration:none;">
                    Facebook
                  </a>
                </td>
                <td class="social-td" style="padding:0 4px;">
                  <a href="https://instagram.com/yourpage"
                    style="display:inline-block;background:#e1306c;color:#fff;font-size:12px;font-weight:600;padding:7px 16px;border-radius:6px;text-decoration:none;">
                    Instagram
                  </a>
                </td>
                <td class="social-td" style="padding:0 4px;">
                  <a href="https://wa.me/254758743522"
                    style="display:inline-block;background:#25d366;color:#fff;font-size:12px;font-weight:600;padding:7px 16px;border-radius:6px;text-decoration:none;">
                    WhatsApp
                  </a>
                </td>
              </tr>
            </table>
            <p style="margin:0;font-size:11px;color:#d1d5db;">&#169; 2026 EDD Tech &amp; Accessories. Nairobi, Kenya.</p>
            <p style="margin:6px 0 0;font-size:11px;color:#d1d5db;">
              <a href="{FRONTEND_URL}/unsubscribe" style="color:#9ca3af;text-decoration:underline;">Unsubscribe</a>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def build_marketing_email(product_name, product_description, product_price, product_image, product_link, cta_text="Shop Now"):
    image_block = ""
    if product_image:
        image_block = f"""
        <tr>
          <td style="padding:0 0 20px;">
            <img src="{product_image}" alt="{product_name}"
              style="width:100%;max-width:400px;border-radius:10px;margin:20px 0;"/>
          </td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <style>
    @media only screen and (max-width:600px){{
      .container{{width:100%!important;border-radius:0!important;}}
      .body-pad{{padding:24px 16px!important;}}
      .header-pad{{padding:24px 16px!important;}}
      .social-td{{display:block!important;padding:4px 0!important;text-align:center!important;}}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:32px 0;">
    <tr><td align="center" style="padding:0 12px;">
      <table class="container" width="600" cellpadding="0" cellspacing="0"
        style="background:#fff;border-radius:12px;overflow:hidden;max-width:600px;width:100%;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <tr>
          <td class="header-pad" style="background:#111827;padding:28px 32px;text-align:center;">
            <h1 style="margin:0 0 6px;font-size:22px;font-weight:700;color:#fff;letter-spacing:-0.5px;">
              EDD TECH<span style="opacity:0.45;">&amp;ACCESSORIES</span>
            </h1>
            <p style="margin:0;font-size:11px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1.5px;">
              New Arrival &#127381;
            </p>
          </td>
        </tr>

        <tr>
          <td style="background:#1f2937;padding:12px 32px;text-align:center;">
            <p style="margin:0;font-size:13px;color:#9ca3af;">
              &#127381; Hot new product just dropped — exclusively for subscribers
            </p>
          </td>
        </tr>

        <tr>
          <td class="body-pad" style="padding:32px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              {image_block}
              <tr>
                <td style="padding-bottom:8px;">
                  <p style="margin:0;font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;">Featured Product</p>
                </td>
              </tr>
              <tr>
                <td style="padding-bottom:12px;">
                  <h2 style="margin:0;font-size:24px;font-weight:700;color:#111827;letter-spacing:-0.5px;">{product_name}</h2>
                </td>
              </tr>
              <tr>
                <td style="padding-bottom:20px;">
                  <p style="margin:0;font-size:14px;color:#6b7280;line-height:1.8;">{product_description}</p>
                </td>
              </tr>
              <tr>
                <td style="padding-bottom:24px;">
                  <table cellpadding="0" cellspacing="0">
                    <tr>
                      <td style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:14px 20px;">
                        <p style="margin:0 0 2px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;">Price</p>
                        <p style="margin:0;font-size:22px;font-weight:700;color:#111827;">{product_price}</p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
              <tr>
                <td align="center" style="padding-bottom:28px;">
                  <a href="{product_link}"
                    style="display:inline-block;background:#111827;color:#fff;font-size:14px;font-weight:600;padding:14px 40px;border-radius:8px;text-decoration:none;">
                    {cta_text} &#8594;
                  </a>
                </td>
              </tr>
              <tr>
                <td>
                  <table width="100%" cellpadding="0" cellspacing="0" style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;">
                    <tr>
                      <td style="padding:14px 16px;">
                        <p style="margin:0 0 6px;font-size:12px;color:#92400e;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;">
                          &#128230; Order via WhatsApp
                        </p>
                        <p style="margin:0;font-size:13px;color:#78350f;">
                          Message us directly on
                          <a href="https://wa.me/254758743522" style="color:#78350f;font-weight:600;">WhatsApp</a>
                          or call <strong>0118396533</strong> to place your order.
                        </p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <tr>
          <td style="padding:0 32px;">
            <hr style="border:none;border-top:1px solid #e5e7eb;margin:0;"/>
          </td>
        </tr>

        <tr>
          <td style="padding:20px 32px;text-align:center;">
            <p style="margin:0 0 12px;font-size:13px;color:#9ca3af;">Follow us</p>
            <table cellpadding="0" cellspacing="0" style="margin:0 auto 16px;">
              <tr>
                <td class="social-td" style="padding:0 4px;">
                  <a href="https://facebook.com/yourpage"
                    style="display:inline-block;background:#1877f2;color:#fff;font-size:12px;font-weight:600;padding:7px 16px;border-radius:6px;text-decoration:none;">
                    Facebook
                  </a>
                </td>
                <td class="social-td" style="padding:0 4px;">
                  <a href="https://instagram.com/yourpage"
                    style="display:inline-block;background:#e1306c;color:#fff;font-size:12px;font-weight:600;padding:7px 16px;border-radius:6px;text-decoration:none;">
                    Instagram
                  </a>
                </td>
                <td class="social-td" style="padding:0 4px;">
                  <a href="https://wa.me/254758743522"
                    style="display:inline-block;background:#25d366;color:#fff;font-size:12px;font-weight:600;padding:7px 16px;border-radius:6px;text-decoration:none;">
                    WhatsApp
                  </a>
                </td>
              </tr>
            </table>
            <p style="margin:0;font-size:11px;color:#d1d5db;">&#169; 2026 EDD Tech &amp; Accessories. Nairobi, Kenya.</p>
            <p style="margin:6px 0 0;font-size:11px;color:#d1d5db;">
              You're receiving this because you subscribed on our website. &nbsp;
              <a href="{FRONTEND_URL}/unsubscribe" style="color:#9ca3af;text-decoration:underline;">Unsubscribe</a>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def build_contact_owner_email(name, email, phone, subject, message):
    return f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" style="padding:30px 0;">
<tr><td align="center">
<table width="600" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
  <tr>
    <td style="background:#111827;padding:28px;text-align:center;">
      <h1 style="margin:0;color:#fff;">EDD TECH<span style="opacity:.4;">&amp;ACCESSORIES</span></h1>
      <p style="color:#9ca3af;font-size:12px;">&#128233; New Contact Message</p>
    </td>
  </tr>
  <tr>
    <td style="padding:30px;">
      <p style="font-size:15px;color:#374151;">You've received a new message from your website:</p>
      <table width="100%" style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:16px;">
        <tr>
          <td>
            <p><strong>Name:</strong> {name}</p>
            <p><strong>Email:</strong> {email}</p>
            <p><strong>Phone:</strong> {phone or "N/A"}</p>
            <p><strong>Subject:</strong> {subject or "General Inquiry"}</p>
          </td>
        </tr>
      </table>
      <br/>
      <table width="100%" style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:16px;">
        <tr>
          <td>
            <p style="font-size:12px;color:#9ca3af;text-transform:uppercase;">Message</p>
            <p style="font-size:14px;color:#374151;line-height:1.6;">{message}</p>
          </td>
        </tr>
      </table>
      <br/>
      <div style="text-align:center;">
        <a href="mailto:{email}"
           style="background:#111827;color:#fff;padding:12px 25px;border-radius:8px;text-decoration:none;font-weight:600;">
           Reply to {name} &rarr;
        </a>
      </div>
    </td>
  </tr>
  <tr>
    <td style="text-align:center;padding:15px;background:#f9fafb;font-size:12px;color:#9ca3af;">
      EDD Tech &amp; Accessories &bull; Nairobi, Kenya
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>"""


def build_contact_customer_email(name, subject):
    return f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" style="padding:30px 0;">
<tr><td align="center">
<table width="600" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
  <tr>
    <td style="background:#111827;padding:32px;text-align:center;">
      <h1 style="margin:0;color:#fff;">EDD TECH<span style="opacity:.4;">&amp;ACCESSORIES</span></h1>
      <p style="color:#9ca3af;font-size:12px;">We've received your message</p>
    </td>
  </tr>
  <tr>
    <td style="padding:32px;text-align:center;">
      <div style="font-size:40px;">&#128233;</div>
      <h2 style="margin:10px 0;color:#111827;">Thank You, {name}!</h2>
      <p style="color:#6b7280;font-size:14px;line-height:1.7;">We truly appreciate you reaching out to us.</p>
      <p style="color:#374151;font-size:14px;line-height:1.7;">
        Your message regarding <strong>"{subject or 'your inquiry'}"</strong> has been received.
      </p>
      <br/>
      <table width="100%" style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:16px;">
        <tr>
          <td>
            <p style="margin:0;font-size:13px;color:#92400e;">
              &#128222; Our team will contact you shortly via phone or email.
            </p>
          </td>
        </tr>
      </table>
      <br/>
      <a href="{FRONTEND_URL}"
         style="display:inline-block;background:#111827;color:#fff;padding:12px 30px;border-radius:8px;text-decoration:none;font-weight:600;">
         Back to Store &rarr;
      </a>
      <br/><br/>
      <p style="font-size:13px;color:#9ca3af;">Need urgent help? Reach us directly:</p>
      <a href="https://wa.me/254758743522"
         style="display:inline-block;background:#25d366;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;">
         WhatsApp Us
      </a>
    </td>
  </tr>
  <tr>
    <td style="text-align:center;padding:15px;background:#f9fafb;font-size:12px;color:#9ca3af;">
      &copy; 2026 EDD Tech &amp; Accessories &bull; Nairobi, Kenya
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>"""


# ─────────────────────────────
# MODELS
# ─────────────────────────────
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default="user")
    agreed_to_policy = db.Column(db.Boolean, default=False)
    agreed_at = db.Column(db.DateTime)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), default="Pending")
    product_name = db.Column(db.String(200))
    storage = db.Column(db.String(100))
    color = db.Column(db.String(100))
    quantity = db.Column(db.Integer)
    price = db.Column(db.String(50))
    full_name = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(200))
    location = db.Column(db.String(200))
    company = db.Column(db.String(200))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Subscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    subscribed_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)


class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(300))
    preheader = db.Column(db.String(300))
    product_name = db.Column(db.String(200))
    product_description = db.Column(db.Text)
    product_price = db.Column(db.String(100))
    product_image = db.Column(db.String(500))
    cta_text = db.Column(db.String(100))
    audience = db.Column(db.String(50))
    sent_count = db.Column(db.Integer, default=0)
    failed_count = db.Column(db.Integer, default=0)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)


class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    subject = db.Column(db.String(200))
    message = db.Column(db.Text)
    status = db.Column(db.String(50), default="New")
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ─────────────────────────────
# CREATE TABLES ON STARTUP
# ─────────────────────────────
with app.app_context():
    db.create_all()


# ─────────────────────────────
# HELPERS
# ─────────────────────────────
def get_current_user():
    auth = request.headers.get("Authorization")
    if not auth or " " not in auth:
        return None
    try:
        token = auth.split(" ")[1]
        decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return User.query.get(decoded["user_id"])
    except Exception:
        return None


# ─────────────────────────────
# SUBSCRIPTION ROUTES
# ─────────────────────────────
@app.route("/api/subscribe", methods=["POST"])
def subscribe():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Login required to subscribe."}), 401

    existing = Subscriber.query.filter_by(email=user.email).first()

    if existing:
        if existing.is_active:
            return jsonify({"error": "You are already subscribed."}), 400
        existing.is_active = True
        db.session.commit()
        msg = Message(
            subject="You're back! Welcome to EDD Tech updates",
            recipients=[user.email],
            html=build_welcome_email(user.email)
        )
        mail.send(msg)
        return jsonify({"message": "Welcome back! You have re-subscribed."}), 200

    subscriber = Subscriber(email=user.email, user_id=user.id)
    db.session.add(subscriber)
    db.session.commit()

    msg = Message(
        subject="Welcome to EDD Tech & Accessories updates!",
        recipients=[user.email],
        html=build_welcome_email(user.email)
    )
    mail.send(msg)
    return jsonify({"message": "Subscribed successfully!"}), 201


@app.route("/api/unsubscribe", methods=["POST"])
def unsubscribe():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Login required."}), 401

    subscriber = Subscriber.query.filter_by(email=user.email).first()
    if not subscriber or not subscriber.is_active:
        return jsonify({"error": "You are not subscribed."}), 400

    subscriber.is_active = False
    db.session.commit()
    return jsonify({"message": "You have unsubscribed."}), 200


@app.route("/api/subscription/status", methods=["GET"])
def subscription_status():
    user = get_current_user()
    if not user:
        return jsonify({"subscribed": False}), 200

    subscriber = Subscriber.query.filter_by(email=user.email, is_active=True).first()
    return jsonify({"subscribed": bool(subscriber)}), 200


@app.route("/api/admin/broadcast", methods=["POST"])
@role_required("admin")
def broadcast():
    data = request.get_json()

    subject             = data.get("subject")
    preheader           = data.get("preheader", "")
    product_name        = data.get("product_name")
    product_description = data.get("product_description")
    product_price       = data.get("product_price", "")
    product_image       = data.get("product_image", "")
    product_link        = data.get("product_link", FRONTEND_URL)
    cta_text            = data.get("cta_text", "Shop Now")
    audience            = data.get("audience", "all")

    if not all([subject, product_name, product_description]):
        return jsonify({"error": "Subject, product name and description are required."}), 400

    if audience == "active":
        subscribers = Subscriber.query.filter_by(is_active=True).all()
    elif audience == "inactive":
        subscribers = Subscriber.query.filter_by(is_active=False).all()
    else:
        subscribers = Subscriber.query.filter_by(is_active=True).all()

    if not subscribers:
        return jsonify({"error": "No subscribers found for this audience."}), 400

    sent   = 0
    failed = 0

    for sub in subscribers:
        try:
            msg = Message(
                subject=subject,
                recipients=[sub.email],
                html=build_marketing_email(
                    product_name=product_name,
                    product_description=product_description,
                    product_price=product_price,
                    product_image=product_image,
                    product_link=product_link,
                    cta_text=cta_text
                )
            )
            mail.send(msg)
            sent += 1
        except Exception as e:
            print(f"Failed to send to {sub.email}: {e}")
            failed += 1

    campaign = Campaign(
        subject=subject,
        preheader=preheader,
        product_name=product_name,
        product_description=product_description,
        product_price=product_price,
        product_image=product_image,
        cta_text=cta_text,
        audience=audience,
        sent_count=sent,
        failed_count=failed
    )
    db.session.add(campaign)
    db.session.commit()

    return jsonify({"message": f"Campaign sent. ✓ {sent} delivered, ✗ {failed} failed."}), 200


@app.route("/api/admin/campaigns", methods=["GET"])
@role_required("admin")
def get_campaigns():
    campaigns = Campaign.query.order_by(Campaign.sent_at.desc()).all()
    return jsonify([
        {
            "id": c.id,
            "subject": c.subject,
            "product_name": c.product_name,
            "product_price": c.product_price,
            "product_image": c.product_image,
            "audience": c.audience,
            "sent_count": c.sent_count,
            "failed_count": c.failed_count,
            "sent_at": c.sent_at.strftime("%d %b %Y, %I:%M %p") if c.sent_at else "N/A"
        } for c in campaigns
    ]), 200


@app.route("/api/admin/campaigns/<int:id>", methods=["DELETE"])
@role_required("admin")
def delete_campaign(id):
    campaign = Campaign.query.get_or_404(id)
    db.session.delete(campaign)
    db.session.commit()
    return jsonify({"message": "Campaign deleted."}), 200


@app.route("/api/admin/subscribers", methods=["GET"])
@role_required("admin")
def get_subscribers():
    subscribers = Subscriber.query.order_by(Subscriber.subscribed_at.desc()).all()
    return jsonify([
        {
            "id": s.id,
            "email": s.email,
            "subscribed_at": s.subscribed_at,
            "is_active": s.is_active
        } for s in subscribers
    ]), 200


# ─────────────────────────────
# AUTH ROUTES
# ─────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    agreed = data.get("agreedToPolicy")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if not agreed:
        return jsonify({"error": "You must agree to the Privacy Policy"}), 400

    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"error": "User already exists"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(
        email=email,
        password=hashed_pw,
        role="user",
        agreed_to_policy=True,
        agreed_at=datetime.utcnow()
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered"}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 401

    otp = generate_otp()
    otp_store[email] = {
        "otp": otp,
        "expires": datetime.utcnow() + timedelta(minutes=5)
    }

    try:
        msg = Message(
            subject="Your EDD Tech Login Code",
            recipients=[email],
            html=build_otp_email(otp)
        )
        mail.send(msg)
    except Exception as e:
        print("OTP EMAIL ERROR:", e)
        return jsonify({"error": "Failed to send verification code"}), 500

    return jsonify({"message": "OTP sent to your email", "requires_otp": True}), 200


@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        return jsonify({"error": "Email and OTP required"}), 400

    stored = otp_store.get(email)

    if not stored:
        return jsonify({"error": "No OTP found. Please login again."}), 400

    if datetime.utcnow() > stored["expires"]:
        del otp_store[email]
        return jsonify({"error": "OTP has expired. Please login again."}), 400

    if stored["otp"] != otp:
        return jsonify({"error": "Invalid OTP. Please try again."}), 400

    del otp_store[email]

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    token = jwt.encode({
        "user_id": user.id,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(hours=24)
    }, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({
        "token": token,
        "role": user.role,
        "email": user.email
    }), 200


@app.route("/api/resend-otp", methods=["POST"])
def resend_otp():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    otp = generate_otp()
    otp_store[email] = {
        "otp": otp,
        "expires": datetime.utcnow() + timedelta(minutes=5)
    }

    try:
        msg = Message(
            subject="Your New EDD Tech Login Code",
            recipients=[email],
            html=build_otp_email(otp)
        )
        mail.send(msg)
    except Exception as e:
        print("RESEND OTP ERROR:", e)
        return jsonify({"error": "Failed to resend code"}), 500

    return jsonify({"message": "New OTP sent to your email"}), 200


# ─────────────────────────────
# GOOGLE AUTH ROUTE
# ─────────────────────────────
@app.route("/api/auth/google", methods=["POST"])
def google_auth():
    data = request.get_json()
    google_token = data.get("token")

    if not google_token:
        return jsonify({"error": "Token required"}), 400

    try:
        idinfo = id_token.verify_firebase_token(
            google_token,
            google_requests.Request()
        )

        email = idinfo.get("email")
        if not email:
            return jsonify({"error": "Could not get email from Google"}), 400

        user = User.query.filter_by(email=email).first()
        is_new_user = False

        if not user:
            is_new_user = True
            random_pw = secrets.token_hex(32)
            hashed_pw = bcrypt.generate_password_hash(random_pw).decode("utf-8")
            user = User(
                email=email,
                password=hashed_pw,
                role="user",
                agreed_to_policy=True,
                agreed_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()

        token = jwt.encode({
            "user_id": user.id,
            "role": user.role,
            "exp": datetime.utcnow() + timedelta(hours=24)
        }, app.config["SECRET_KEY"], algorithm="HS256")

        return jsonify({
            "token": token,
            "role": user.role,
            "is_new_user": is_new_user,
            "email": email
        }), 200

    except Exception as e:
        print("GOOGLE AUTH ERROR:", e)
        return jsonify({"error": "Invalid or expired Google token"}), 401


@app.route("/api/set-password", methods=["POST"])
def set_password():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.password = bcrypt.generate_password_hash(password).decode("utf-8")
    db.session.commit()

    return jsonify({"message": "Password set successfully"}), 200


# ─────────────────────────────
# ORDER ROUTES
# ─────────────────────────────
@app.route("/api/order", methods=["POST"])
def create_order():
    data = request.get_json()

    try:
        order = Order(
            product_name=data.get("product_name"),
            storage=data.get("storage"),
            color=data.get("color"),
            quantity=data.get("quantity"),
            price=data.get("price"),
            full_name=data.get("full_name"),
            phone=data.get("phone"),
            email=data.get("email"),
            location=data.get("location"),
            company=data.get("company"),
            notes=data.get("notes")
        )
        db.session.add(order)
        db.session.commit()

        owner_msg = Message(
            subject=f"New Order — {order.product_name} ({order.full_name})",
            recipients=[os.getenv("OWNER_EMAIL")],
            html=build_owner_email(order),
            reply_to=order.email
        )
        mail.send(owner_msg)

        customer_msg = Message(
            subject=f"Order Confirmed — {order.product_name}",
            recipients=[order.email],
            html=build_customer_email(order)
        )
        mail.send(customer_msg)

        return jsonify({"message": "Order placed successfully"}), 201

    except Exception as e:
        print("ORDER ERROR:", e)
        return jsonify({"error": "Failed to place order"}), 500


@app.route("/api/orders", methods=["GET"])
@role_required("admin")
def get_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return jsonify([
        {
            "id": o.id,
            "product_name": o.product_name,
            "price": o.price,
            "status": o.status,
            "customer": o.full_name,
            "email": o.email,
            "location": o.location,
            "phone": o.phone,
            "created_at": o.created_at
        } for o in orders
    ]), 200


@app.route("/api/orders/<int:id>", methods=["GET"])
def get_order(id):
    order = Order.query.get_or_404(id)
    return jsonify({
        "id": order.id,
        "product_name": order.product_name,
        "status": order.status
    }), 200


@app.route("/api/orders/<int:id>/status", methods=["PUT"])
@role_required("admin")
def update_order_status(id):
    order = Order.query.get_or_404(id)
    data = request.get_json()
    new_status = data.get("status")

    if new_status not in ["Pending", "Confirmed", "Shipped", "Delivered"]:
        return jsonify({"error": "Invalid status"}), 400

    order.status = new_status
    db.session.commit()
    return jsonify({"message": "Status updated"}), 200


@app.route("/api/orders/track", methods=["POST"])
def track_order():
    data = request.get_json()
    email = data.get("email")
    orders = Order.query.filter_by(email=email).all()
    return jsonify([
        {"id": o.id, "product": o.product_name, "status": o.status}
        for o in orders
    ])


# ─────────────────────────────
# CONTACT
# ─────────────────────────────
@app.route("/api/contact", methods=["POST"])
def contact():
    data = request.get_json()

    name = data.get("name")
    phone = data.get("phone")
    subject = data.get("subject")
    email = data.get("email")
    message = data.get("message")

    if not name or not email or not message:
        return jsonify({"error": "All fields required"}), 400

    try:
        new_message = ContactMessage(
            name=name,
            email=email,
            phone=phone,
            subject=subject,
            message=message
        )
        db.session.add(new_message)
        db.session.commit()

        owner_msg = Message(
            subject=f"New Contact: {subject or 'General Inquiry'} — {name}",
            recipients=[os.getenv("OWNER_EMAIL")],
            html=build_contact_owner_email(name, email, phone, subject, message),
            reply_to=email
        )
        mail.send(owner_msg)

        customer_msg = Message(
            subject="We've received your message 🙌",
            recipients=[email],
            html=build_contact_customer_email(name, subject)
        )
        mail.send(customer_msg)

        return jsonify({"message": "Message sent successfully"}), 200

    except Exception as e:
        print("CONTACT ERROR:", e)
        return jsonify({"error": "Failed to send message"}), 500


@app.route("/api/admin/messages", methods=["GET"])
@role_required("admin")
def get_messages():
    messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    return jsonify([
        {
            "id": m.id,
            "name": m.name,
            "email": m.email,
            "phone": m.phone,
            "subject": m.subject,
            "message": m.message,
            "status": m.status,
            "created_at": m.created_at.strftime("%d %b %Y, %I:%M %p")
        }
        for m in messages
    ]), 200


@app.route("/api/admin/messages/<int:id>/status", methods=["PUT"])
@role_required("admin")
def update_message_status(id):
    msg = ContactMessage.query.get_or_404(id)
    data = request.get_json()
    status = data.get("status")

    if status not in ["New", "Replied", "Closed"]:
        return jsonify({"error": "Invalid status"}), 400

    msg.status = status
    db.session.commit()
    return jsonify({"message": "Status updated"}), 200


@app.route("/api/admin/messages/<int:id>/read", methods=["PUT"])
@role_required("admin")
def mark_message_read(id):
    try:
        msg = ContactMessage.query.get(id)
        if not msg:
            return jsonify({"error": "Not found"}), 404

        msg.is_read = True
        db.session.commit()
        return jsonify({"message": "Marked as read"}), 200

    except Exception as e:
        print("ERROR MARKING READ:", e)
        return jsonify({"error": "Server error"}), 500


# ─────────────────────────────
# PRODUCT SEARCH
# ─────────────────────────────
@app.route("/api/products/search")
def search_products():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([])

    query_tokens = tokenize(query)
    all_products = load_products_with_category()
    results = [p for p in all_products if product_matches(p, query_tokens)]
    return jsonify(results)


# ─────────────────────────────
# RUN
# ─────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)