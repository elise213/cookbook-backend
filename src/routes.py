from flask import Blueprint, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token, set_access_cookies, jwt_required, get_jwt_identity, decode_token
)
from flask import make_response, jsonify, request
from flask_cors import cross_origin

from flask_mail import Message
from datetime import timedelta
from src.models import db, User
import os
from app import mail
import stripe
import secrets
import string


stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET") 
api = Blueprint("api", __name__)

# ------------------------
# Register New User
# ------------------------
@api.route("/createUser", methods=["POST"])
def create_user():
    data = request.get_json()
    if not data.get("email") or not data.get("password") or not data.get("name"):
        return jsonify({"error": "Missing required fields"}), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already exists"}), 400

    user = User(
        name=data["name"],
        email=data["email"],
        password=generate_password_hash(data["password"]),
        is_org=data.get("is_org", False)
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

# ------------------------
# Login User (JWT via Cookie)
# ------------------------




@api.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get("email")).first()

    if not user or not check_password_hash(user.password, data.get("password")):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id)) 
    response = make_response(jsonify({
        "message": f"Welcome back, {user.name}!",
        "user": user.serialize()
    }))
    set_access_cookies(response, access_token)
    return response



# ------------------------
# Protected Route (requires login)
# ------------------------
@api.route("/protected", methods=["GET", "OPTIONS"])
@cross_origin(supports_credentials=True, origins=["http://localhost:3000"])
@jwt_required()
def protected():
    if request.method == "OPTIONS":
        return jsonify({"message": "Preflight success"}), 200

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "is_org": user.is_org
        }
    })






from src.send_email import send_email  # make sure this path matches your project

@api.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "No user found with that email"}), 404

    token = create_access_token(
    identity=str(user.id),  # ✅ force it to a string
    expires_delta=timedelta(minutes=30)
)

    reset_link = f"http://localhost:3000/resetpassword?token={token}"

    subject = "Password Reset Request"
    body = f"""
    <p>Hi {user.name},</p>
    <p>A request was made to reset your password.</p>
    <p>Click the link below to reset it:</p>
    <p><a href="{reset_link}">{reset_link}</a></p>
    <p>If you did not request this, you can ignore this message.</p>
    """

    result = send_email(email, subject, body)

    if result != "Email sent successfully!":
        return jsonify({"error": f"Failed to send email: {result}"}), 500

    return jsonify({
        "message": "Reset email sent successfully",
        "reset_link": reset_link
    }), 200



# ------------------------
@api.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    print("📥 Received reset-password payload:", data)

    token = data.get("token")
    new_password = data.get("new_password")

    if not token or not new_password:
        print("❌ Missing token or new_password")
        return jsonify({"error": "Token and new password are required"}), 400

    try:
        print("🔐 Decoding token...")
        decoded = decode_token(token)
        print("✅ Token decoded:", decoded)

        user_id = decoded.get("sub")  # now a string
        print("👤 Extracted user_id:", user_id)

        user = User.query.get(int(user_id))
        if not user:
            print("❌ User not found for ID:", user_id)
            return jsonify({"error": "User not found"}), 404

        print("🔄 Updating password...")
        user.password = generate_password_hash(new_password)
        db.session.commit()

        print("✅ Password reset successful for user:", user.email)
        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        print("❌ Exception during reset-password:", str(e))
        return jsonify({"error": "Invalid or expired token"}), 400





stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")


@api.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    print("✅ Webhook endpoint triggered")

    testing_mode = request.headers.get("X-Test-Mode") == "true"

    if testing_mode:
        print("🧪 Running in test mode (curl)")
        try:
            data = request.get_json()
            event = {
                "type": "checkout.session.completed",
                "data": {
                    "object": {
                        "customer_email": data.get("data", {}).get("object", {}).get("customer_email", "testuser@example.com")
                    }
                }
            }
        except Exception as e:
            print("❌ Failed to parse test payload:", str(e))
            return jsonify({"error": "Malformed test data"}), 400

    else:
        payload = request.get_data(as_text=True)
        sig_header = request.headers.get("Stripe-Signature")

        try:
            event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
        except ValueError as e:
            print("❌ Invalid payload:", str(e))
            return jsonify({"error": "Invalid payload"}), 400
        except stripe.error.SignatureVerificationError as e:
            print("❌ Invalid signature:", str(e))
            return jsonify({"error": "Invalid signature"}), 400

    # Handle the event
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        print("✅ Stripe session completed:", session)

        customer_email = session.get("customer_email")
        print("📧 Email from Stripe:", customer_email)

        if not customer_email:
            print("❌ No email provided — cannot proceed")
            return jsonify({"error": "No email found"}), 400

        # Generate random credentials
        username = f"user_{secrets.token_hex(4)}"
        raw_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        hashed_password = generate_password_hash(raw_password)
        email = customer_email

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            print(f"⚠️ User already exists: {email}")
        else:
            new_user = User(
                name=username,
                email=email,
                password=hashed_password,
                is_org=False
            )
            db.session.add(new_user)
            db.session.commit()
            print(f"✅ New user created: {email}")

        # Send welcome email
        subject = "Welcome to Fatima’s Cookbook"
        body = f"""
        <p>Thank you for your purchase!</p>
        <p>You now have access to the cookbook.</p>
        <p><strong>Login:</strong> <a href="http://localhost:3000/login">http://localhost:3000/login</a></p>
        <p><strong>Email:</strong> {email}<br>
        <strong>Password:</strong> {raw_password}</p>
        <p>Best,<br>Recipes from Rafah</p>
        """

        result = send_email(email, subject, body)
        if result == "Email sent successfully!":
            print("📨 Welcome email sent")
        else:
            print(f"❌ Email sending failed: {result}")

    return jsonify({"status": "success"}), 200


# ------------------------
# Create Stripe Checkout Session
# ------------------------
@api.route("/create-checkout-session", methods=["POST"])
@jwt_required()
def create_checkout_session():
    print("🧾 Received create-checkout-session request")

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        print("❌ User not found")
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    amount = data.get("amount", 2000)  # Default to $20
    product_name = data.get("product_name", "Fatima's Cookbook")

    try:
        print(f"📦 Creating session for {user.email}, amount: {amount}")

        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="payment",
            customer_email=user.email,
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {
                        "name": product_name,
                    },
                    "unit_amount": amount,
                },
                "quantity": 1,
            }],
            success_url="http://localhost:3000/success",
            cancel_url="http://localhost:3000/cancel",
        )

        print("✅ Stripe session created successfully")
        return jsonify({"url": session.url}), 200

    except Exception as e:
        print("❌ Stripe session creation failed:", str(e))
        return jsonify({"error": str(e)}), 500

# ------------------------
# Check Simple Password Gate
# ------------------------
@api.route("/check-password", methods=["POST", "OPTIONS"])
@cross_origin(supports_credentials=True, origins=["http://localhost:3000"])
def check_password_gate():
    if request.method == "OPTIONS":
        return jsonify({"message": "CORS preflight success"}), 200

    data = request.get_json()
    input_password = data.get("password")

    if not input_password:
        return jsonify({"error": "Password is required"}), 400

    correct_password = os.getenv("SITE_PASSWORD")

    if not correct_password:
        return jsonify({"error": "Server misconfiguration"}), 500

    if input_password == correct_password:
        return jsonify({"success": True}), 200
    else:
        return jsonify({"success": False}), 401


@api.route("/", methods=["GET"])
def root():
    return jsonify({"message": "API is working!"})
