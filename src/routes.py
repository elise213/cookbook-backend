from flask import Blueprint, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token, set_access_cookies, jwt_required, get_jwt_identity, decode_token
)
from flask_cors import cross_origin
from flask_mail import Message
from datetime import timedelta
from src.models import db, User
from app import mail
import os
import stripe
from src.send_email import send_email


# Constants
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "https://recipesforrafah.com",
    "http://recipesforrafah.com",
    "https://www.recipesforrafah.com",
]

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

api = Blueprint("api", __name__)

# ------------------------
# Register User
# ------------------------
@api.route("/createUser", methods=["POST"])
def create_user():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON received"}), 400

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
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500


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
# Protected Route
# ------------------------
@api.route("/protected", methods=["GET", "OPTIONS"])
@cross_origin(supports_credentials=True, origins=ALLOWED_ORIGINS)
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

# ------------------------
# Forgot Password
# ------------------------# ------------------------
# Forgot Password
# ------------------------
@api.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "No user found with that email"}), 404

    token = create_access_token(identity=str(user.id), expires_delta=timedelta(minutes=30))
    reset_link = f"https://zesty-phoenix-8cec46.netlify.app/resetpassword?token={token}"

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
# Reset Password
# ------------------------
@api.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    token = data.get("token")
    new_password = data.get("new_password")

    if not token or not new_password:
        return jsonify({"error": "Token and new password are required"}), 400

    try:
        decoded = decode_token(token)
        user_id = decoded.get("sub")
        user = User.query.get(int(user_id))
        if not user:
            return jsonify({"error": "User not found"}), 404

        user.password = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": "Invalid or expired token"}), 400

# ------------------------
# Stripe Webhook
# ------------------------@api.route("/stripe-webhook", methods=["POST"])


@api.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    import secrets, string

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
        print("✅ Webhook event received:", event.get("type"))
    except Exception as e:
        print("❌ Webhook error:", str(e))
        return jsonify(success=False), 400

    if event.get("type") == "checkout.session.completed":
        try:
            session = event.get("data", {}).get("object", {})
            print("📦 Checkout session object:", session)

            customer_email = (
                session.get("customer_email") or
                session.get("customer_details", {}).get("email")
            )

            if not customer_email:
                print("❌ No customer_email found anywhere!")
                return jsonify({"error": "No email found"}), 400


            print(f"🎉 Payment complete for: {customer_email}")

            # Generate credentials
            username = f"user_{secrets.token_hex(4)}"
            raw_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            hashed_password = generate_password_hash(raw_password)

            # Check if user exists
            existing_user = User.query.filter_by(email=customer_email).first()
            if not existing_user:
                new_user = User(
                    name=username,
                    email=customer_email,
                    password=hashed_password,
                    is_org=False
                )
                db.session.add(new_user)
                db.session.commit()
                print(f"✅ New user created: {username}")
            else:
                print(f"ℹ️ User already exists: {existing_user.email}")

            # Send credentials by email
            subject = "Welcome to Fatima’s Cookbook"
            body = f"""
            <p>Thank you for your purchase!</p>
            <p>You now have access to the cookbook.</p>
            <p><strong>Login:</strong> <a href="https://zesty-phoenix-8cec46.netlify.app/login">Login</a></p>
            <p><strong>Email:</strong> {customer_email}<br>
            <strong>Password:</strong> {raw_password}</p>
            <p>To change your password, visit: <a href="https://zesty-phoenix-8cec46.netlify.app/forgotpassword">Change Password</a></p>
            <p>Best,<br>Recipes from Rafah</p>
            """

            send_email(customer_email, subject, body)
            print("📧 Email sent!")

        except Exception as e:
            print("❌ Error processing checkout.session.completed:", str(e))
            return jsonify({"error": str(e)}), 500

    return jsonify({"status": "success"}), 200




# ------------------------
# Create Checkout Session
# ------------------------
@api.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    data = request.get_json()
    amount = data.get("amount", 2000)
    product_name = data.get("product_name", "Fatima's Cookbook")

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="payment",
            customer_creation="if_required", 
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
            success_url="https://zesty-phoenix-8cec46.netlify.app/success",
            cancel_url="https://zesty-phoenix-8cec46.netlify.app/", 
        )

        return jsonify({"url": session.url}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500




# ------------------------
# Password Gate
# ------------------------
@api.route("/check-password", methods=["POST", "OPTIONS"])
@cross_origin(supports_credentials=True, origins=ALLOWED_ORIGINS)
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

# ------------------------
# Misc
# ------------------------
@api.route("/", methods=["GET"])
def root():
    return jsonify({"message": "API is working!"})

@api.route("/debug-cors", methods=["GET", "OPTIONS"])
def debug_cors():
    origin = request.headers.get("Origin")
    return jsonify({
        "Received-Origin-Header": origin,
        "CORS-Allow-Origin-Should-Be": "https://zesty-phoenix-8cec46.netlify.app"
    })

@api.route("/debug", methods=["POST"])
def debug():
    try:
        data = request.get_json()
        print("Received JSON:", data)
        return jsonify({"status": "ok", "received": data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
