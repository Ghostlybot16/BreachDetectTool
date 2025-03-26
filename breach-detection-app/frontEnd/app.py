from flask import Flask, render_template, request, redirect, session, url_for
import requests
from fastapi import status
import os
from dotenv import load_dotenv

# Initialize Flask app
app = Flask(__name__)

load_dotenv() # Load environment variables from .env file from the frontEnd directory
app.secret_key = os.getenv("FLASK_SECRET_KEY")

API_URL = "http://localhost:8000"  # Base URL for FastAPI backend

# Root path
@app.route("/")
def home():
    return redirect("/login")

# Login Page (GET shows login form, POST submits login credentials)
@app.route("/login", methods=["GET", "POST"])
def login():
    success = request.args.get("success") == "true"
    if request.method == "POST":
        data = { # Collect Login Data
            "email": request.form["email"],
            "password": request.form["password"]
        }
        
        # Send login request to FastAPI backend
        res = requests.post(f"{API_URL}/login", json=data)
        
        # If success, save token in session and redirect to dashboard 
        if res.status_code == status.HTTP_200_OK:
            token = res.json()["access_token"]
            session["token"] = token
            return redirect("/dashboard")
        return render_template("login.html", error="Invalid credentials") # If login fails, show error
    return render_template("login.html", success=success) # Show login form

# Register Page (GET shows registration form, POST submits new user)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = { # Collect registration data 
            "email": request.form["email"],
            "password": request.form["password"],
            "role": "user" #Default role
        }
        
        # Send registration data to FastAPI backend
        res = requests.post(f"{API_URL}/register", json=data)
        
        # Redirect to login page if successful 
        if res.status_code in [200, 201]:
            return redirect(url_for("login", success="true"))
        return render_template("register.html", error="Registration failed") # Show error if registration fails 
    return render_template("register.html") # Show registration form

# Dashboard page (only accessible if logged in)
@app.route("/dashboard")
def dashboard():
    
    # Redirect to login page if not authenticated 
    if "token" not in session:
        return redirect("/login")
    return render_template("userDashboard.html")

# Logout route clears session and returns to login page 
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
