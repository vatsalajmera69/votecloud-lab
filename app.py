# app.py
import os
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from botocore.exceptions import ClientError

# ---- Config ----
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-for-lab")  # set a strong one in prod

S3_BUCKET = os.getenv("S3_BUCKET", "votecloud-data")
S3_KEY = os.getenv("S3_KEY", "data.json")
AWS_REGION = os.getenv("AWS_REGION", None)  # optional

if AWS_REGION:
    s3 = boto3.client("s3", region_name=AWS_REGION)
else:
    s3 = boto3.client("s3")

# ---- S3 helpers ----
def load_data():
    """
    Load JSON from S3. If the object doesn't exist, create a default dataset (admin + 2 candidates).
    """
    try:
        resp = s3.get_object(Bucket=S3_BUCKET, Key=S3_KEY)
        body = resp['Body'].read().decode('utf-8')
        return json.loads(body)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        # If not found -> create default dataset
        if code in ("NoSuchKey", "NoSuchBucket", "404"):
            data = {
                "users": [],
                "candidates": []
            }
            # create an admin user for demo
            admin_user = {
                "id": 1,
                "username": "admin",
                "password": generate_password_hash("admin123"),  # demo password
                "role": "admin",
                "has_voted": False
            }
            data["users"].append(admin_user)
            data["candidates"] = [
                {"id": 1, "name": "Alice", "party": "Party A", "votes": 0},
                {"id": 2, "name": "Bob", "party": "Party B", "votes": 0}
            ]
            save_data(data)
            return data
        else:
            # For other errors (permissions, no bucket, etc.) re-raise for visibility
            raise

def save_data(data):
    """
    Save JSON to S3. Overwrites the object.
    """
    s3.put_object(Bucket=S3_BUCKET, Key=S3_KEY,
                  Body=json.dumps(data, indent=2).encode("utf-8"))

# ---- Routes (same structure as earlier app) ----
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('vote'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = load_data()
        username = request.form['username'].strip()
        password = request.form['password']

        if any(u['username'] == username for u in data['users']):
            flash("Username already exists!")
            return render_template('register.html')

        new_id = max((u['id'] for u in data['users']), default=0) + 1
        new_user = {
            "id": new_id,
            "username": username,
            "password": generate_password_hash(password),
            "role": "user",
            "has_voted": False
        }
        data['users'].append(new_user)
        save_data(data)
        flash("Registration successful! Please login.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = load_data()
        username = request.form['username'].strip()
        password = request.form['password']

        user = next((u for u in data['users'] if u['username'] == username), None)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials!")

    return render_template('login.html')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    data = load_data()
    user = next((u for u in data['users'] if u['id'] == session['user_id']), None)
    if user is None:
        flash("User not found; please login again.")
        session.clear()
        return redirect(url_for('login'))

    if user.get("has_voted"):
        flash("You have already voted!")
        return render_template('vote_success.html')

    if request.method == 'POST':
        candidate_id = request.form.get('candidate_id')
        if not candidate_id:
            flash("Please select a candidate")
            return redirect(url_for('vote'))

        candidate_id = int(candidate_id)
        candidate = next((c for c in data['candidates'] if c['id'] == candidate_id), None)
        if not candidate:
            flash("Selected candidate not found")
            return redirect(url_for('vote'))

        candidate['votes'] = candidate.get('votes', 0) + 1
        user['has_voted'] = True
        save_data(data)
        flash("Vote cast successfully!")
        return render_template('vote_success.html')

    return render_template('vote.html', candidates=data['candidates'])

@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash("Admin access required!")
        return redirect(url_for('login'))

    data = load_data()
    results = data['candidates']
    total_votes = sum(c.get('votes', 0) for c in results)
    return render_template('admin.html', results=results, total_votes=total_votes)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Convenience: show current config (only for demo/testing, remove in production)
@app.route('/_status')
def status():
    return {
        "S3_BUCKET": S3_BUCKET,
        "S3_KEY": S3_KEY,
        "user": session.get("username")
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", "5000")), debug=True)
