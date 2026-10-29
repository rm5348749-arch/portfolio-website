import os, sqlite3
from functools import wraps
from flask import (Flask, g, render_template, request, redirect, url_for,
                   session, flash, send_from_directory, abort)
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "portfolio.db")
UPLOADS = os.path.join(BASE, "uploads")
os.makedirs(UPLOADS, exist_ok=True)

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB resume limit

# section key -> (title, [(column, label), ...])  (whitelist; keys are never user input)
SECTIONS = {
    "education":    ("Education",    [("degree", "Degree"), ("institute", "Institute"), ("year", "Year"), ("grade", "Grade")]),
    "skills":       ("Skills",       [("name", "Skill"), ("level", "Level")]),
    "projects":     ("Projects",     [("title", "Title"), ("description", "Description"), ("link", "Link")]),
    "certificates": ("Certificates", [("title", "Certificate"), ("issuer", "Issued by"), ("year", "Year")]),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, headline TEXT DEFAULT '',
  about TEXT DEFAULT '', phone TEXT DEFAULT '', is_admin INTEGER DEFAULT 0, has_resume INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS education(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, degree TEXT, institute TEXT, year TEXT, grade TEXT);
CREATE TABLE IF NOT EXISTS skills(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT, level TEXT);
CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT, description TEXT, link TEXT);
CREATE TABLE IF NOT EXISTS certificates(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT, issuer TEXT, year TEXT);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    con = sqlite3.connect(DB)
    con.executescript(SCHEMA)
    if not con.execute("SELECT 1 FROM users WHERE is_admin=1").fetchone():
        con.execute("INSERT INTO users(name,username,email,password_hash,is_admin) VALUES(?,?,?,?,1)",
                    ("Administrator", "admin", "admin@example.com", generate_password_hash("admin123")))
    con.commit(); con.close()

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("user_id"):
            flash("Log in to continue.", "error")
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if not session.get("is_admin"):
            abort(403)
        return f(*a, **k)
    return w

def load_sections(uid):
    out = {}
    for key, (title, fields) in SECTIONS.items():
        rows = db().execute(f"SELECT * FROM {key} WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
        items = []
        for r in rows:
            first = r[fields[0][0]] or ""
            rest = " | ".join(r[c] for c, _ in fields[1:] if r[c])
            items.append({"id": r["id"], "title": first, "detail": rest})
        out[key] = items
    return out

@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    sql = "SELECT * FROM users WHERE is_admin=0"
    args = ()
    if q:
        sql += " AND (name LIKE ? OR headline LIKE ? OR username LIKE ?)"
        args = (f"%{q}%",) * 3
    users = db().execute(sql + " ORDER BY id DESC", args).fetchall()
    return render_template("index.html", users=users, q=q)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        name, username = f["name"].strip(), f["username"].strip().lower()
        email, pw = f["email"].strip().lower(), f["password"]
        if not (name and username and email and len(pw) >= 6):
            flash("Fill every field. Password needs at least 6 characters.", "error")
        elif not username.replace("-", "").replace("_", "").isalnum():
            flash("Username can use letters, numbers, - and _ only.", "error")
        else:
            try:
                db().execute("INSERT INTO users(name,username,email,password_hash) VALUES(?,?,?,?)",
                             (name, username, email, generate_password_hash(pw)))
                db().commit()
                flash("Profile created. Log in to add your details.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username or email is already registered.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident, pw = request.form["ident"].strip().lower(), request.form["password"]
        u = db().execute("SELECT * FROM users WHERE username=? OR email=?", (ident, ident)).fetchone()
        if u and check_password_hash(u["password_hash"], pw):
            session.clear()
            session.update(user_id=u["id"], username=u["username"], is_admin=bool(u["is_admin"]))
            return redirect(url_for("admin" if u["is_admin"] else "dashboard"))
        flash("Wrong username/email or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    u = db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("dashboard.html", u=u, data=load_sections(u["id"]), sections=SECTIONS)

@app.route("/dashboard/profile", methods=["POST"])
@login_required
def update_profile():
    f = request.form
    db().execute("UPDATE users SET name=?, headline=?, about=?, phone=? WHERE id=?",
                 (f["name"].strip(), f["headline"].strip(), f["about"].strip(), f["phone"].strip(), session["user_id"]))
    db().commit()
    flash("Profile saved.", "ok")
    return redirect(url_for("dashboard"))

@app.route("/add/<section>", methods=["POST"])
@login_required
def add_item(section):
    if section not in SECTIONS:
        abort(404)
    cols = [c for c, _ in SECTIONS[section][1]]
    vals = [request.form.get(c, "").strip() for c in cols]
    if not vals[0]:
        flash("The first field is required.", "error")
    else:
        db().execute(f"INSERT INTO {section}(user_id,{','.join(cols)}) VALUES(?,{','.join('?'*len(cols))})",
                     [session["user_id"], *vals])
        db().commit()
        flash(f"{SECTIONS[section][0]} entry added.", "ok")
    return redirect(url_for("dashboard"))

@app.route("/delete/<section>/<int:item_id>", methods=["POST"])
@login_required
def delete_item(section, item_id):
    if section not in SECTIONS:
        abort(404)
    row = db().execute(f"SELECT user_id FROM {section} WHERE id=?", (item_id,)).fetchone()
    if not row or (row["user_id"] != session["user_id"] and not session.get("is_admin")):
        abort(403)
    db().execute(f"DELETE FROM {section} WHERE id=?", (item_id,))
    db().commit()
    flash("Entry removed.", "ok")
    return redirect(request.referrer or url_for("dashboard"))

@app.route("/resume/upload", methods=["POST"])
@login_required
def upload_resume():
    f = request.files.get("resume")
    if not f or not f.filename.lower().endswith(".pdf"):
        flash("Upload a PDF file.", "error")
    else:
        f.save(os.path.join(UPLOADS, f"{session['user_id']}.pdf"))
        db().execute("UPDATE users SET has_resume=1 WHERE id=?", (session["user_id"],))
        db().commit()
        flash("Resume uploaded.", "ok")
    return redirect(url_for("dashboard"))

@app.route("/resume/<username>")
def resume(username):
    u = db().execute("SELECT id, has_resume FROM users WHERE username=?", (username,)).fetchone()
    if not u or not u["has_resume"]:
        abort(404)
    return send_from_directory(UPLOADS, f"{u['id']}.pdf", as_attachment=True,
                               download_name=f"{username}_resume.pdf")

@app.route("/u/<username>")
def profile(username):
    u = db().execute("SELECT * FROM users WHERE username=? AND is_admin=0", (username,)).fetchone()
    if not u:
        abort(404)
    return render_template("profile.html", u=u, data=load_sections(u["id"]), sections=SECTIONS)

@app.route("/admin")
@admin_required
def admin():
    users = db().execute("""SELECT u.*, (SELECT COUNT(*) FROM projects p WHERE p.user_id=u.id) AS n_projects,
        (SELECT COUNT(*) FROM skills s WHERE s.user_id=u.id) AS n_skills
        FROM users u WHERE is_admin=0 ORDER BY id DESC""").fetchall()
    return render_template("admin.html", users=users)

@app.route("/admin/delete_user/<int:uid>", methods=["POST"])
@admin_required
def delete_user(uid):
    for key in SECTIONS:
        db().execute(f"DELETE FROM {key} WHERE user_id=?", (uid,))
    db().execute("DELETE FROM users WHERE id=? AND is_admin=0", (uid,))
    db().commit()
    p = os.path.join(UPLOADS, f"{uid}.pdf")
    if os.path.exists(p):
        os.remove(p)
    flash("User removed.", "ok")
    return redirect(url_for("admin"))

init_db()

if __name__ == "__main__":
    app.run(debug=True)
