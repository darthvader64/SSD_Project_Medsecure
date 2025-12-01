# MedSecure – Secure Medical Records Sharing Platform

MedSecure is a teaching / coursework project that demonstrates how patients can
securely store, share, and audit access to their medical records using a
privacy-first, consent-driven model.

The project is implemented as a **client–server web application** with:

- A **Flask** backend (Python)
- **SQLite** for persistence
- **Jinja2** templates for the UI
- **Role-based access control** for Patients, Doctors, and Admin


## 1. Features

### Patient Portal

- Register and log in as a patient
- Create and view personal health records
  - e.g. “Blood Test Report – Nov 2025”
- Grant / revoke access to doctors using **consent management**
- View all **active consents** granted to doctors

### Doctor Portal

- Log in as a doctor and view records shared with you
- See which patient and which consent granted you access
- Create **patient history / visit notes** that are visible to both doctor and patient

### Admin Panel

- Log in as the administrator
- View system-wide **audit logs** (logins, record access, etc.)
- View **all patient records**
- View **doctor access overview** (which doctor can see which record)

### Security / Architecture

- Client–Server architecture (browser client, Flask server, SQLite DB)
- JWT-based authentication
- Role-based authorization (PATIENT / DOCTOR / ADMIN)
- Audit logging of critical events
- Containerized backend using **Docker** for consistent deployment


## 2. Tech Stack

- **Backend:** Python, Flask, Flask-JWT-Extended, SQLAlchemy
- **Database:** SQLite (`health_records.db`)
- **Frontend:** Jinja2 templates + vanilla JS + CSS
- **Containerization:** Docker, Docker Compose
- **Other:** HTML5, CSS3


## 3. Project Structure

Assuming this is the repository root:

.
├─ backend/               # Flask backend + templates + static files
│  ├─ app.py              # Main Flask application
│  ├─ health_records.db   # SQLite database (persistent data)
│  ├─ requirements.txt    # Python dependencies
│  ├─ templates/          # Jinja2 templates (index, login, dashboard, etc.)
│  └─ static/             # CSS, JS, images (e.g. hero-doctor.jpg)
├─ docs/                  # Documentation (reports, diagrams, etc.) – optional
├─ infra/                 # Infrastructure / config files (if any)
├─ docker-compose.yml     # Docker Compose configuration
└─ README.md              # This file
🔴 Important: Do not delete backend/health_records.db.
It stores all user accounts, records, consents, and audit logs.

4. How to Run the Project
You have two ways to run the project:

Using Docker (recommended, simplest)

Using local Python + virtual environment

Both options are described step-by-step below.

4.1 Option A – Run with Docker (Recommended)
This is the easiest way to run it later for demos.

Prerequisites
Docker Desktop installed

Docker Desktop engine running (you should see “Engine running” at the bottom of the Docker Desktop window)

Steps
Open a terminal / PowerShell

Change directory to the repo root (the folder that contains backend/ and docker-compose.yml):


cd path\to\SSD_Project\SSD_Project
(Adjust the path according to where you saved the project.)

Start the containers (build + run)


docker compose up --build
The first run may take a bit longer because Docker has to build the image.

You should eventually see logs like:

medsecure-api  | * Serving Flask app 'app'
medsecure-api  | * Running on all addresses (0.0.0.0)
medsecure-api  | * Running on http://127.0.0.1:5000
medsecure-api  | GET /health HTTP/1.1" 200 -
Open the application in your browser

http://localhost:5000
You should see the MedSecure home page.

Stop the app

In the same terminal where Docker is running, press Ctrl + C
OR

From another terminal in the repo root:


docker compose down
4.2 Option B – Run with Local Python (Without Docker)
This is useful if Docker is not available or if you want to modify code live.

Prerequisites
Python 3.11 (or compatible 3.x version) installed

pip available in your PATH

Steps
Open a terminal / PowerShell

Go to the repo root


cd path\to\SSD_Project\SSD_Project
Create a virtual environment (only once)


python -m venv .venv
Activate the virtual environment

On Windows (PowerShell):


.\.venv\Scripts\Activate.ps1
On Windows (CMD):

   
.venv\Scripts\activate.bat
On macOS / Linux:

source .venv/bin/activate
After activation you should see (.venv) at the start of your prompt.

Install backend dependencies

From the repo root:


pip install -r backend/requirements.txt
Run the Flask app


cd backend
python app.py
You should see something like:

* Serving Flask app 'app'
* Running on http://127.0.0.1:5000
Open the app in your browser

    
http://127.0.0.1:5000
Stop the app

Press Ctrl + C in the terminal.

Deactivate the virtual environment (optional when you’re done)


deactivate
5. Default Users & Roles (Example)
Depending on how you seeded your database, you may have some default accounts.
If you used the provided test data/debug functions, typical users look like:

Admin

Email: admin@medsecure.local

Password: your chosen password (remember what you set!)

Doctor

Example: doctor9@gmail.com

Patients

Example: patient9@gmail.com

🔐 If you forget passwords or want a clean slate, you can delete backend/health_records.db
(this wipes all data) and then recreate users via the Register page.

6. Application Flow Summary
Registration & Login

Users register as either patient or doctor.

Admin account is predefined (or created manually).

JWT is issued after login and stored in the browser (frontend uses it in API calls).

Patient Actions

Create health records (metadata stored in health_records table).

Use the Consent Management section to:

Select one of their records.

Choose a doctor from the dropdown.

Click Grant Access.

Doctor Actions

See all records shared with them under Records Shared With Me.

View record details and create visit history notes for patients.

Admin Actions

View system audit logs.

View all patient records.

View doctor access overview.

7. Health Check Endpoint
To verify that the API is reachable (especially when running in Docker), the backend exposes a simple health check:

http
GET /health
Expected response (HTTP 200):

json
{"status": "ok"}
You can open:

   
http://localhost:5000/health
in a browser or use curl:


curl http://localhost:5000/health
8. Troubleshooting
8.1 Docker: Cannot connect to the Docker daemon / pipe error
Make sure Docker Desktop is running and shows “Engine running”.

Run docker version to confirm the Docker Server section is visible.

Then run docker compose up --build again from the repo root.

8.2 ModuleNotFoundError: No module named 'flask' (when running locally)
You are either:

Not in the virtual environment, or

Haven’t installed dependencies.

Fix:

cd path\to\SSD_Project\SSD_Project
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
python backend/app.py
8.3 Port already in use
If port 5000 is already in use:

Close any other Flask / web servers

Or, edit app.py to use another port:

python
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
and update Docker / your browser URL accordingly.

9. How to Present This to the Teacher (Quick Demo Checklist)
Make sure Docker Desktop is running.

In terminal:


cd path\to\SSD_Project\SSD_Project
docker compose up --build
Open browser at http://localhost:5000.

Demonstrate:

Register as patient and log in

Create a record

Grant consent to a doctor

Log in as the doctor and show shared records

Log in as admin and show audit logs / records overview

After demo:


docker compose down
10. Credits
Developed as part of the Secure Software Development / Security Engineering coursework.

Team members:
Eman Akbar 22i-1588
Saad Umar 22i-1679
Laiba Waseem 22i-1566
Shifa Zehra 22i-1727
Huda Imran 22i-1713
