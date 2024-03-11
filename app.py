from flask import Flask, render_template, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import request as myrequest
import base64
import requests

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid user')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        return render_template('dashboard.html', user=user)
    
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

@app.route('/user/login', methods=['POST'])
def login_redirect():
    return redirect('/user/saml/login')

@app.route('/user/saml/login', methods=['GET', 'POST'])
def saml_login():
    if request.method == 'GET':
        # Generate the SAML authentication request
        entity_id = "http://127.0.0.1:5000/user/saml/login"
        acs_url = "http://127.0.0.1:5000/user/saml/login"
        authn_request_xml = myrequest.generate_authn_request(entity_id, acs_url)

        # Base64 encode the XML
        if authn_request_xml is not None:
            encoded_authn_request = base64.b64encode(authn_request_xml).decode()
            print("SAML Request:")
            print(encoded_authn_request)  # Print the encoded XML
        else:
            print("Error: Authentication request XML is None")

        # Okta SSO endpoint URL
        okta_sso_url = "https://trial-4751654.okta.com/app/trial-4751654_lux20_1/exkbxtx5fii7FOLC3697/sso/saml"

        # Construct the payload for the POST request
        payload = {'SAMLRequest': encoded_authn_request}

        # Send the POST request to Okta
        response = requests.post(okta_sso_url, data=payload)

        # Check the response
        if response.status_code == 200:
            print("SAML authentication request sent successfully.")
        else:
            print(f"Failed to send SAML authentication request. Status code: {response.status_code}")

        return redirect(okta_sso_url)
    
    elif request.method == 'POST':
        saml_response = request.form.get('SAMLResponse')
        
        # Process the SAML response as needed
        print("Received SAML Response:")
        print(saml_response)
        
        # Check if the SAML response is valid
        if saml_response is not None:
            # Set up the user session here
            session['logged_in'] = True  # Example session setup
            session['user'] = {'_id': 'example_id', 'name': 'Example User', 'email': 'user@example.com'}  # Example user data
            
            # Redirect to the dashboard
            return redirect('/dashboard')
        else:
            # Handle the case when the SAML response is not valid
            return "Invalid SAML response"

@app.route('/error')
def error():
    return render_template('error.html')

if __name__ == '__main__':
    app.run(debug=True)
