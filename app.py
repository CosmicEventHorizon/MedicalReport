from flask import Flask, render_template, request, make_response, send_from_directory, jsonify, redirect, url_for
from utils.auth import check_password, get_user, generate_jwt, get_authorization_info
import uuid
import os
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/')
def home():
    token = request.cookies.get('jwt_token')
    if token is None:
        print("No token found, redirecting to login")
        return redirect(url_for('login'))
    is_valid, username = get_authorization_info(token)
    if not is_valid:
        print("Invalid token, redirecting to login")
        return redirect(url_for('login'))
    user_site_path = os.path.join('generated_sites', username)
    index_file = os.path.join(user_site_path, 'index.html')
    if not os.path.exists(index_file):
        return "User site not found. Please try again later.", 404
    return redirect(url_for('serve_user_site', username=username, filename='index.html'))


@app.route('/sites/<username>/<path:filename>')
def serve_user_site(username, filename):
    token = request.cookies.get('jwt_token')    
    if not token:
        return abort(401) 
    is_valid, token_username = get_authorization_info(token)
    if not is_valid or token_username != username:
        return abort(403)  
    return send_from_directory(os.path.join('generated_sites', username), filename)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form['username']
    password = request.form['password']
    user = get_user(username)
    if not user or not check_password(user[2], password): 
        return jsonify({'message': 'Invalid username or password'}), 401
    token = generate_jwt(username)
    response = make_response(jsonify({'message': 'Successfully logged in'}), 202)
    response.set_cookie('jwt_token', token, httponly=True)
    return response

@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({'message': 'Successfully logged out'}), 202)
    response.set_cookie('jwt_token', '', expires=0, httponly=True)
    return response

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
