import bcrypt
from flask import Flask, jsonify, request
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'

login_manager = LoginManager()

db.init_app(app)
login_manager.init_app(app)

# view login
login_manager.login_view = 'login'

@login_manager.user_loader # recuperar usuario
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        # login
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({'message': 'Login success'})
        return jsonify({'message': 'Invalid username or password'}), 400
    
    return jsonify({'message': 'Invalid username or password'}), 400

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout success'})

@app.route('/user', methods=['POST'])
# @login_required # Protege a criação de usuário para apenas usuários logados
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user is None:
        if username and password:
            hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
            user_filter = User(username=username, password=hashed_password, role='user')
            db.session.add(user_filter)
            db.session.commit()
            return jsonify({'message': 'User created successfully'})
        return jsonify({'message': 'Invalid username or password'}), 400
    
    return jsonify({'message': 'User already exists'}), 400

@app.route('/user/<int:user_id>', methods=['GET'])
@login_required
def read_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({'id': user.id, 'username': user.username, 'password': user.password})
    return jsonify({'message': 'User not found'}), 404

@app.route('/user/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    data = request.json
    user = User.query.get(user_id)

    if user_id != current_user.id and current_user.role == 'user':
        return jsonify({'message': 'Atualização não permitida'}), 403
    
    if user and data.get('password'):
        password = data.get('password')
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user.password = hashed_password
        db.session.commit()
        return jsonify({'message': f'User {user_id} updated successfully, try login again'})
    return jsonify({'message': 'User not found'}), 404

@app.route('/user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)

    if current_user.role != 'admin':
        return jsonify({'message': 'Deleção não permitida'}), 403
    
    if user_id == current_user.id:
        return jsonify({'message': 'Deleção não permitida'}), 403
    
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': f'User {user_id} deleted successfully'})
    return jsonify({'message': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)