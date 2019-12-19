from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity, create_refresh_token,
    jwt_refresh_token_required, get_raw_jwt
)
import pymysql
# import importlib

#init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))


app.config['SECRET_KEY'] =  'thisisasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db1.sqlite')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/wakily'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)

# Init db
db = SQLAlchemy(app)

# init ma
ma = Marshmallow(app)

# from models import *

class Product(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    # public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(50))
    # password = db.Column(db.String(80))
    # admin = db.Column(db.Boolean)
    description = db.Column(db.String(200))
    price = db.Column(db.Float)
    qty = db.Column(db.Integer)

    def __init__(self, name, description, price, qty):
        self.name = name
        self.description = description
        self.price = price
        self.qty = qty

class NewUser(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    password = db.Column(db.String(80))
    role = db.Column(db.String(50))
    

    def __init__(self, public_id, name, email, password, role):
        self.public_id = public_id
        self.name = name
        self.email = email
        self.password = password
        self.role = role
        

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

    def __init__(self, text, complete, user_id):
        self.text = text
        self.complete = complete
        self.user_id = user_id

# from routes import *

# product Schema
class ProductSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'description', 'price', 'qty')

class UserSchema(ma.Schema):
    class Meta:
        fields = ('name', 'email', 'public_id', 'password', 'role')

# init schema
product_schema = ProductSchema(strict=True)
products_schema = ProductSchema(many=True, strict=True)
user_schema = UserSchema(strict=True)
users_schema = UserSchema(many=True, strict=True)

# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    # username = request.json.get('username', None)
    # username = request.json['username']
    email = request.json['email']
    password = request.json.get('password', None)
    if not email:
        # return jsonify({"msg": "Missing username parameter"}), 400
        return jsonify({"code": 5000}), 400
    if not password:
        # return jsonify({"msg": "Missing password parameter"}), 400
        return jsonify({"code": 5000}), 400
    
    emailTest = NewUser.query.filter_by(email=email).first()
    
    if emailTest is None:
        return jsonify({"code": 5000}), 400
    
    is_valid = check_password_hash(emailTest.password, password)
    if not is_valid:
        return jsonify({"code": 5000}), 400
    
    # if username != 'test' or password != 'test':
    #     return jsonify({"msg": "Bad username or password"}), 401

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=emailTest.id)
    # return jsonify(access_token=access_token), 200
    return jsonify({"token": access_token,
                    "code": 200,
                    "token ident": emailTest.id}), 200


# Endpoint for revoking the current users access token
@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out",
                    "code": 200}), 200


# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/user', methods=['GET'])
def get_all_users():
    users = NewUser.query.all()

    # output = []

    # for user in users:
    #     user_data = {}
    #     user_data['public_id'] = user.public_id
    #     user_data['name'] = user.name
    #     user_data['password'] = user.password
    #     user_data['admin'] = user.admin
    #     output.append(user_data)
    # return jsonify({'users' : output})

    # all_products = Product.query.all()
    result = user_schema.dump(users)
    return jsonify({'users': result.data})
    # return jsonify(users.data)

@app.route('/user/<user_id>', methods=['GET'])
def get_one_user():
    return ''

@app.route('/user', methods=['POST'])
def create_user():
    # data = request.get_json()
    # hashed_password = generate_password_hash(data['password'], method='sha256')
    # new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)

    name = request.json['name']
    password = generate_password_hash(request.json['password'], method='sha256')
    email = request.json['email']
    public_id = str(uuid.uuid4())
    role = request.json['role']
    

    new_user = NewUser(public_id, name, email, password, role)

    db.session.add(new_user)
    db.session.commit()
    # return jsonify({'message':'new user created'})
    # return user_schema.jsonify(new_user)
    result = user_schema.dump(new_user)
    return jsonify({"data":result.data,
                    "code": 200})
    # return (new_user)

@app.route('/user/<user_id>', methods=['PUT'])
def promote_user():
    return ''

@app.route('/user/<user_id>', methods=['DELETE'])
def delete_user():
    return ''

@app.route('/product', methods=['POST'])
def add_product():
    name = request.json['name']
    description = request.json['description']
    price = request.json['price']
    qty = request.json['qty']

    new_product = Product(name, description, price, qty)

    db.session.add(new_product)
    db.session.commit()

    result = product_schema.dump(new_product)
    return jsonify({"data":result.data,
                    "code": 200})

# get all products
@app.route('/product', methods=['GET'])
def get_products():
    all_products = Product.query.all()
    result = products_schema.dump(all_products)
    return jsonify({"data":result.data,
                    "code": 200})
    # return products_schema.jsonify(all_products)

# get single products
@app.route('/product/<id>', methods=['GET'])
def get_product(id):
    product = Product.query.get(id)
    
    result = product_schema.dump(product)
    return jsonify({"data":result.data,
                    "code": 200})

# update a product
@app.route('/product/<id>', methods=['PUT'])
def update_product(id):

    product = Product.query.get(id)

    name = request.json['name']
    description = request.json['description']
    price = request.json['price']
    qty = request.json['qty']

    product.name = name
    product.description = description
    product.price = price
    product.qty = qty

    db.session.commit()

    return product_schema.jsonify(product)

# Delete product
@app.route('/product/<id>', methods=['DELETE'])
def delete_product(id):
    try:
        product = Product.query.get(id)
        db.session.delete(product)
        db.session.commit()
        
        return product_schema.jsonify(product)
    except Exception as e:
        return jsonify({'error' : "there is an error"})
        # str(e)
    
# @app.route('/', methods=['GET'])
# def get():
#     return jsonify({ 'msg': 'Hello world'})

# run server
if __name__ == '__main__':
    app.run(debug = True)