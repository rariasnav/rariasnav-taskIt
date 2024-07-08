"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint, current_app
from api.models import db, User, ChooseGender, Roles, ServiceCategory, ServiceSubCategory, ServiceCategorySubCategory, ServiceRequest, ServiceRequestOffer, OfferKnowledge, PictureUserUpload
from api.utils import generate_sitemap, APIException
from flask_cors import CORS

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import generate_password_hash

import cloudinary.uploader
import re

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route('/signup', methods=['POST'])
def create_user():
    body = request.get_json()

    required_fields = ['email', 'password', 'nationality', 'gender', 'phone_number', 'role']
    for field in required_fields:
        if field not in body:
            return jsonify({"msg": f"Missing field {field}"}), 400

    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, body['email']):
        return jsonify({"msg": "Invalid email format"}), 400

    if User.query.filter_by(email=body['email']).first():
        return jsonify({"msg": "Email already in use"}), 400
    
    try:
        password_hash = current_app.bcrypt.generate_password_hash(body['password']).decode('utf-8')

        new_user = User(
            email=body['email'],
            password=password_hash,
            nationality=body['nationality'],
            gender=ChooseGender[body['gender']],
            phone_number=body['phone_number'],
            is_active=True,
            role=Roles[body['role']]
        )
        db.session.add(new_user)
        db.session.commit()        

        return jsonify({ 'msg': 'User created' }), 201

    except KeyError as e:
        return jsonify({"msg": f"Invalid value for field: {str(e)}"}), 400
    except IntegrityError:
        db.session.rollback()
        return jsonify({"msg": "Database error ocurred"}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": f"An error ocurred: {str(e)}"}), 500


#user update password and email
@api.route('/user_update/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    body = request.get_json()
    password_hash = current_app.bcrypt.generate_password_hash(body['password']).decode('utf-8')
    updating_user = User.query.filter_by(id=user_id).first()
    updating_email = User.query.filter_by(email=body['email']).first()

    if updating_email != None:
        return jsonify({ 'msg': 'Email already in use' })
    
    if updating_email == None:
        updating_user.email = body['email']
        updating_user.password = password_hash

        db.session.commit()

        return jsonify({ 'msg': 'User updated' }), 200
    
@api.route('/login', methods=['POST'])
def login():
    try:
        email = request.json.get("email", None)
        password = request.json.get("password", None)
        user = User.query.filter_by(email=email).first()

        if user is None or not current_app.bcrypt.check_password_hash(user.password, password):
            return jsonify({"msg": "Bad email or password"}), 401

        access_token = create_access_token(identity=email)        
        user_data = {
            "id": user.id,
            "email": user.email,
            "role": user.role.name
        }
        return jsonify(user=user_data, access_token=access_token), 200        
    
    except Exception as e:
        current_app.logger.error(f"An error ocurred: {str(e)}")
        return jsonify({"msg": "Internal server error"}), 500


@api.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    try:
        user_email = get_jwt_identity()
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return jsonify({"msg": "User not found"}), 404

        user_data = user.serialize()

        if user.role == Roles.vendor:
            user_data = user.serialize_vendor_knowledge()

        response_body = {
            "msg": "User found",
            "user": user_data
        }

        return jsonify(response_body), 200

    except Exception as e:
        current_app.logger.error(f"An error ocurred: {str(e)}")
        return jsonify({"msg": "Internal server error"}), 500

@api.route('/user_information', methods=['PUT'])
@jwt_required()
def fill_user_information():
    email = get_jwt_identity()
    body = request.get_json()  
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404
        
    for key in body:
        for col in user.serialize():
            if key == col and key != "id":
                setattr(user, key, body[key])

    if user.role == Roles.vendor and "knowledge" in body:
        for subcategory_id in body['knowledge']:
            if not OfferKnowledge.query.filter_by(user_id=user.id, service_subcategory_id=subcategory_id).first():
                new_offer_knowledge = OfferKnowledge(user_id=user.id, service_subcategory_id=subcategory_id)
                db.session.add(new_offer_knowledge)

    try:
        db.session.commit()        
        response_body = {
            "msg": "succesfully updated"
        }
        return jsonify(response_body), 200    
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": str(e)}), 500

@api.route('/services_category', methods=['GET'])
def get_all_services_category():
    all_categories = ServiceCategory.query.filter_by(is_active=True).all()
    result = list(map(lambda category: category.serialize(), all_categories))

    return jsonify(result), 200

@api.route('/services_subcategory', methods=['GET'])
def get_all_services_subcategory():
    all_subcategories = ServiceSubCategory.query.filter_by(is_active=True).all()
    result = list(map(lambda subcategory: subcategory.serialize(), all_subcategories))

    return jsonify(result), 200

@api.route('/services_category_subcategory', methods=['GET'])
def get_all_services_category_subcategory():
    all_category_subcategory = ServiceCategorySubCategory.query.all()
    result = list(map(lambda category_subcategory : category_subcategory.serialize(), all_category_subcategory))

    return jsonify(result), 200

@api.route('/services_category/<int:category_id>', methods=['GET'])
def get_category(category_id):
    category = ServiceCategory.query.filter_by(id=category_id).first()

    return jsonify(category.serialize()), 200

@api.route('/services_subcategory/<int:subcategory_id>', methods=['GET'])
@jwt_required()
def get_subcategory(subcategory_id):
    subcategory = ServiceSubCategory.query.filter_by(id=subcategory_id).first()

    return jsonify(subcategory.serialize()), 200

@api.route('/services_category_subcategory/<int:category_subcategory_id>', methods=['GET'])
@jwt_required()
def get_category_subcategory_id(category_subcategory_id):
    category_subcategory = ServiceCategorySubCategory.query.filter_by(id=category_subcategory_id).first()

    return jsonify(category_subcategory.serialize()), 200

@api.route('/services_category/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    category = ServiceCategory.query.filter_by(id=category_id).first()
    
    setattr(category, 'is_active', False)
    db.session.commit()

    return jsonify({"msg": "Category deleted"}), 200

@api.route('/services_subcategory/<int:subcategory_id>', methods=['DELETE'])
@jwt_required()
def delete_subcategory(subcategory_id):
    subcategory = ServiceSubCategory.query.filter_by(id=subcategory_id).first()

    setattr(subcategory, 'is_active', False)
    db.session.commit()

    return jsonify({"msg": "Subcategory deleted"}), 200

@api.route('/services_category_subcategory/<int:category_subcategory_id>', methods=['DELETE'])
@jwt_required()
def delete_category_subcategory(category_subcategory_id):
    category_subcategory = ServiceCategorySubCategory.query.filter_by(id=category_subcategory_id).first()

    db.session.delete(category_subcategory)
    db.session.commit()

    return jsonify({"msg": "CategorySubcategory deleted"}), 200

@api.route('/services_category', methods=['POST'])
@jwt_required()
def add_category():
    body = request.get_json()
    new_category = ServiceCategory(
        name = body['name'],
        icon = body['icon'],
        image = body['image'],
        description = body['description'],
        is_active = True
    )
    db.session.add(new_category)
    db.session.commit()

    return jsonify({"msg": "Category created"}), 200

@api.route('/services_subcategory', methods=['POST'])
@jwt_required()
def add_subcategory():
    body = request.get_json()
    new_subcategory = ServiceSubCategory(
        name = body['name'],
        description = body['description'],
        is_active = True
    )
    db.session.add(new_subcategory)
    db.session.commit()

    return jsonify({"msg": "Subcategory created"}), 200

@api.route('/services_category_subcategory', methods=['POST'])
@jwt_required()
def add_category_subcategory():
    body= request.get_json()
    service_category = ServiceCategory.query.filter_by(id=body['service_category_id']).first()
    service_subcategory = ServiceSubCategory.query.filter_by(id=body['service_subcategory_id']).first()
    new_category_subcategory = ServiceCategorySubCategory(
        service_category_id = service_category.id,
        service_subcategory_id = service_subcategory.id
    )

    db.session.add(new_category_subcategory)
    db.session.commit()

    return jsonify({"msg": "CategorySubcategory created"}), 200

@api.route('/services_category/<int:category_id>', methods=['PUT'])
@jwt_required()
def update_category(category_id):
    body = request.get_json()
    category = ServiceCategory.query.filter_by(id=category_id).first()

    category.name = body['name']
    category.icon = body['icon']
    category.image = body['image']
    category.desciption = body['description']

    db.session.commit()

    return jsonify({"msg": "Category updated"}), 200

@api.route('/services_subcategory/<int:subcategory_id>', methods=['PUT'])
@jwt_required()
def update_subcategory(subcategory_id):
    body = request.get_json()
    subcategory = ServiceSubCategory.query.filter_by(id=subcategory_id).first()

    subcategory.name = body['name']
    subcategory.desciption = body['description']

    db.session.commit()

    return jsonify({"msg": "Subcategory updated"}), 200

@api.route('/service_request', methods=['GET'])
@jwt_required()
def get_all_services_requests():
    services_requests = ServiceRequest.query.all()
    result = list(map(lambda service_request: service_request.serialize(), services_requests))

    return jsonify(result), 200

@api.route('/service_request/<int:service_request_id>', methods=['GET'])
@jwt_required()
def get_service_request(service_request_id):
    service_request = ServiceRequest.query.filter_by(id=service_request_id).first()
    if service_request is None:
        return jsonify({"msg": "Service request not found"})

    return jsonify(service_request.serialize()), 200

@api.route('/service_request', methods=['POST'])
@jwt_required()
def add_service_request():
    body = request.get_json()    
    service_subcategory_id = ServiceSubCategory.query.get(body['service_subcategory_id'])
    if not service_subcategory_id:
        return jsonify({"msg": "Service id not valid"}), 400 
    user = User.query.filter_by(email=body['email']).first()    
    
    if user:
        service_request = ServiceRequest(
            description = body['description'],
            address = body['address'],
            tools = body['tools'],
            moving = body['moving'],
            service_subcategory_id = body['service_subcategory_id'],
            user_id = user.id,
            is_active = True,
            status = 'pending'
        )

        db.session.add(service_request)
        db.session.commit()
        return jsonify({"msg": "Service request added"}), 200
    else:
        return jsonify({"msg": "Email not valid"}), 400

@api.route('/service_request/<int:service_request_id>', methods=['DELETE'])
@jwt_required()
def delete_service_request(service_request_id):
    service_request = ServiceRequest.query.filter_by(id=service_request_id).first()
    setattr(service_request, 'is_active', False)

    db.session.commit()

    return jsonify({"msg": "Service request deleted"}), 200

@api.route('/service_request_offer', methods=['GET'])
@jwt_required()
def get_all_service_request_offer():
    service_request_offers = ServiceRequestOffer.query.all()
    result = list(map(lambda service_request_offer: service_request_offer.serialize() ,service_request_offers))

    return jsonify(result), 200

@api.route('/service_request_offer', methods=['POST'])
@jwt_required()
def add_service_request_offer():
    body = request.get_json()
    service_request_id = ServiceRequest.query.get(body['service_request_id'])
    if not service_request_id:
        return jsonify({"msg": "Service request id not valid"}), 400 
    
    vendor_user = User.query.filter_by(email=body['vendor_email']).first()

    if not vendor_user:
         return jsonify({"msg": "Vendor user error"}), 400 
    client_user = User.query.filter_by(email=body['client_email']).first()

    if vendor_user:    
        service_request_offer = ServiceRequestOffer(
            rate = body['rate'],
            status = body['status'],
            service_request_id = body['service_request_id'],
            user_client_id = client_user.id,
            user_vendor_id = vendor_user.id
        ) 
        db.session.add(service_request_offer)
        db.session.commit()

        return jsonify({"msg": "Service request offer added"}), 200
    else:
        return jsonify({"msg": "Email not valid"}), 400

@api.route('/offer_knowledge', methods=['GET'])
@jwt_required()
def get_all_known_offers():
    email = get_jwt_identity() 
    
    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({ 'msg': 'Email not in system' }), 401

    if user:    
        offer_knowledge = OfferKnowledge.query.filter_by(user_id=user.id).all()
        result = list(map(lambda offer: offer.serialize() ,offer_knowledge))
        return jsonify(result), 200
    
@api.route('/service_request_offer/<int:service_request_offer_id>/<int:service_request_id>', methods=['PUT'])
@jwt_required()
def update_service_request_offer(service_request_offer_id,service_request_id):
    email = get_jwt_identity()
    body = request.get_json()

    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({ 'msg': 'Email not in system' }), 401
    
    service_request = ServiceRequest.query.filter_by(id=service_request_id).first()
    if service_request is None:
        return jsonify({ 'msg': 'Service request does not exist' }), 401
    
    service_request_offer = ServiceRequestOffer.query.filter_by(id=service_request_offer_id).first()
    if service_request_offer is None:
        return jsonify({ 'msg': 'Service request offer does not exist' }), 401
    
    if user and service_request_offer:
        service_request.status = body["service_request_status"]
        service_request_offer.status = body["service_request_offer_status"]

        db.session.commit()

        return jsonify({ 'msg': 'Service request offer updated' }), 200
    
@api.route('/upload_profile_picture', methods=['PUT'])
@jwt_required()
def upload_user_pictures():
    email = get_jwt_identity()
    data_file = request.files

    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({ 'msg': 'Email not in system' }), 401

    profile_picture = data_file.get("profile_picture")

    if 'profile_picture' not in request.files:
        return jsonify({"error": "No file part"}), 400

    result_profile_picture = cloudinary.uploader.upload(profile_picture)
    user.profile_picture = result_profile_picture['secure_url']

    db.session.commit()

    return jsonify({"msg": "Profile picture updated"}), 200

@api.route('/user_gallery_pictures', methods=['POST'])
@jwt_required()
def upload_gallery_picture():
    email = get_jwt_identity()
    data_file = request.files
    data_form = request.form

    user= User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({"msg": "Email not in system"}), 401
    
    gallery_picture = data_file.get('gallery_picture')

    if gallery_picture is None:
        return jsonify({"error": "No file part"}), 400
    
    result_gallery_picture = cloudinary.uploader.upload(gallery_picture)

    if gallery_picture:    
        new_gallery_picture = PictureUserUpload(
            user = user,
            gallery_pictures = result_gallery_picture.get("secure_url"),
            gallery_pictures_public_id = result_gallery_picture.get("public_id")
        ) 
        db.session.add(new_gallery_picture)
        db.session.commit()

        return jsonify({ 'msg': 'Gallery picture uploaded' }), 200

@api.route('/user_gallery_pictures', methods=['GET'])
@jwt_required()
def get_user_gallery_pictures():
    email = get_jwt_identity()

    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({ 'msg': 'Email not in system' }), 401
    
    if user:
        user_pictures = PictureUserUpload.query.all()
        result = list(map(lambda pictures: pictures.serialize(), user_pictures))
        return jsonify(result), 200