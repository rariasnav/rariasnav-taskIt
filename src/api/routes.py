"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint, current_app
from api.models import db, User, ChooseGender, Roles, ServiceCategory, ServiceSubCategory, ServiceCategorySubCategory, ServiceRequest, ServiceRequestStatus, ServiceRequestOffer, ServiceRequestOfferStatus, OfferKnowledge, PictureUserUpload
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
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "Invalid input: No data provided"}), 400

        required_fields = ['email', 'password', 'nationality', 'gender', 'phone_number', 'role']
        for field in required_fields:
            if field not in body or not body[field]:
                return jsonify({"error": f"Missing field {field}"}), 400

        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, body['email']):
            return jsonify({"error": "Invalid email format"}), 400

        if User.query.filter_by(email=body['email']).first():
            return jsonify({"error": "Email already in use"}), 400        
    
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

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.error(f"Database error: {str(e)}")
        return jsonify({"error": "Database error ocurred"}), 500
    except KeyError as e:
        current_app.logger.error(f"Invalid value for field: {str(e)}")
        return jsonify({"error": f"Invalid value for field: {str(e)}"}), 400
    except Exception as e:
        current_app.logger.error(f"Error creating user")
        return jsonify({"error": f"Error creating user: {str(e)}"}), 500


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
    body = request.get_json()  

    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Invalid request"}), 401
        
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
        return jsonify({"msg": "Succesfully updated"}), 200  
      
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": str(e)}), 500

@api.route('/services_category', methods=['GET'])
def get_all_services_category():
    try:
        all_categories = ServiceCategory.query.filter_by(is_active=True).all()
        result = list(map(lambda category: category.serialize(), all_categories))
        return jsonify(result), 200
    
    except Exception as e:
        current_app.logger.error(f"Error getting categories: {str(e)}")
        return jsonify({"error": "Error getting categories"}), 500

@api.route('/services_subcategory', methods=['GET'])
def get_all_services_subcategory():
    try:
        all_subcategories = ServiceSubCategory.query.filter_by(is_active=True).all()
        result = list(map(lambda subcategory: subcategory.serialize(), all_subcategories))
        return jsonify(result), 200
    
    except Exception as e:
        current_app.logger.error(f"Error getting subcategories: {str(e)}")
        return jsonify({"error": "Error getting subcategories"}), 500

@api.route('/services_category_subcategory', methods=['GET'])
def get_all_services_category_subcategory():
    try:
        all_category_subcategory = ServiceCategorySubCategory.query.all()
        result = list(map(lambda category_subcategory : category_subcategory.serialize(), all_category_subcategory))

        return jsonify(result), 200
    
    except Exception as e:
        current_app.logger.error(f"Error getting categories subcategories: {str(e)}")
        return jsonify({"error": "Error getting categories subcategories"}), 500

@api.route('/services_category/<int:category_id>', methods=['GET'])
def get_category(category_id):
    try:
        if category_id <= 0:
            return jsonify({"error": "Invalid category ID"}), 400
        
        category = ServiceCategory.query.filter_by(id=category_id, is_active=True).one_or_none()

        if category is None:
            return jsonify({"error": "Category not found"}), 404

        return jsonify(category.serialize()), 200
    
    except SQLAlchemyError as e:
        current_app.logger.error(f"unexpected error: {str(e)}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        current_app.logger.error(f"Error getting category: {str(e)}")
        return jsonify({"error": "Error getting category"}), 500    

@api.route('/services_subcategory/<int:subcategory_id>', methods=['GET'])
def get_subcategory(subcategory_id):
    try:
        if subcategory_id <= 0:
            return jsonify({"error": "Invalid subcategory ID"}), 400
        
        subcategory = ServiceSubCategory.query.filter_by(id=subcategory_id, is_active=True).one_or_none()
        if subcategory is None:
            return jsonify({"error": "Subcategory not found"}), 404
        return jsonify(subcategory.serialize()), 200
    
    except SQLAlchemyError as e:
        current_app.logger.error(f"unexpected error: {str(e)}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        current_app.logger.error(f"Error getting subcategory: {str(e)}")
        return jsonify({"error": "Error getting subcategory"}), 500

@api.route('/services_category_subcategory/<int:category_subcategory_id>', methods=['GET'])
def get_category_subcategory_id(category_subcategory_id):
    try:        
        category_subcategory = ServiceCategorySubCategory.query.get_or_404(category_subcategory_id)
        return jsonify(category_subcategory.serialize()), 200
    
    except SQLAlchemyError as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        current_app.logger.error(f"Error getting category subcategory: {str(e)}")
        return jsonify({"error": "Error getting category subcategory"}), 500

@api.route('/services_category/<int:category_id>', methods=['DELETE'])
def delete_category(category_id):
    try:
        category = ServiceCategory.query.get_or_404(category_id)
        
        setattr(category, 'is_active', False)
        db.session.commit()

        return jsonify({"msg": "Category succesfully deactivated"}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@api.route('/services_subcategory/<int:subcategory_id>', methods=['DELETE'])
def delete_subcategory(subcategory_id):
    try:
        subcategory = ServiceSubCategory.query.get_or_404(subcategory_id)

        setattr(subcategory, 'is_active', False)
        db.session.commit()

        return jsonify({"msg": "Subcategory succesfully deactivated"}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@api.route('/services_category_subcategory/<int:category_subcategory_id>', methods=['DELETE'])
def delete_category_subcategory(category_subcategory_id):
    try:
        category_subcategory = ServiceCategorySubCategory.query.get_or_404(category_subcategory_id)
        db.session.delete(category_subcategory)
        db.session.commit()

        return jsonify({"msg": "CategorySubcategory succesfully deleted"}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@api.route('/services_category', methods=['POST'])
def add_category():
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "Invalid input: No data provided"}), 400
        
        required_fields = ['name', 'icon', 'description']
        for field in required_fields:
            if field not in body or not body[field]:
                return jsonify({"error": f"Invalid input: {field} is required"}), 400
            
        image = body.get('image', '')

        new_category = ServiceCategory(
            name=body['name'],
            icon=body['icon'],
            image=image,
            description=body['description'],
            is_active=True
        )
        db.session.add(new_category)
        db.session.commit()

        return jsonify({"msg": "Category created"}), 201
    
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    except KeyError as e:
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred"}), 500

@api.route('/services_subcategory', methods=['POST'])
def add_subcategory():
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "Invalid input: No data provided"}), 400
        
        required_fields = ['name', 'description']
        for field in required_fields:
            if field not in body or not body[field]:
                return jsonify({"error": f"Invalid input: {field} is required"}), 400

        new_subcategory = ServiceSubCategory(
            name = body['name'],
            description = body['description'],
            is_active = True
        )
        db.session.add(new_subcategory)
        db.session.commit()

        return jsonify({"msg": "Subcategory created"}), 201
    
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    except KeyError as e:
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"msg": "An unexpected error ocurred"}), 500

@api.route('/services_category_subcategory', methods=['POST'])
def add_category_subcategory():
    try:
        body= request.get_json()
        if not body:
            return jsonify({"error": "Invalid input: No data provided"}), 400
        
        required_fields = ['service_category_id', 'service_subcategory_id']
        for field in required_fields:
            if field not in body or not body[field]:
                return jsonify({"error": f"Invalid input: {field} is required"}), 400

        service_category = ServiceCategory.query.get_or_404(body['service_category_id'])
        service_subcategory = ServiceSubCategory.query.get_or_404(body['service_subcategory_id'])

        new_category_subcategory = ServiceCategorySubCategory(
            service_category_id=service_category.id,
            service_subcategory_id=service_subcategory.id
        )
        db.session.add(new_category_subcategory)
        db.session.commit()

        return jsonify({"msg": "CategorySubcategory created"}), 201
    
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    except KeyError as e:
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error ocurred"}), 500

@api.route('/services_category/<int:category_id>', methods=['PUT'])
def update_category(category_id):
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "Invalid input: No data provided"}), 400
        
        required_fields = ['name', 'icon', 'description']
        for field in required_fields:
            if field not in body or not body[field]:
                return jsonify({"error": f"Invalid input: {field} is required"}), 400

        category = ServiceCategory.query.get_or_404(category_id)

        category.name = body['name']
        category.icon = body['icon']
        category.image = body['image']
        category.description = body['description']

        db.session.commit()

        return jsonify({"msg": "Category updated"}), 200
    
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Database error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except KeyError as e:
        current_app.logger.error(f"Invalid input: {str(e)}")
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:        
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "An unexpected error ocurred"}), 500

@api.route('/services_subcategory/<int:subcategory_id>', methods=['PUT'])
def update_subcategory(subcategory_id):
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "Invalid input: No data provided"}), 400
        
        required_fields = ['name', 'description']
        for field in required_fields:
            if field not in body or not body[field]:
                return jsonify({"error": f"Invalid input: {field} is required"}), 400

        subcategory = ServiceSubCategory.query.get_or_404(subcategory_id)

        subcategory.name = body['name']
        subcategory.desciption = body['description']

        db.session.commit()

        return jsonify({"msg": "Subcategory updated"}), 200
    
    except SQLAlchemyError as e:
        db.session.rollbavk()
        return jsonify({"error": str(e)}), 500
    except KeyError as e:
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error ocurred"}), 500

@api.route('/service_request', methods=['GET'])
@jwt_required()
def get_all_services_requests():
    try: 
        email = get_jwt_identity()
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "Invalid request"}), 401

        service_requests = ServiceRequest.query.all()
        result = list(map(lambda service_request: service_request.serialize(), service_requests))

        return jsonify(result), 200
    
    except SQLAlchemyError as e:
        current_app.logger.error(f"Error getting service requests: {str(e)}")
        return jsonify({"error": "Error getting service requests"}), 500
    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "An unexpected error ocurred"}), 500

@api.route('/service_request/<int:service_request_id>', methods=['GET'])
@jwt_required()
def get_service_request(service_request_id):
    try:
        email = get_jwt_identity()
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "Invalid request"}), 401

        if service_request_id <= 0:
            return jsonify({"error": "Invalid service request ID"}), 400

        service_request = ServiceRequest.query.filter_by(id=service_request_id).first()
        if service_request is None:
            return jsonify({"msg": "Service request not found"})

        return jsonify(service_request.serialize()), 200
    
    except SQLAlchemyError as e:
        current_app.logger.error(f"Error getting service request: {str(e)}")
        return jsonify({"error": "Error getting service request"}), 500
    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "An unexpected error ocurred"}), 500

@api.route('/service_request', methods=['POST'])
@jwt_required()
def add_service_request():
    try:
        email = get_jwt_identity()
        body = request.get_json()    
        if not body:
            return jsonify({"error": "Invalid input: No data provided"}), 400

        user = User.query.filter_by(email=email).first() 
        if not user:
            return jsonify({"error": "Invalid service request post"}), 401
        
        required_fields = ['description', 'address', 'service_subcategory_id']
        for field in required_fields:
            if field not in body or not body[field]:
                return jsonify({"error": f"Invalid input: {field} is required"}), 400

        service_subcategory = ServiceSubCategory.query.get_or_404(body['service_subcategory_id'])       

        tools = body.get('tools', '')
        moving = body.get('moving', '')
        
        if user:
            service_request = ServiceRequest(
                description = body['description'],
                address = body['address'],
                tools = tools,
                moving = moving,
                service_subcategory_id = service_subcategory.id,
                user_id = user.id,
                is_active = True,
                status = ServiceRequestStatus.pending
            )

            db.session.add(service_request)
            db.session.commit()
            return jsonify({"msg": "Service request added"}), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Database error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except KeyError as e:
        current_app.logger.error(f"Invalid input: {str(e)}")
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        current_app.logger.error(f"Error posting service request: {str(e)}")
        return jsonify({"error": "Error posting service request"}), 500

@api.route('/service_request/<int:service_request_id>', methods=['DELETE'])
@jwt_required()
def delete_service_request(service_request_id):
    try:
        email = get_jwt_identity()
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "Invalid request"}), 401

        service_request = ServiceRequest.query.get_or_404(service_request_id)
        setattr(service_request, 'is_active', False)
        db.session.commit()

        return jsonify({"msg": "Service request deactivated"}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@api.route('/service_request_offer', methods=['GET'])
@jwt_required()
def get_all_service_request_offer():
    try:
        service_request_offers = ServiceRequestOffer.query.all()
        result = list(map(lambda service_request_offer: service_request_offer.serialize() ,service_request_offers))

        return jsonify(result), 200
    except SQLAlchemyError as e:
        current_app.logger.error(f"Error getting service request offers: {str(e)}")
        return jsonify({"error": "Error getting service request offers"}), 500
    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "An unexpected error ocurred"}), 500

@api.route('/service_request_offer', methods=['POST'])
@jwt_required()
def add_service_request_offer():
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "Invalid input: No data provided"}), 400
        
        required_fields = ['rate', 'status', 'service_request_id', 'vendor_email', 'client_email']
        for field in required_fields:
            if field not in body or not body[field]:
                return jsonify({"error": f"Invalid input: {field} is required"}), 400
        
        vendor_user = User.query.filter_by(email=body['vendor_email']).first()
        if not vendor_user:
            return jsonify({"error": "Invalid service request offer post: vendor_email"}), 401
        
        client_user = User.query.filter_by(email=body['client_email']).first()
        if not client_user:
            return jsonify({"error": "Invalid service request offer post: client_email"}), 401

        service_request = ServiceRequest.query.get_or_404(body['service_request_id'])

        if vendor_user:    
            service_request_offer = ServiceRequestOffer(
                rate = body['rate'],
                status = body['status'],
                service_request_id = service_request.id,
                user_client_id = client_user.id,
                user_vendor_id = vendor_user.id
            ) 
            db.session.add(service_request_offer)
            db.session.commit()

            return jsonify({"msg": "Service request offer added"}), 201
        
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Database error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except KeyError as e:
        current_app.logger.error(f"Invalid input: {str(e)}")
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        current_app.logger.error(f"Error posting service request offer: {str(e)}")
        return jsonify({"error": "Error posting service request offer"}), 500

@api.route('/offer_knowledge', methods=['GET'])
@jwt_required()
def get_all_known_offers():
    try:
        email = get_jwt_identity()     
        user = User.query.filter_by(email=email).first()
        if user is None:
            return jsonify({"error": "Invalid request"}), 401

        vendor_id = request.args.get('vendor_id')
        if not vendor_id:
            return jsonify({"error": "vendor_id is required"}), 400
        
        vendor = User.query.filter_by(id=vendor_id).first()
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
  
        offer_knowledge = OfferKnowledge.query.filter_by(user_id=vendor.id).all()
        result = list(map(lambda offer: offer.serialize() ,offer_knowledge))

        return jsonify(result), 200
        
    except SQLAlchemyError as e:
        current_app.logger.error(f"Database error: {str(e)}")
        return jsonify({"error": f"Database error"}), 500
    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"eror": "Unexpected error"}), 500
    
@api.route('/service_request_offer/<int:service_request_offer_id>/<int:service_request_id>', methods=['PUT'])
@jwt_required()
def update_service_request_offer(service_request_offer_id,service_request_id):
    try:
        email = get_jwt_identity()
        body = request.get_json()
        if not body:
            return jsonify({"error": "Invalid input: No data provided"}), 400

        user = User.query.filter_by(email=email).first()
        if user is None:
            return jsonify({ "error": "Invalid request" }), 401
        
        service_request = ServiceRequest.query.get_or_404(service_request_id, description="Service request not found")
        service_request_offer = ServiceRequestOffer.query.get_or_404(service_request_offer_id, description="Service request offer not found")

        if "service_request_status" in body:
            if body["service_request_status"] not in [status.name for status in ServiceRequestStatus]:
                return jsonify({"error": "Invalid service request status"}), 400
            service_request.status = ServiceRequestStatus[body["service_request_status"]]

        if "service_request_offer_status" in body:
            if body["service_request_offer_status"] not in [status.name for status in ServiceRequestOfferStatus]:
                return jsonify({"error": "Invalid service request offer status"}), 400
            service_request_offer.status = ServiceRequestOfferStatus[body["service_request_offer_status"]]

        db.session.commit()
        
        return jsonify({ 'msg': 'Service request offer updated' }), 200
        
    except SQLAlchemyError as e:
        current_app.logger.error(f"Database error: {str(e)}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "Unexpected error"}), 500
    
@api.route('/upload_profile_picture', methods=['PUT'])
@jwt_required()
def upload_user_pictures():
    email = get_jwt_identity()
    data_file = request.files

    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({"error": "Invalid request"}), 401

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
        return jsonify({"error": "Invalid request"}), 401
    
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
        return jsonify({"error": "Invalid request"}), 401
    
    if user:
        user_pictures = PictureUserUpload.query.all()
        result = list(map(lambda pictures: pictures.serialize(), user_pictures))
        return jsonify(result), 200