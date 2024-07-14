from flask_sqlalchemy import SQLAlchemy
import enum

db = SQLAlchemy()

class Roles(enum.Enum):
    client = 'client'
    vendor = 'vendor'

class ChooseGender(enum.Enum):
    non_binary = 'non_binary'
    female = 'female'
    male = 'male'

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), unique=False, nullable=False)
    is_active = db.Column(db.Boolean(), unique=False, nullable=False)
    full_name = db.Column(db.String(250), unique=False, nullable=True)
    date_of_birth = db.Column(db.String, unique=False, nullable=True)       
    phone_number = db.Column(db.BigInteger, unique=True, nullable=False)
    address = db.Column(db.String(120), unique=False, nullable=True)
    profile_resume = db.Column(db.String(400), unique=False, nullable=True)
    role = db.Column(db.Enum(Roles), unique=False, nullable=False)
    gender = db.Column(db.Enum(ChooseGender), unique=False, nullable=False)
    profile_picture = db.Column(db.String(100), unique=False, nullable=True)
    nationality = db.Column(db.String(120), unique=False, nullable=False)
    service_request = db.relationship('ServiceRequest', backref='user', lazy=True) 
    offer_knowledge = db.relationship('OfferKnowledge', backref='user', lazy=True) 
    picture_user_upload = db.relationship('PictureUserUpload', backref='user', lazy=True) 
    service_request_offer = db.relationship('ServiceRequestOffer', uselist=True, backref='user', foreign_keys='ServiceRequestOffer.user_client_id', lazy=True)
    service_request_offer = db.relationship('ServiceRequestOffer', uselist=True, backref='user', foreign_keys='ServiceRequestOffer.user_vendor_id', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'

    def serialize(self):   
        return {
            "id": self.id,
            "email": self.email,
            "is_active": self.is_active,
            "full_name": self.full_name,           
            "date_of_birth": self.date_of_birth,            
            "phone_number": self.phone_number,
            "address": self.address,
            "role": self.role.name,
            "gender": self.gender.name,
            "profile_resume": self.profile_resume,
            "nationality": self.nationality,
            "profile_picture": self.profile_picture
        }
    def serialize_vendor_knowledge(self):
        if self.role != Roles.vendor:
            return None
        knowledge = OfferKnowledge.query.filter_by(user_id=self.id).first()
        if knowledge is not None:
            knowledge = knowledge.serialize_client()
        return {
            'user': self.serialize(),
            'knowledge': knowledge
        }    

class ServiceCategory(db.Model):
    __tablename__ = 'servicecategory'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    is_active = db.Column(db.Boolean(), nullable=False, default=True)
    icon = db.Column(db.String(80), nullable=False)
    image = db.Column(db.String(250), nullable=True)
    description = db.Column(db.String(120), nullable=False)
    service_category_subcategory = db.relationship('ServiceCategorySubCategory', backref='servicecategory', lazy=True) 
    
    def __repr__(self):
        return f'<ServiceCategory {self.name}>'

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "icon": self.icon,
            "description": self.description,
            "image": self.image,
            "is_active": self.is_active
        }
    
class ServiceSubCategory(db.Model):
    __tablename__ = 'servicesubcategory'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    is_active = db.Column(db.Boolean(), nullable=False, default=True)
    description = db.Column(db.String(250), nullable=False)
    service_category_subcategory = db.relationship('ServiceCategorySubCategory', backref='servicesubcategory', lazy=True) 
    service_request = db.relationship('ServiceRequest', backref='servicesubcategory', lazy=True)
    offer_knowledge = db.relationship('OfferKnowledge', backref='servicesubcategory', lazy=True)
    
    def __repr__(self):
        return f'<ServiceSubCategory {self.name}>'

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_active": self.is_active
        }
    
class ServiceCategorySubCategory(db.Model):
    __tablename__ = 'servicecategorysubcategory'
    id = db.Column(db.Integer, primary_key=True)
    service_category_id = db.Column(db.Integer, db.ForeignKey('servicecategory.id'), nullable=False)
    service_subcategory_id = db.Column(db.Integer, db.ForeignKey('servicesubcategory.id'), nullable=False)
    
    def __repr__(self):
        return f'<ServiceCategorySubCategory {self.id}>'

    def serialize(self):
        service_category = ServiceCategory.query.get(self.service_category_id)
        if service_category is not None:
            service_category = service_category.serialize() 
        service_subcategory = ServiceSubCategory.query.get(self.service_subcategory_id)
        if service_subcategory is not None:
            service_subcategory = service_subcategory.serialize() 
    
        return {
            "id": self.id,
            "service_category": service_category,
            "service_subcategory": service_subcategory
        }

class ServiceRequestStatus(enum.Enum):
    pending = 'pending'
    taken = 'taken'
    done = 'done'
    
class ServiceRequest(db.Model):
    __tablename__='servicerequest'
    id = db.Column(db.Integer, primary_key=True)    
    is_active = db.Column(db.Boolean(), nullable=False, default=True)
    status = db.Column(db.Enum(ServiceRequestStatus), unique=False, nullable=False)
    description = db.Column(db.String(250), nullable=False)
    address = db.Column(db.String(80), nullable=False)
    tools = db.Column(db.String(250), nullable=True)
    moving = db.Column(db.String(250), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_subcategory_id = db.Column(db.Integer, db.ForeignKey('servicesubcategory.id'), nullable=False)
    service_request_offer = db.relationship('ServiceRequestOffer', backref='servicerequest', lazy=True)

    def __repr__(self):
        return f'<ServiceRequest {self.id}>'

    def serialize(self):
        service_subcategory_id = ServiceSubCategory.query.get(self.service_subcategory_id)
        if service_subcategory_id is not None:
            service_subcategory_id = service_subcategory_id.serialize()
        user = User.query.get(self.user_id)
        if user is not None:
            user = user.serialize()

        return{
            "id": self.id,
            "service_subcategory_id": service_subcategory_id,
            "description": self.description,
            "address": self.address,
            "tools": self.tools,
            "moving": self.moving,
            "user": user,
            "is_active": self.is_active,
            "status": self.status.name
        }

class ServiceRequestOfferStatus(enum.Enum):
    accepted = 'accepted'
    pending = 'pending'
    finished = 'finished'

class ServiceRequestOffer(db.Model):
    __tablename__='servicerequestoffer'
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.Enum(ServiceRequestOfferStatus), nullable=False)
    rate = db.Column(db.Integer, nullable=False)
    service_request_id = db.Column(db.Integer, db.ForeignKey('servicerequest.id'), nullable=False)
    user_client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_vendor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)    

    def __repr__(self):
        return f'<ServiceRequestOffer {self.id}>'
    
    def serialize(self):
        service_request_id = ServiceRequest.query.get(self.service_request_id)
        if service_request_id is not None:
            service_request_id = service_request_id.serialize()

        user_client_id = User.query.get(self.user_client_id)
        if user_client_id is not None:
            user_client_id = user_client_id.serialize()

        user_vendor_id = User.query.get(self.user_vendor_id)
        if user_vendor_id is not None:
            user_vendor_id = user_vendor_id.serialize()

        return{
            "id": self.id,
            "service_request_id": service_request_id,
            "status": self.status.name,
            "user_client_id": user_client_id,
            "user_vendor_id": user_vendor_id,
            "rate": self.rate
        }

class OfferKnowledge(db.Model):
    __tablename__ = 'offerknowledge'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_subcategory_id = db.Column(db.Integer, db.ForeignKey('servicesubcategory.id'), nullable=False)

    def __repr__(self):
        return f'<OfferKnowledge {self.id}>'

    def serialize(self):
        knowledge = ServiceSubCategory.query.get(self.service_subcategory_id)
        if knowledge is not None:
            knowledge = knowledge.serialize() 

        user = User.query.get(self.user_id)
        if user is not None:
            user = user.serialize()       
        
        return {
            "id": self.id,
            "knowledge": knowledge,
            "user": user
        }
    def serialize_client(self):
        knowledge = ServiceSubCategory.query.get(self.service_subcategory_id)
        if knowledge is not None:
            knowledge = knowledge.serialize() 
        return {
            "id": self.id,
            "knowledge": knowledge
        }
    
class PictureUserUpload(db.Model):
    __tablename__ = 'pictureuserupload'
    id = db.Column(db.Integer, primary_key=True)
    gallery_pictures = db.Column(db.String(100), nullable=True)
    gallery_pictures_public_id = db.Column(db.String(80), nullable=True)    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<PictureUserUpload {self.id}>'
    
    def serialize(self):
        user = User.query.get(self.user_id)
        if user is not None:
            user = user.serialize()

        return {
            "id": self.id,
            "user": user,
            "gallery_pictures": self.gallery_pictures,
            "gallery_pictures_public_id": self.gallery_pictures_public_id
        }