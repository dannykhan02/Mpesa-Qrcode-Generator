from flask import Flask, jsonify, send_file
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
import qrcode
from qrcode.constants import ERROR_CORRECT_L
from io import BytesIO
import os
import hashlib
from models import db, QRCode, QRCodeEntityType, User, Merchant, MPesaAgent, UserRole
from email_utils import send_email
from auth import role_required

# Helper function to generate QR code
def generate_qr_code(data, directory="qrcodes"):
    qr = qrcode.QRCode(
        version=1,
        error_correction=ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    qr_directory = os.path.join("static", directory)
    os.makedirs(qr_directory, exist_ok=True)

    hashed_filename = hashlib.md5(data.encode()).hexdigest()
    qr_code_path = os.path.join(qr_directory, f"qrcode_{hashed_filename}.png")

    img.save(qr_code_path)
    return img, qr_code_path

# Request parsers
qr_code_post_parser = reqparse.RequestParser()
qr_code_post_parser.add_argument('merchant_type', type=str, required=False)
qr_code_post_parser.add_argument('merchant_id', type=int, required=False)
qr_code_post_parser.add_argument('agent_type', type=str, required=False)
qr_code_post_parser.add_argument('agent_id', type=int, required=False)

qr_code_put_parser = reqparse.RequestParser()
qr_code_put_parser.add_argument('qr_code_url', type=str, required=True)

class QRCodeResource(Resource):
    @jwt_required()
    @role_required(UserRole.ADMIN.value)
    def get(self, qr_code_id=None):
        if qr_code_id:
            qr_code = QRCode.query.get_or_404(qr_code_id)
            return qr_code.as_dict(), 200
        return [qr_code.as_dict() for qr_code in QRCode.query.all()], 200

    @jwt_required()
    @role_required(UserRole.ADMIN.value)
    def post(self):
        args = qr_code_post_parser.parse_args()
        merchant_type, merchant_id = args['merchant_type'], args['merchant_id']
        agent_type, agent_id = args['agent_type'], args['agent_id']
        
        qr_code_url, entity_type_enum, entity_id = None, None, None

        if merchant_id:
            merchant = Merchant.query.get_or_404(merchant_id)
            entity_id = merchant.id
            try:
                entity_type_enum = QRCodeEntityType(merchant_type)
            except ValueError:
                return {"msg": "Invalid merchant type"}, 400
            qr_code_url = f"https://example.com/qr/merchant/{merchant.merchant_type.lower()}/{merchant.id}"

        elif agent_id:
            agent = MPesaAgent.query.get_or_404(agent_id)
            entity_id = agent.id
            qr_code_url = f"https://example.com/qr/agent/{agent.agent_number}"
            entity_type_enum = QRCodeEntityType.AGENT
        else:
            return {"msg": "Invalid entity type"}, 400

        new_qr_code = QRCode(entity_id=entity_id, identity_type=entity_type_enum, qr_code_url=qr_code_url)
        db.session.add(new_qr_code)
        db.session.commit()

        img, qr_code_path = generate_qr_code(qr_code_url)
        user = User.query.get(entity_id)
        if user:
            send_email(user.email, "Your QR Code", "Find your QR code attached.", attachment_path=qr_code_path)

        return {"msg": "QR code generated successfully", "qr_code_url": qr_code_url}, 201

    @jwt_required()
    @role_required(UserRole.ADMIN.value)
    def put(self, qr_code_id):
        args = qr_code_put_parser.parse_args()
        qr_code_url = args['qr_code_url']
        qr_code = QRCode.query.get_or_404(qr_code_id)
        qr_code.qr_code_url = qr_code_url
        db.session.commit()
        
        img, qr_code_path = generate_qr_code(qr_code_url)
        user = User.query.get(qr_code.entity_id)
        if user:
            send_email(user.email, "Updated QR Code", "Find your updated QR code attached.", attachment_path=qr_code_path)

        return {"msg": "QR code updated successfully"}, 200

    @jwt_required()
    @role_required(UserRole.ADMIN.value)
    def delete(self, qr_code_id):
        qr_code = QRCode.query.get_or_404(qr_code_id)
        hashed_filename = hashlib.md5(qr_code.qr_code_url.encode()).hexdigest()
        qr_code_path = os.path.join("static", "qrcodes", f"qrcode_{hashed_filename}.png")

        if os.path.exists(qr_code_path):
            os.remove(qr_code_path)
        
        db.session.delete(qr_code)
        db.session.commit()

        return {"msg": "QR code deleted successfully"}, 200



class QRCodeImageResource(Resource):
    @jwt_required()
    def get(self, qr_code_id):
        qr_code = QRCode.query.get_or_404(qr_code_id)
        qr_code_path = f"static/qrcodes/qrcode_{qr_code.qr_code_url}.png"

        if not os.path.exists(qr_code_path):
            return {"msg": "QR code image not found"}, 404

        return send_file(qr_code_path, mimetype="image/png")

class MerchantQRCodesResource(Resource):
    @jwt_required()
    @role_required(UserRole.MERCHANT.value)
    def get(self, merchant_id):  # Use merchant_id instead of merchant.id
        merchant = Merchant.query.get_or_404(merchant_id)
        qr_codes = QRCode.query.filter_by(entity_id=merchant.id).all()

        # Filter QR codes based on merchant type
        if merchant.merchant_type == 'Paybill':
            qr_codes = [qr_code for qr_code in qr_codes if qr_code.identity_type == QRCodeEntityType.PAYBILL]
        elif merchant.merchant_type == 'Till':
            qr_codes = [qr_code for qr_code in qr_codes if qr_code.identity_type == QRCodeEntityType.TILL]
        elif merchant.merchant_type == 'Pochi':
            qr_codes = [qr_code for qr_code in qr_codes if qr_code.identity_type == QRCodeEntityType.POCHI]

        return [qr_code.as_dict() for qr_code in qr_codes], 200


class AgentQRCodesResource(Resource):
    @jwt_required()
    @role_required(UserRole.AGENT.value)
    def get(self, agent_id):  # Use agent_id instead of agent.id
        qr_codes = QRCode.query.filter_by(entity_id=agent_id, identity_type=QRCodeEntityType.AGENT).all()
        return [qr_code.as_dict() for qr_code in qr_codes], 200

# Register resources with the API
def register_qrcode_resources(api):
    """Registers QR code-related resources with Flask-RESTful API."""
    api.add_resource(QRCodeResource, "/api/qrcodes", "/api/qrcodes/<int:qr_code_id>")
    api.add_resource(QRCodeImageResource, "/api/qrcodes/image/<int:qr_code_id>")
    api.add_resource(MerchantQRCodesResource, "/api/qrcodes/merchant/<int:merchant_id>")
    api.add_resource(AgentQRCodesResource, "/api/qrcodes/agent/<int:agent_id>")
