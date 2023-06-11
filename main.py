import pymysql
pymysql.install_as_MySQLdb()
from flask import Flask, make_response, jsonify, render_template,session
from flask_restx import Resource, Api, reqparse
from flask_cors import  CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt, os,random
from flask_mail import Mail, Message

# Yolov5 library
import cv2
from PIL import Image
import torch
import numpy as np
from pathlib import Path
from models.experimental import attempt_load
from utils.general import non_max_suppression, scale_coords, check_img_size
from utils.plots import plot_one_box
from utils.torch_utils import select_device

app = Flask(__name__)
api = Api(app)
CORS(app)
port = int(os.environ.get("RAILWAY_PORT", 5000))
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/kendaraan"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'whateveryouwant'
# mail env config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
mail = Mail(app)
# mail env config
db = SQLAlchemy(app)



class Users(db.Model):
    id       = db.Column(db.Integer(), primary_key=True, nullable=False)
    firstname     = db.Column(db.String(30), nullable=False)
    lastname     = db.Column(db.String(30), nullable=False)
    email    = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_verified = db.Column(db.Boolean(),nullable=False)
    createdAt = db.Column(db.Date)
    updatedAt = db.Column(db.Date)

# class History(db.Model):
#     id = db.Column(db.Integer(), primary_key=True, nullable=False)
#     nama = db.Column(db.String(30), nullable=False)
#     jenis_kendaraan = db.Column(db.String(30), nullable=False)
#     tanggal = db.Column(db.Date)
#     waktu = db.Column(db.Time)




# Email functions
# https://medium.com/@stevenrmonaghan/password-reset-with-flask-mail-protocol-ddcdfc190968
# https://www.youtube.com/watch?v=g_j6ILT-X0k
# https://stackoverflow.com/questions/72547853/unable-to-send-email-in-c-sharp-less-secure-app-access-not-longer-available

#history
# historyParser = reqparse.RequestParser()
# historyParser.add_argument('jenis_kendaraan', type=str, help='Jenis Kendaraan', location='json', required=True)
# historyParser.add_argument('tanggal', type=str, help='Tanggal', location='json', required=True)
# historyParser.add_argument('waktu', type=str, help='Waktu', location='json', required=True)

# @app.route('/history')
# def get_history():
#     args = historyParser.parse_args()
#     jenis_kendaraan = args['jenis_kendaraan']
#     tanggal = args['tanggal']
#     waktu = args['waktu']

#     # Lanjutkan dengan logika lainnya untuk mendapatkan data history
#     history_list = History.query.all()
#     history_data = []
#     for history in history_list:
#         history_data.append({
#             'nama': history.nama,
#             'jenis_kendaraan': history.jenis_kendaraan,
#             'tanggal': history.tanggal.strftime('%Y-%m-%d'),
#             'waktu': history.waktu.strftime('%H:%M:%S')
#         })
#     return jsonify(history_data)

parserVideo = reqparse.RequestParser()
parserVideo.add_argument('Authorization', type=str, location='headers', required=True)
parserVideo.add_argument('video', type=FileStorage, location='files', required=True)

@api.route('/dataset/video')
class UploadVideo(Resource):
	@api.expect(parserVideo)
	def post(self):
		@after_this_request
		def removed_file(response):
			shutil.rmtree(os.path.join("./runs/detect", filename))
			return response
		args = parserVideo.parse_args()
		bearerAuth = args['Authorization']
		video = args['video']
		if bearerAuth.split(' ')[0] != 'Bearer':
			return {
				'message': 'Bearer token not found!'
			}, 401
		if video is None:
			return {
				'message': 'Video is required!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			if video.filename == '':
				return {
					'message': 'File not found!'
				}, 400
			if video and allowed_file(video.filename):
				filename = secure_filename(video.filename)
				video.save(os.path.join(app.config['VIDEO_FOLDER'], filename))
			subprocess.run(['python3', 'detect.py', '--source', f'./public/videos/{filename}', '--weights', 'best.onnx', '--name', f'{filename}'])	
			print('success predict')
			os.remove(f'./public/videos/{filename}')
			print('success remove')
			return send_file(os.path.join(f"./runs/detect/{filename}", filename), mimetype='video/mp4', as_attachment=True, download_name=filename)
			
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500


#parserRegister
regParser = reqparse.RequestParser()
regParser.add_argument('firstname', type=str, help='firstname', location='json', required=True)
regParser.add_argument('lastname', type=str, help='lastname', location='json', required=True)
regParser.add_argument('email', type=str, help='Email', location='json', required=True)
regParser.add_argument('password', type=str, help='Password', location='json', required=True)
regParser.add_argument('confirm_password', type=str, help='Confirm Password', location='json', required=True)


@api.route('/register')
class Registration(Resource):
    @api.expect(regParser)
    def post(self):
        # BEGIN: Get request parameters.
        args        = regParser.parse_args()
        firstname   = args['firstname']
        lastname    = args['lastname']
        email       = args['email']
        password    = args['password']
        password2  = args['confirm_password']
        is_verified = False

        # cek confirm password
        if password != password2:
            return {
                'messege': 'Password tidak cocok'
            }, 400

        #cek email sudah terdaftar
        user = db.session.execute(db.select(Users).filter_by(email=email)).first()
        if user:
            return "Email sudah terpakai silahkan coba lagi menggunakan email lain"
        user          = Users()
        user.firstname    = firstname
        user.lastname     = lastname
        user.email    = email
        user.password = generate_password_hash(password)
        user.is_verified = is_verified
        db.session.add(user)
        msg = Message(subject='Verification OTP',sender=os.environ.get("MAIL_USERNAME"),recipients=[user.email])
        token =  random.randrange(10000,99999)
        session['email'] = user.email
        session['token'] = str(token)
        print("Isi session email:", session['email'])
        print("Isi session token:", session['token'])
        msg.html=render_template(
        'verify_email.html', token=token)
        mail.send(msg)
        db.session.commit()
        return {'message':
            'Registrasi Berhasil. Silahkan cek email untuk verifikasi.'}, 201

otpparser = reqparse.RequestParser()
otpparser.add_argument('otp', type=str, help='otp', location='json', required=True)
# @api.route('/verifikasi')
# class Verify(Resource):
#     @api.expect(otpparser)
#     def post(self):
#         args = otpparser.parse_args()
#         otp = args['otp']
#         if 'token' in session:
#             sesion = session['token']
#             if otp == sesion:
#                 email = session['email']

#                 user = Users.query.filter_by(email=email).first()
#                 user.is_verified = True

#                 db.session.commit()  # Melakukan komit ke database

#                 if db.session.is_active:  # Memeriksa apakah sesi masih aktif
#                     session.pop('token', None)
#                     print("Perubahan berhasil dikommit ke database")
#                     return {'message': 'Email berhasil diverifikasi'}
#                 else:
#                     print("Terjadi kesalahan saat melakukan komit")
#                     db.session.rollback()  # Mengembalikan perubahan jika terjadi kesalahan
#                     return {'message': 'Terjadi kesalahan pada server'}

#             else:
#                 return {'message': 'Kode OTP Salah'}
#         else:
#             return {'message': 'Kode OTP Salah'}

@api.route('/verifikasi')
class Verify(Resource):
    @api.expect(otpparser)
    def post(self):
        args = otpparser.parse_args()
        otp = args['otp']
        print("Kode OTP:", otp)  # Cetak kode OTP di log
        if 'token' in session:
            sesion = session['token']
            print("Token:", sesion)
            if otp == sesion:
                email = session['email']

                user = Users.query.filter_by(email=email).first()
                user.is_verified = True
                db.session.commit()
                session.pop('token',None)
                print('Email berhasil diverifikasi')
                return {'message' : 'Email berhasil diverifikasi'}
            else:
                return {'message' : 'Kode Otp Salah'}
        else:
            return {'message' : 'Kode Otp Salah'}
logParser = reqparse.RequestParser()
logParser.add_argument('email', type=str, help='Email', location='json', required=True)
logParser.add_argument('password', type=str, help='Password', location='json', required=True)

@api.route('/login')
class LogIn(Resource):
    @api.expect(logParser)
    def post(self):
        args        = logParser.parse_args()
        email       = args['email']
        password    = args['password']
        # cek jika kolom email dan password tidak terisi
        print(email)
        print(password)
        if not email or not password:
            return {
                'message': 'Email Dan Password Harus Diisi'
            }, 400
        #cek email sudah ada
        user = db.session.execute(
            db.select(Users).filter_by(email=email)).first()
        if not user:
            return {
                'message': 'Email / Password Salah'
            }, 400
        else:
            user = user[0]
        #cek password
        if check_password_hash(user.password, password):
            if user.is_verified == True:
                token= jwt.encode({
                        "user_id":user.id,
                        "user_email":user.email,
                        "exp": datetime.utcnow() + timedelta(days= 1)
                },app.config['SECRET_KEY'],algorithm="HS256")
                print(f'Token: {token}')
                return {'message' : 'Login Berhasil',
                        'token' : token
                        },200
                
            else:
                return {'message' : 'Email Belum Diverifikasi ,Silahka verifikasikan terlebih dahulu '},401
        else:
            return {
                'message': 'Email / Password Salah'
            }, 400
def decodetoken(jwtToken):
    decode_result = jwt.decode(
               jwtToken,
               app.config['SECRET_KEY'],
               algorithms = ['HS256'],
            )
    return decode_result

authParser = reqparse.RequestParser()
authParser.add_argument('Authorization', type=str, help='Authorization', location='headers', required=True)
@api.route('/user')
class DetailUser(Resource):
       @api.expect(authParser)
       def get(self):
        args = authParser.parse_args()
        bearerAuth  = args['Authorization']
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            user =  db.session.execute(db.select(Users).filter_by(email=token['user_email'])).first()
            user = user[0]
            data = {
                'firstname' : user.firstname,
                'lastname' : user.lastname,
                'email' : user.email
            }
        except:
            return {
                'message' : 'Token Tidak valid,Silahkan Login Terlebih Dahulu!'
            }, 401

        return data, 200

editParser = reqparse.RequestParser()
editParser.add_argument('firstname', type=str, help='Firstname', location='json', required=True)
editParser.add_argument('lastname', type=str, help='Lastname', location='json', required=True)
editParser.add_argument('Authorization', type=str, help='Authorization', location='headers', required=True)
@api.route('/edituser')
class EditUser(Resource):
       @api.expect(editParser)
       def put(self):
        args = editParser.parse_args()
        bearerAuth  = args['Authorization']
        firstname = args['firstname']
        lastname = args['lastname']
        datenow =  datetime.today().strftime('%Y-%m-%d %H:%M:%S')
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            user = Users.query.filter_by(email=token.get('user_email')).first()
            user.firstname = firstname
            user.lastname = lastname
            user.updatedAt = datenow
            db.session.commit()
        except:
            return {
                'message' : 'Token Tidak valid,Silahkan Login Terlebih Dahulu!'
            }, 401
        return {'message' : 'Update User Sukses'}, 200


verifyParser = reqparse.RequestParser()
verifyParser.add_argument(
    'otp', type=str, help='firstname', location='json', required=True)


# @api.route('/verify')
# class Verify(Resource):
#     @api.expect(verifyParser)
#     def post(self):
#         args = verifyParser.parse_args()
#         otp = args['otp']
#         try:
#             user = Users.verify_token(otp)
#             if user is None:
#                 return {'message' : 'Verifikasi gagal'}, 401
#             user.is_verified = True
#             db.session.commit()
#             return {'message' : 'Akun sudah terverifikasi'}, 200
#         except Exception as e:
#             print(e)
#             return {'message' : 'Terjadi error'}, 200

#editpasswordParser
editPasswordParser =  reqparse.RequestParser()
editPasswordParser.add_argument('current_password', type=str, help='current_password',location='json', required=True)
editPasswordParser.add_argument('new_password', type=str, help='new_password',location='json', required=True)
@api.route('/editpassword')
class Password(Resource):
    @api.expect(authParser,editPasswordParser)
    def put(self):
        args = editPasswordParser.parse_args()
        argss = authParser.parse_args()
        bearerAuth  = argss['Authorization']
        cu_password = args['current_password']
        newpassword = args['new_password']
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            user = Users.query.filter_by(id=token.get('user_id')).first()
            if check_password_hash(user.password, cu_password):
                user.password = generate_password_hash(newpassword)
                db.session.commit()
            else:
                return {'message' : 'Password Lama Salah'},400
        except:
            return {
                'message' : 'Token Tidak valid! Silahkan, Sign in!'
            }, 401
        return {'message' : 'Password Berhasil Diubah'}, 200

if __name__ == '__main__':
    # app.run(ssl_context='adhoc', debug=True)
    app.run(host='0.0.0.0' , debug=True)
