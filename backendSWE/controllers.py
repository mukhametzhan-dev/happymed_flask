# controllers.py
import os

from werkzeug.utils import secure_filename
from models import Appointment, Doctor, Specialization, db, Patient, User, Administrator
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import current_app, jsonify
import requests
import logging
import random
import string
import requests


def register_patient(data):
    try:
        # Check if email already exists in Patient table
        if Patient.query.filter_by(email=data['email']).first():
            return {'error': 'Email already exists from 17'}, 400

        date_of_birth = datetime.strptime(
            f"{data['dateOfBirthYear']}-{data['dateOfBirthMonth']}-{data['dateOfBirthDay']}",
            '%Y-%m-%d'
        ).date()
        
        hashed_password = generate_password_hash(data['password'])

        new_patient = Patient(
            first_name=data['firstName'],
            last_name=data['lastName'],
            date_of_birth=date_of_birth,
            email=data['email'],
            phone=data['mobileNumber'],
            gender=data.get('gender', 'Male')
        )
        # print(new_patient.to_dict())
        print(new_patient.email)
        db.session.add(new_patient)
        db.session.commit()


        new_user = User(
            password=hashed_password,
            role='patient',
            patient_id=new_patient.patient_id
        )
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'Patient registered successfully'}, 201
    except IntegrityError:
        # print(IntegrityError.__cause__)
        
        db.session.rollback()
        return {'error': 'Email already exists 52'}, 400
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400

def register_doctor(data, medical_certificate):

    try:
        logging.info(f"Data: {data}")
        print(data)
        # Check if email already exists in Doctor table
        if Doctor.query.filter_by(email=data['email']).first():
            return {'error': 'Email already exists Doctor 57'}, 400

        date_of_birth = datetime.strptime(
            f"{data['dateOfBirthYear']}-{data['dateOfBirthMonth']}-{data['dateOfBirthDay']}",
            '%Y-%m-%d'
        ).date()


        # Get specialization
        # convert 004 to 4
        print(int(data['specialty']))

        # spec = Specialization.query.filter_by(spec_id=int(data['specialty'])).first()

        # if not spec:
        #     return {'error': 'Specialization not found'}, 400
        
        # print(spec)
        # print(spec.spec_id)
        # print(spec.spec_name)
        # print(data.specialty)
        # if not spec:
        #     return {'error': 'Specialization not found'}, 400

        hashed_password = generate_password_hash(data['password'])

        new_doctor = Doctor(
            first_name=data['firstName'],
            last_name=data['lastName'],
            date_of_birth=date_of_birth,
            email=data['email'],
            phone=data['mobileNumber'],
            spec_id=int(data['specialty']),
            
        )
        db.session.add(new_doctor)
        db.session.commit()

        new_user = User(
            password=hashed_password,
            role='doctor',
            doctor_id=new_doctor.doctor_id
        )
        db.session.add(new_user)
        db.session.commit()

        # Save the medical certificate file
        if medical_certificate:
            filename = secure_filename(medical_certificate.filename)
            upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            medical_certificate.save(upload_path)

        return {'message': 'Doctor registered successfully'}, 201
    except IntegrityError:
        db.session.rollback()
        return {'error': 'Email already exists doctor 99'}, 400
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400
def save_schedule(data):
    try:
        email = data.get('email')
        schedule = data.get('schedule')

        doctor = Doctor.query.filter_by(email=email).first()
        if not doctor:
            return {'error': 'Doctor not found'}, 404

        doctor.schedule = schedule
        db.session.commit()

        return {'message': 'Schedule saved successfully', 'schedule': doctor.schedule}, 200
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400

def authenticate_user(email, password):
    user = User.query.join(Patient, User.patient_id == Patient.patient_id, isouter=True) \
                     .join(Doctor, User.doctor_id == Doctor.doctor_id, isouter=True) \
                     .join(Administrator, User.admin_id == Administrator.admin_id, isouter=True) \
                     .filter((Patient.email == email) | (Doctor.email == email) | (Administrator.email == email)).first()

    if user and check_password_hash(user.password, password):
        user_data = {
            'user_id': user.user_id,
            'role': user.role
        }
        if user.role == 'patient':
            patient_id = get_patient_id_from_user_id(user.user_id)
            user_data.update({
                'first_name': user.patient.first_name,
                'last_name': user.patient.last_name,
                'email': user.patient.email,
                'phone': user.patient.phone,
                'gender': user.patient.gender,
                'patient_id': patient_id
            })
        elif user.role == 'doctor':
            user_data.update({
                'first_name': user.doctor.first_name,
                'last_name': user.doctor.last_name,
                'email': user.doctor.email,
                'phone': user.doctor.phone,
                'gender': user.doctor.gender,
                # 'specialization': user.doctor.specialization.spec_name
                'specialization': user.doctor.spec_id # ska
            })
        elif user.role == 'administrator':
            user_data.update({
                'first_name': user.administrator.first_name,
                'last_name': user.administrator.last_name,
                'email': user.administrator.email,
                'phone': user.administrator.phone
            })

        return {'status': 'success', 'message': 'Login successful', 'user': user_data}, 200
    else:
        return {'status': 'fail', 'error': 'Invalid email or password'}, 401

from werkzeug.utils import secure_filename
import os

def edit_patient_profile(email, data, avatar=None):
    patient = Patient.query.filter_by(email=email).first()
    if not patient:
        return {'error': 'Patient not found'}, 404
    #avator is null

    try:
        if 'firstName' in data:
            patient.first_name = data['firstName']
        if 'lastName' in data:
            patient.last_name = data['lastName']
        if 'dateOfBirth' in data:
            patient.date_of_birth = datetime.strptime(data['dateOfBirth'], '%Y-%m-%dT%H:%M:%S.%fZ').date()
        if 'mobileNumber' in data:
            patient.phone = data['mobileNumber']
        if 'gender' in data:
            patient.gender = data['gender']
        if 'password' in data:
            user = User.query.filter_by(patient_id=patient.patient_id).first()
            user.password = generate_password_hash(data['password'])

        if avatar:
            filename = secure_filename(avatar.filename)
            upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            avatar.save(upload_path)
            patient.avatar = filename
            print(patient.avatar)

        db.session.commit()
        return {'message': 'Profile updated successfully'}, 200
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400
def get_all_doctors():
    doctors = Doctor.query.all()

    doctors_list = [{
        'doctor_id': doctor.doctor_id,
        'first_name': doctor.first_name,
        'last_name': doctor.last_name,
        'date_of_birth': doctor.date_of_birth.strftime('%Y-%m-%d'),
        'email': doctor.email,
        'phone': doctor.phone,
        'schedule': doctor.schedule,
        'specialization': {
            'spec_id': doctor.specialization.spec_id,
            'spec_name': doctor.specialization.spec_name    }
        


    }
        for doctor in doctors

    ]
    return doctors_list, 200
    
def get_all_patients():
    patients = Patient.query.all()

    patients_list = [{
        'patient_id': patient.patient_id,
        'first_name': patient.first_name,
        'last_name': patient.last_name,
        'date_of_birth': patient.date_of_birth.strftime('%Y-%m-%d'),
        'email': patient.email,
        'phone': patient.phone,
        'gender': patient.gender
    } for patient in patients]
    return patients_list, 200

def send_password_reset_email(email):
    user = User.query.join(Patient, User.patient_id == Patient.patient_id, isouter=True) \
                     .join(Doctor, User.doctor_id == Doctor.doctor_id, isouter=True) \
                     .join(Administrator, User.admin_id == Administrator.admin_id, isouter=True) \
                     .filter((Patient.email == email) | (Doctor.email == email) | (Administrator.email == email)).first()

    if not user:
        return {'error': 'Email does not exist'}, 404

    try:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        token = serializer.dumps(email, salt='password-reset-salt')

        reset_url = f'http://localhost:5173/reset-password/{token}'
        send_reset_password_email(email, f"{user.role.capitalize()} {user.user_id}", reset_url)

        return {'message': 'Password reset email sent'}, 200
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return {'error': 'An internal error occurred'}, 500

def send_reset_password_email(to_email, to_name, reset_url):
    api_url = 'https://api.smtp2go.com/v3/email/send'
    api_key = current_app.config['SMTP2GO_API_KEY']  # Use config

    headers = {
        'Content-Type': 'application/json',
        'X-Smtp2go-Api-Key': api_key,
        'accept': 'application/json'
    }

    payload = {
        "sender": current_app.config['SMTP2GO_SENDER'],  # Use config
        "to": [to_email],
        "subject": "Password Reset Request",
        "html_body": f"""
            <p>Hello {to_name},</p>
            <p>Please click the link below to reset your password:</p>
            <p><a href='{reset_url}'>Reset Password</a></p>
            <p>If you did not request this, please ignore this email.</p>
        """
    }

    response = requests.post(api_url, headers=headers, json=payload)
    if response.status_code != 200:
        logging.error(f"Failed to send email: {response.text}")
        raise Exception("Failed to send email")

def reset_password(token, method, data=None):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

    if method == 'GET':
        try:
            # Validate token
            email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
            return {'message': 'Token is valid', 'email': email}, 200
        except SignatureExpired:
            return {'error': 'The token is expired'}, 400
        except BadSignature:
            return {'error': 'Invalid token'}, 400

    elif method == 'POST':
        password = data.get('password')
        confirm_password = data.get('confirmPassword')

        if not password or not confirm_password:
            return {'error': 'Fields cannot be empty!'}, 400

        if password != confirm_password:
            return {'error': 'Passwords do not match!'}, 400

        try:
            # Validate token again
            email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        except SignatureExpired:
            return {'error': 'The token is expired'}, 400
        except BadSignature:
            return {'error': 'Invalid token'}, 400

        user = User.query.join(Patient, User.patient_id == Patient.patient_id, isouter=True) \
                         .join(Doctor, User.doctor_id == Doctor.doctor_id, isouter=True) \
                         .join(Administrator, User.admin_id == Administrator.admin_id, isouter=True) \
                         .filter((Patient.email == email) | (Doctor.email == email) | (Administrator.email == email)).first()

        if not user:
            return {'error': 'User not found!'}, 404

        # Update the password
        user.password = generate_password_hash(password)
        db.session.commit()

        return {'message': 'Your password has been reset successfully!'}, 200
def get_schedule(email):
    
    try:
        doctor = Doctor.query.filter_by(email=email).first()
        if not doctor:

            return {'error': 'Doctor not found'}, 404
        

        return {'schedule': doctor.schedule}, 200
    except Exception as e:
        return {'error': str(e)}, 400

def verify_id(identification_number):
    try:
        dict = {
            'Mars': 220107126,
            'Sanzhar': 200107052,
            'MuratAbdilda': 77777777
        }     
        # print(int(identification_number) == 200107052)
        if int(identification_number) in dict.values():
            print("verified")
            return {'exists': True, 'role': 'admin', 'status': 'verified'}, 200
            
        # Check in Patient table

        # Check in Administrator table
        # administrator = Administrator.query.filter_by(admin_id=identification_number).first()
        # if administrator:

            return {'exists': True, 'role': 'administrator'}, 200

        # If not found in any table
        return {'exists': False}, 404
    except Exception as e:
        return {'error': str(e)}, 400
def register_admin(data):
    try:
        # Check if email already exists in Administrator table
        
        if Administrator.query.filter_by(email=data['email']).first() or Patient.query.filter_by(email=data['email']).first() or Doctor.query.filter_by(email=data['email']).first(): 

            return {'error': 'Email already exists'}, 400

        hashed_password = generate_password_hash(data['password'])

        new_admin = Administrator(
            first_name=data['firstName'],
            last_name=data['lastName'],
            email=data['email'],
            phone=data['number']
        )
        print(data['email'])
        print(data['number'])
        db.session.add(new_admin)
        db.session.commit()

        new_user = User(
            password=hashed_password,
            role='administrator',
            admin_id=new_admin.admin_id
        )
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'Administrator registered successfully', 'status': 'success'}, 201
    except IntegrityError:
        db.session.rollback()
        return {'error': 'Email already exists'}, 400
    except Exception as e:
        db.session.rollback()
        print(e)
        return {'error': str(e)}, 400
def get_patients(query=None):
    try:
        if query:
            patients = Patient.query.filter(
                (Patient.first_name.ilike(f'%{query}%')) |
                (Patient.last_name.ilike(f'%{query}%')) |
                (Patient.email.ilike(f'%{query}%')) |
                (Patient.patient_id.ilike(f'%{query}%'))
            ).all()
        else:
            patients = Patient.query.all()

        patients_list = [{
            'firstName': patient.first_name,
            'lastName': patient.last_name,
            'email': patient.email,
            'role': 'patient',
            'id': patient.patient_id
        } for patient in patients]

        return patients_list, 200
    except Exception as e:
        return {'error': str(e)}, 400


def get_doctors(query=None):
    try:
        if query:
            doctors = Doctor.query.filter(
                (Doctor.first_name.ilike(f'%{query}%')) |
                (Doctor.last_name.ilike(f'%{query}%')) |
                (Doctor.email.ilike(f'%{query}%')) |
                (Doctor.doctor_id.ilike(f'%{query}%'))
            ).all()
        else:
            doctors = Doctor.query.all()

        doctors_list = [{
            'firstName': doctor.first_name,
            'lastName': doctor.last_name,
            'email': doctor.email,
            'role': 'doctor',
            'id': doctor.doctor_id
        } for doctor in doctors]

        return doctors_list, 200
    except Exception as e:
        return {'error': str(e)}, 400
def make_appointment(data):
    try:
        doctor_id = data['doctor']
        description = data['description']
        time_slot = data['timeSlot']
        patient_id = data['patient_id']
        print(patient_id)
        appointment_type = data.get('appointmentType', 'General')  # Default to 'General' if not provided

        print(data)

        # Check if doctor exists
        doctor = Doctor.query.filter_by(doctor_id=doctor_id).first()
        if not doctor:
            return {'error': 'Doctor not found'}, 404

        # Check if patient exists
        patient = Patient.query.filter_by(patient_id=patient_id).first()
        if not patient:
            return {'error': 'Patient not found'}, 404

        start_time_str, end_time_str = time_slot['time'].split('-')
        start_time = datetime.strptime(start_time_str, '%H:%M').time()
        end_time = datetime.strptime(end_time_str, '%H:%M').time()
        date = datetime.strptime(time_slot['date'], '%d.%m.%Y').date()
        day_of_week = time_slot['day']

        new_appointment = Appointment(
            doctor_id=doctor_id,
            description=description,
            start_time=start_time,
            end_time=end_time,
            date=date,
            day_of_week=day_of_week,
            patient_id=patient_id,
            appointmentType=appointment_type
        )
        db.session.add(new_appointment)
        db.session.commit()

        return {'message': 'Appointment created successfully'}, 201
    
    except IntegrityError as e:
        db.session.rollback()
        logging.error(f"IntegrityError: {e}")
        return {'error': 'Failed to create appointment due to integrity error'}, 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Exception: {e}")
        return {'error': str(e)}, 400
def get_appointments_for_doctor(email):
    try:
        doctor = Doctor.query.filter_by(email=email).first()
        if not doctor:
            return {'error': 'Doctor not found'}, 404

        appointments = db.session.query(Appointment, Patient).join(Patient, Appointment.patient_id == Patient.patient_id).filter(Appointment.doctor_id == doctor.doctor_id).all()
        
        appointments_list = [{
            'appointment_id': appointment.Appointment.appointment_id,
            'description': appointment.Appointment.description,
            'start_time': appointment.Appointment.start_time.strftime('%H:%M'),
            'end_time': appointment.Appointment.end_time.strftime('%H:%M'),
            'date': appointment.Appointment.date.strftime('%Y-%m-%d'),
            'day_of_week': appointment.Appointment.day_of_week,
            'status': appointment.Appointment.status,
            'patient_name': f"{appointment.Patient.first_name} {appointment.Patient.last_name}"
        } for appointment in appointments]

        return {'appointments': appointments_list}, 200
    except Exception as e:
        return {'error': str(e)}, 400
def get_appointments_for_patient(user_id):
    try:
        # Fetch patient_id using user_id
        user = User.query.filter_by(user_id=user_id).first()
        if not user or not user.patient_id:
            return {'error': 'Patient not found'}, 404

        patient_id = user.patient_id

        appointments = Appointment.query.filter_by(patient_id=patient_id).all()
        appointments_list = [{
            'appointment_id': appointment.appointment_id,
            'doctor_id': appointment.doctor_id,
            'description': appointment.description,
            'start_time': appointment.start_time.strftime('%H:%M'),
            'end_time': appointment.end_time.strftime('%H:%M'),
            'date': appointment.date.strftime('%Y-%m-%d'),
            'day_of_week': appointment.day_of_week,
            'status': appointment.status
        } for appointment in appointments]

        return {'appointments': appointments_list}, 200
    except Exception as e:
        return {'error': str(e)}, 400
def get_appointments_for_patient_with_pid(user_id):
    try:
        patient_id= user_id
        print(user_id)
        # Fetch patient_id using user_id
        patient = Patient.query.filter_by(patient_id=user_id).first()



        patient_id = patient.patient_id

        appointments = Appointment.query.filter_by(patient_id=patient_id).all()
        appointments_list = [{
            'appointment_id': appointment.appointment_id,
            'doctor_id': appointment.doctor_id,
            'description': appointment.description,
            'start_time': appointment.start_time.strftime('%H:%M'),
            'end_time': appointment.end_time.strftime('%H:%M'),
            'date': appointment.date.strftime('%Y-%m-%d'),
            'day_of_week': appointment.day_of_week,
            'status': appointment.status
        } for appointment in appointments]

        return {'appointments': appointments_list}, 200
    except Exception as e:
        return {'error': str(e)}, 400

def complete_appointment(data):
    try:
        appointment_id = data['appointment_id']

        # Fetch the appointment
        appointment = Appointment.query.filter_by(appointment_id=appointment_id).first()
        if not appointment:
            return {'error': 'Appointment not found'}, 404

        # Update the status to completed
        appointment.status = 'completed'
        db.session.commit()

        # Add appointment details to patient's medical history
        patient = Patient.query.filter_by(patient_id=appointment.patient_id).first()
        if not patient:
            return {'error': 'Patient not found'}, 404

        medical_history_entry = {
            'appointment_id': appointment.appointment_id,
            'description': appointment.description,
            'start_time': appointment.start_time.strftime('%H:%M'),
            'end_time': appointment.end_time.strftime('%H:%M'),
            'date': appointment.date.strftime('%Y-%m-%d'),
            'day_of_week': appointment.day_of_week,
            'status': appointment.status
        }

        if patient.medical_history is None:
            patient.medical_history = []
        patient.medical_history.append(medical_history_entry)

        db.session.commit()

        return {'message': 'Appointment status updated to completed and added to medical history'}, 200
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400
    
def update_user(data):
    try:
        role = data.get('role')
        email = data.get('email')
        if not role or not email:
            return {'error': 'Role and email are required'}, 400

        if role == 'patient':
            user = Patient.query.filter_by(email=email).first()
        elif role == 'doctor':
            user = Doctor.query.filter_by(email=email).first()
        else:
            return {'error': 'Invalid role'}, 400

        if not user:
            return {'error': 'User not found'}, 404

        user.first_name = data.get('firstName', user.first_name)
        user.last_name = data.get('lastName', user.last_name)

        db.session.commit()
        return {'message': 'User updated successfully'}, 200
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

def delete_user(email):
    try:
        user =Patient.query.filter_by(email=email).first() or Doctor.query.filter_by(email=email).first()
        if not user:
            return {'error': 'User not found'}, 404

        db.session.delete(user)
        db.session.commit()
        return {'message': 'User deleted successfully'}, 200
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def add_user(data):
    try:
        role = data.get('role')
        if not role:
            return {'error': 'Role is required'}, 400

        email = data.get('email')
        if not email:
            return {'error': 'Email is required'}, 400

        password = data.get('password', generate_random_password())
        hashed_password = generate_password_hash(password)

        date_of_birth_str = data.get('dob')
        if not date_of_birth_str:
            return {'error': 'Date of birth is required'}, 400

        date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%dT%H:%M:%S.%fZ').date()

        if role == 'patient':
            if Patient.query.filter_by(email=email).first():
                return {'error': 'Email already exists in Patient table'}, 400

            new_patient = Patient(
                first_name=data['firstName'],
                last_name=data['lastName'],
                date_of_birth=date_of_birth,
                email=email,
                phone=data['phone'],
                gender=data.get('gender', 'Male')
            )
            db.session.add(new_patient)
            db.session.commit()

            new_user = User(
                password=hashed_password,
                role='patient',
                patient_id=new_patient.patient_id
            )
            db.session.add(new_user)
            db.session.commit()

        elif role == 'doctor':
            if Doctor.query.filter_by(email=email).first():
                return {'error': 'Email already exists in Doctor table'}, 400

            new_doctor = Doctor(
                first_name=data['firstName'],
                last_name=data['lastName'],
                date_of_birth=date_of_birth,
                email=email,
                phone=data['phone'],
                spec_id=int(data['spec_id']),
            )
            db.session.add(new_doctor)
            db.session.commit()

            new_user = User(
                password=hashed_password,
                role='doctor',
                doctor_id=new_doctor.doctor_id
            )
            db.session.add(new_user)
            db.session.commit()

        else:

            return {'error': 'Invalid role'}, 400

        return {'message': f'{role.capitalize()} added successfully', 'password': password}, 201
    except IntegrityError:
        db.session.rollback()
        return {'error': 'Email already exists'}, 400
    except Exception as e:
        print(e)
        db.session.rollback()
        return {'error': str(e)}, 400
def edit_doctor_profile(email, data, avatar=None):
    doctor = Doctor.query.filter_by(email=email).first()
    if not doctor:
        return {'error': 'Doctor not found'}, 404

    try:
        if 'firstName' in data:
            doctor.first_name = data['firstName']
        if 'lastName' in data:
            doctor.last_name = data['lastName']
        if 'dateOfBirth' in data:
            doctor.date_of_birth = datetime.strptime(data['dateOfBirth'], '%Y-%m-%dT%H:%M:%S.%fZ').date()
        if 'mobileNumber' in data:
            doctor.phone = data['mobileNumber']
        if 'gender' in data:
            doctor.gender = data['gender']
        if 'password' in data:
            user = User.query.filter_by(doctor_id=doctor.doctor_id).first()
            user.password = generate_password_hash(data['password'])

        if avatar:
            filename = secure_filename(avatar.filename)
            upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            avatar.save(upload_path)
            doctor.avatar = filename

        db.session.commit()
        return {'message': 'Profile updated successfully'}, 200
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400
    
def get_medhistory(email):
    try:
        print(email)
        patient = Patient.query.filter_by(email=email).first()
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404

        medical_history = patient.medical_history
        if medical_history is None:
            medical_history = []

        # Add doctor's name to each entry in the medical history
        for entry in medical_history:
            appointment_id = entry.get('appointment_id')
            appointment = Appointment.query.filter_by(appointment_id=appointment_id).first()
            if appointment:
                doctor = Doctor.query.filter_by(doctor_id=appointment.doctor_id).first()
                if doctor:
                    entry['doctor_name'] = f"{doctor.first_name} {doctor.last_name}"
                    entry['specialization'] = doctor.specialization.spec_name

        return jsonify(medical_history), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
def cancel_appointment(data):
    try:
        appointment_id = data.get('appointment_id')
        if not appointment_id:
            return {'error': 'Appointment ID is required'}, 400

        # Fetch the appointment
        appointment = Appointment.query.filter_by(appointment_id=appointment_id).first()
        if not appointment:
            return {'error': 'Appointment not found'}, 404

        # Fetch the patient
        patient = Patient.query.filter_by(patient_id=appointment.patient_id).first()
        if not patient:
            return {'error': 'Patient not found'}, 404

        # Count canceled appointments
        canceled_count = Appointment.query.filter_by(patient_id=patient.patient_id, status='canceled').count()

        # Apply penalty if canceled appointments are 3 or more
        if canceled_count >= 3:
            appointment_type = appointment.appointmentType
            price_dict = {
                'Consultation': 10000,
                'Follow-Up Visit': 16000,
                'Routine Check-Up': 9000,
                'Cluster Sceduling':7000,
                'Personal Health Assessment': 20000
            }
            price = price_dict.get(appointment_type, 100)  # Default price if type not found
            penalty = price * 0.30
            patient.balance -= penalty

        # Update the status to canceled
        appointment.status = 'canceled'
        db.session.commit()

        return {'message': 'Appointment canceled successfully'}, 200
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400
def get_appointments_for_patient_id(patient_id):
    try:
        # Fetch appointments using patient_id
        appointments = Appointment.query.filter_by(patient_id=patient_id).all()
        if not appointments:
            return {'appointments': []}, 200

        appointments_list = [{
            'appointment_id': appointment.appointment_id,
            'doctor_id': appointment.doctor_id,
            'description': appointment.description,
            'start_time': appointment.start_time.strftime('%H:%M'),
            'end_time': appointment.end_time.strftime('%H:%M'),
            'date': appointment.date.strftime('%Y-%m-%d'),
            'day_of_week': appointment.day_of_week,
            'status': appointment.status
        } for appointment in appointments]

        return {'appointments': appointments_list}, 200
    except Exception as e:
        return {'error': str(e)}, 400
def count_canceled_appointments(patient_id):
    try:
        # Count canceled appointments using patient_id
        canceled_count = Appointment.query.filter_by(patient_id=patient_id, status='canceled').count()
        return {'canceled_appointments_count': canceled_count}, 200
    except Exception as e:
        return {'error': str(e)}, 400
def get_balance(email):
    try:
        # Fetch the patient using email
        patient = Patient.query.filter_by(email=email).first()
        if not patient:
            return {'error': 'Patient not found'}, 404

        # Return the balance
        return {'balance': patient.balance}, 200
    except Exception as e:
        return {'error': str(e)}, 400
def get_transactions(patient_id):
    # patient_id = get_patient_id_from_user_id(patient_id)
    print(patient_id)
    try:
        # Define the price dictionary
        price_dict = {
            'Consultation': 10000,
            'Follow-Up Visit': 16000,
            'Routine Check-Up': 9000,
            'Cluster Scheduling': 7000,
            'Personal Health Assessment': 20000
        }

        # Fetch appointments using patient_id
        appointments = Appointment.query.filter_by(patient_id=patient_id).all()
        if not appointments:
            return {'transactions': []}, 200

        transactions_list = [{
            'date': appointment.date.strftime('%Y-%m-%d'),
            'price': price_dict.get(appointment.appointmentType, 0),
            'status': appointment.status
        } for appointment in appointments if appointment.appointmentType]

        return {'transactions': transactions_list}, 200
    except Exception as e:
        return {'error': str(e)}, 400
def get_patient_id_from_user_id(user_id):
    try:
        # Fetch the user using user_id
        user = User.query.filter_by(user_id=user_id).first()
        if not user or not user.patient_id:
            return {'error': 'Patient not found'}, 404

        # Return the patient_id
        return user.patient_id
    except Exception as e:
        return {'error': str(e)}, 400
    


def answer_user_query(data):
    try:
        user_query = data.get('query')

        if not user_query:
            return {'error': 'Query is required'}, 400

        # Predefined prompt to explain the project to Gemini API
        predefined_prompt = """
        This project is a medical appointment management system.
          It allows patients to register, book appointments with doctors, and manage their medical history. Doctors can also register, manage their schedules, and view appointments. The system includes features such as user authentication, password reset, and appointment cancellation with penalties for frequent cancellations. The project uses Flask for the backend, MySQL for the database, and React for the frontend.
          So to answer question who are you ? I am a medical appointment management system's trained model. I can help you with any questions you have about the system. Please feel free to ask me anything.
          How to make an appointment? To make an appointment, you need to log in as a patient, select a doctor, choose a date and timeslot, and provide a description of your symptoms. Once the appointment is confirmed, you will receive a notification with the appointment details.
          Appointment cancelation policy: If you cancel 3 or more appointments, you will be charged a penalty of 30% of the appointment price. The penalty will be deducted from your account balance.
            How to reset password? To reset your password, click on the 'Forgot Password' link on the login page. You will receive an email with a link to reset your password. Click on the link and follow the instructions to create a new password.
            How to view medical history? To view your medical history, log in as a patient and go to the 'Medical History' section. You will see a list of all your past appointments with details such as date, time, doctor, and description.
            How to view appointments? To view your appointments, log in as a patient and go to the 'Appointments' section. You will see a list of all your upcoming appointments with details such as date, time, doctor, and status.
            How to view balance? To view your account balance, log in as a patient and go to the 'Transactions' section. You will see your current balance and a list of all your transactions.
        For admins:
            How can i manage patient,doctor records?: As an admin, you can add, edit, and delete patient and doctor records. You can also view the list of all patients and doctors in the system.
            How can i verify a admin user?: To verify a user, you need to enter their identification number in the verification form. The system will check if the user exists in the database and return their role if found.

        """

        # Combine the predefined prompt with the user query
        prompt = f"{predefined_prompt}\n\nUser Query: {user_query}"

        # Gemini API endpoint and API key
        gemini_api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=AIzaSyBNJvnpDjzrTlepR3GUrDn-_8t1veCiFA0"

        # Prepare the request payload
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ]
        }

        # Send the request to the Gemini API
        response = requests.post(gemini_api_url, json=payload, headers={"Content-Type": "application/json"})
        response_data = response.json()

        # Log the response for debugging
        print("Gemini API Response:", response_data)

        # Extract the answer from the response
        answer = response_data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'No answer available')

        return {'answer': answer}, 200
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400