# routes.py
from flask import Blueprint, request, jsonify

from controllers import (
    answer_user_query,
    count_canceled_appointments,
    delete_user,
    edit_doctor_profile,
    get_all_doctors,
    get_appointments_for_patient_with_pid,
    get_balance,
    get_medhistory,
    get_patient_id_from_user_id,
    get_transactions,
    register_admin,
    register_patient,
    register_doctor,
    authenticate_user,
    edit_patient_profile,
    get_all_patients,
    send_password_reset_email,
    reset_password,
    save_schedule,
    get_schedule,
    update_user,
    verify_id,
    get_doctors,
    get_patients,
    make_appointment,
    get_appointments_for_doctor,
    get_appointments_for_patient,
    complete_appointment,
    add_user,
    cancel_appointment,

)
import os

routes = Blueprint('routes', __name__)

@routes.route('/register', methods=['POST'])
def register_route():
    data = request.form.to_dict()
    medical_certificate = request.files.get('medicalCertificate')
    if data.get('role') == 'doctor':
        response, status_code = register_doctor(data, medical_certificate)
    else:
        response, status_code = register_patient(data)
    return jsonify(response), status_code

@routes.route('/login', methods=['POST'])
def login_route():
    data = request.get_json()
    response, status_code = authenticate_user(data['email'], data['password'])
    return jsonify(response), status_code

# @routes.route('/edit_profile', methods=['PUT'])
# def edit_profile_route():
#     data = request.get_json()
#     response, status_code = edit_patient_profile(data['email'], data)
#     return jsonify(response), status_code
@routes.route('/edit_patient_profile', methods=['PUT'])
def edit_profile_route():
    data = request.form.to_dict()
    avatar = request.files.get('avatar')
    print(avatar)
    email = data.get('email')
    response, status_code = edit_patient_profile(email, data, avatar)
    return jsonify(response), status_code
@routes.route('/edit_doctor_profile', methods=['PUT'])
def edit_doctor_profile_route():
    data = request.form.to_dict()
    avatar = request.files.get('avatar')
    email = data.get('email')
    response, status_code = edit_doctor_profile(email, data, avatar)
    return jsonify(response), status_code
@routes.route('/patients', methods=['GET'])
def get_all_patients_route():
    response, status_code = get_all_patients()
    return jsonify(response), status_code

@routes.route('/doctors', methods=['GET'])
def get_all_doctors_route():
    response, status_code = get_all_doctors()
    return jsonify(response), status_code

@routes.route('/forgot-password', methods=['POST'])
def forgot_password_route():
    data = request.get_json()
    email = data.get('email')
    response, status_code = send_password_reset_email(email)
    return jsonify(response), status_code

@routes.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_route(token):
    if request.method == 'GET':
        response, status_code = reset_password(token, 'GET')
    elif request.method == 'POST':
        data = request.get_json()
        response, status_code = reset_password(token, 'POST', data)
    return jsonify(response), status_code

@routes.route('/save_schedule', methods=['POST'])
def save_schedule_route():
    data = request.get_json()
    response, status_code = save_schedule(data)
    return jsonify(response), status_code

@routes.route('/get_schedule', methods=['GET'])
def get_schedule_route():
    email = request.args.get('email')
    response, status_code = get_schedule(email)
    return jsonify(response), status_code

@routes.route('/verify_id', methods=['GET'])
def verify_id_route():
    identification_number = request.args.get('identificationNumber')
    response, status_code = verify_id(identification_number)
    return jsonify(response), status_code

@routes.route('/register_admin', methods=['POST'])
def register_admin_route():
    data = request.get_json()
    response, status_code = register_admin(data)
    return jsonify(response), status_code

@routes.route('/get_patients', methods=['GET'])
def search_patients_route():
    query = request.args.get('query')
    print(f"Search Query: {query}")
    response, status_code = get_patients(query)
    return jsonify(response), status_code

@routes.route('/get_doctors', methods=['GET'])
def search_doctors_route():
    query = request.args.get('query')
    print(f"Search Query: {query}")
    response, status_code = get_doctors(query)
    return jsonify(response), status_code

@routes.route('/make_appointment', methods=['POST'])
def make_appointment_route():
    data = request.get_json()
    response, status_code = make_appointment(data)
    return jsonify(response), status_code

@routes.route('/get_appointments_for_doctor', methods=['GET'])
def get_appointments_for_doctor_route():
    email = request.args.get('email')
    response, status_code = get_appointments_for_doctor(email)
    return jsonify(response), status_code

@routes.route('/my_appointments', methods=['GET'])
def my_appointments_route():
    user_id = request.args.get('user_id')
    response, status_code = get_appointments_for_patient(user_id)
    return jsonify(response), status_code

    return jsonify(response), status_code

@routes.route('/complete_appointment', methods=['POST'])
def complete_appointment_route():
    data = request.get_json()
    response, status_code = complete_appointment(data)
    return jsonify(response), status_code

@routes.route('/update_user', methods=['PUT'])
def update_user_route():
    data = request.get_json()
    print(data)
    response, status_code = update_user(data)
    return jsonify(response), status_code

@routes.route('/delete_user', methods=['DELETE'])
def delete_user_route():
    data = request.get_json()
    email = data.get('email')
    response, status_code = delete_user(email)
    return jsonify(response), status_code
@routes.route('/add_user', methods=['POST'])
def add_user_route():
    data = request.get_json()
    response, status_code = add_user(data)
    return jsonify(response), status_code
@routes.route('/get_medhistory', methods=['GET'])
def get_medhistory_route():
    email = request.args.get('email')
    response, status_code = get_medhistory(email)
    return (response), status_code
@routes.route('/cancel', methods=['POST'])
def cancel_appointment_route():
    data = request.get_json()
    response, status_code = cancel_appointment(data)
    return jsonify(response), status_code
@routes.route('/get_appointments_for_patient_with_id', methods=['GET'])
def get_appointments_for_patient_route():
    patient_id = request.args.get('patient_id')
    response, status_code = get_appointments_for_patient_with_pid(patient_id)
    return jsonify(response), status_code
@routes.route('/count_canceled_appointments', methods=['GET'])
def count_canceled_appointments_route():
    patient_id = request.args.get('patient_id')
    response, status_code = count_canceled_appointments(patient_id)
    return jsonify(response), status_code

@routes.route('/get_balance', methods=['GET'])
def get_balance_route():
    email = request.args.get('email')
    response, status_code = get_balance(email)
    return jsonify(response), status_code

@routes.route('/get_transactions', methods=['GET'])
def get_transactions_route():
    patient_id = request.args.get('patient_id')
    response, status_code = get_transactions(patient_id)
    return jsonify(response), status_code
@routes.route('/get_patient_id', methods=['GET'])
def get_patient_id_route():
    user_id = request.args.get('user_id')
    response, status_code = get_patient_id_from_user_id(user_id)
    return jsonify(response), status_code

# Other routes...
@routes.route('/answer_query', methods=['POST'])
def answer_query_route():
    data = request.get_json()
    response, status_code = answer_user_query(data)
    return jsonify(response), status_code