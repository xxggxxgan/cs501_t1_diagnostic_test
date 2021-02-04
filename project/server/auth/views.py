# project/server/auth/views.py

from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User

auth_blueprint = Blueprint('auth', __name__)

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """
    
    def get(self):
    	responseObject = {
    		'status': 'success',
    		'message': 'Request successful but please send an HTTP POST request to register the user.'
    	}
    	return make_response(jsonify(responseObject)), 201

    def post(self):
        # get the post data
        post_data = request.get_json(); print(request)
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password')
                )
                
                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                auth_token = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode()
                }
              
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                print('Reason:', e)   
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            print("exist here")
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202

class UserAPI(MethodView):
    def get(self):
        list = User.query.all()
        result = []
        for i in list:
            result.append(str(i.email))
        print(result)
        return str(result),200

class RootPage(MethodView):
    def get(self):
        s1 = "wlcome to Xiaoxin Gan's hw1 for cs501"
        s2 = "please use postman to register new account on https://gxx-cs501-hw1.herokuapp.com/auth/register"
        s3 = "check all registered users on https://gxx-cs501-hw1.herokuapp.com/users/index"
        end = "\n"
        return s1 + end + s2 + end + s3,200

# define the API resources
registration_view = RegisterAPI.as_view('register_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST', 'GET']
)

user_view = UserAPI.as_view('user_api')

auth_blueprint.add_url_rule(
    '/users/index',
    view_func=user_view,
    methods=['POST', 'GET']
)

root_page= RootPage.as_view('root_api')

auth_blueprint.add_url_rule(
    '/',
    view_func=root_page,
    methods=['POST', 'GET']
)