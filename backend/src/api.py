import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

# Initialize the database
db_drop_and_create_all()

## ROUTES

@app.route('/')
def index():
    return jsonify({
        "message": "Welcome to Udacity Coffee Shop!"
    })

# Public endpoint to get all available drinks
@app.route('/drinks')
def drinks():
    # Get all drinks from db
    drinks = Drink.query.all()
    # Format drinks to have drink.short() data representation
    formatted_drinks = [drink.short() for drink in drinks]

    return jsonify({
        "success": True,
        "drinks": formatted_drinks
    })


# Display drinks detail
@app.route('/drinks-detail')
@requires_auth('get:drinks-detail')
def drinks_detail(payload):
    # Get all drinks from db
    drinks = Drink.query.all()
    # Format drinks to have drink.long() data representation
    formatted_drinks = [drink.long() for drink in drinks]

    return jsonify({
        "success": True,
        "drinks": formatted_drinks
    })


# Add a new drink
@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def add_drinks(payload):
    # Get data from the request
    data = request.get_json()

    # If the request misses title or recipe raise an error
    if 'title' or 'recipe' not in data:
        abort(422)

    # Create an instance of Drink model and insert it into the db
    drink = Drink(title = data.title, recipe = data.recipe)
    drink.insert()

    return jsonify({
        "success": True,
        "drinks": drink.long()
    })


# Update a drink
@app.route('/drinks/<id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def edit_drinks(payload, id):
    
    # Query to be updated drink from db
    drink = Drink.query.get(id)

    # if the drink does not exist
    if drink is None:
        abort(404)

    # Get the new info
    data = request.get_json()

    # if the new info misses the title or recipe
    if 'title' or 'recipe' not in data:
        abort(422)

    # update the drink with new info
    drink.title = data['title']
    drink.recipe = data['recipe']
    drink.update()

    return jsonify({
        "success": True,
        "drinks": drink.long()
    })


# Delete a drink
@app.route('/drinks/<id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drinks(payload, id):
    # Query the drink to be deleted
    drink = Drink.query.get(id)

    # If the drink does not exist abort
    if drink is None:
        abort(404)

    drink.delete()

    return jsonify({
        "success": True,
        "delete": id
    })


## Error Handling
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False, 
        "error": 422,
        "message": "unprocessable"
        }), 422

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }),404

@app.errorhandler(AuthError)
def auth_error(error):
    return jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.args[0]["description"]
    }), error.status_code