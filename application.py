import json
import urllib
import uuid

import httplib2
import requests
from flask import Flask, request, render_template, url_for, redirect, \
    jsonify, flash, make_response
from flask import session as login_session
from flask_login import login_user, logout_user, current_user, LoginManager, \
    login_required
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

import repository
from database_structure import Item

GOOGLE_CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# INDEX (Catalog) ----------------------------------------------------------- #
@app.route('/')
@app.route('/catalog')
def show_catalog():
    """Endpoint that serve the catalog page.

    Returns:
        Catalog page.
    """
    categories = repository.get_categories()

    items = repository.session.query(Item) \
        .order_by(Item.added_at.desc()) \
        .limit(10) \
        .all()

    return render_template('catalog.html', categories=categories, items=items)


@app.route('/catalog.json')
def catalog_json():
    """Endpoint returning all items in the catalog as JSON.

    Returns:
        The catalog as JSON.
    """
    categories = repository.get_categories()
    if categories:
        return jsonify(
            categories=[category.serialize for category in categories])

    return jsonify(categories=[])


# Categories ---------------------------------------------------------------- #
@app.route('/catalog/<category_name>/items')
def show_category(category_name):
    """Endpoint that serve the category page.

    Args:
        category_name: Category name.

    Returns:
        Catalog page.
    """
    category = repository.get_category_by_name_url(category_name)

    categories = repository.get_categories()

    return render_template('category.html', categories=categories,
                           category=category)


@app.route('/catalog/<category_name>/items.json')
def category_json(category_name):
    """Endpoint returning all items in the the given category name as JSON.

    Args:
        category_name: Category name.

    Returns:
        The category as JSON.
    """
    category = repository.get_category_by_name_url(category_name)
    return jsonify(category=category.serialize)


# Items --------------------------------------------------------------------- #
@app.route('/catalog/<item_title>')
def show_item(item_title):
    """Endpoint that serve the item page.

    Args:
        item_title: Item title.

    Returns:
        Item page.
    """
    item = repository.get_item_by_title_url(item_title)
    return render_template('item/item.html', item=item)


@app.route('/catalog/items/new', methods=['GET', 'POST'])
@login_required
def new_item():
    """Endpoint that both for GET and POST methods to add new item.

    Methods:
        GET: Serve the new item page.
        POST: Add new item to the database.

    Returns:
        New item page or redirect to catalog page.
    """
    if request.method == 'POST':
        item = Item(title=request.form['title'],
                    description=request.form['description'],
                    category_id=request.form['category_id'],
                    user=current_user)

        if not item.is_valid():
            flash('Item fields are invalid, please fill all required fields')
            return redirect(url_for('new_item'))

        repository.create_item(item)
        flash('\'%s\' successfully added' % item.title)

        return redirect(url_for('show_catalog'))

    # GET
    categories = repository.get_categories()
    if not categories:
        return 'There is no categories in the Database.'

    return render_template('item/new.html', categories=categories)


@app.route('/catalog/<item_title>/edit', methods=['GET', 'POST'])
@login_required
def edit_item(item_title):
    """Endpoint that both for GET and POST methods to edit item.

    Methods:
        GET: Serve the edit item page.
        POST: Update item in the database.

    Args:
        item_title: Item title.

    Returns:
        New item page or redirect to catalog page.
    """
    item = repository.get_item_by_title_url(item_title)
    if not item:
        # When there is no Item show the user the edit page with the message
        # of there is no such Item
        return render_template('item/edit.html')

    # Checks whether the item belong to the current user
    if current_user.id is not item.user_id:
        return render_template('not-authorized.html',
                               message='You do not have permission to '
                                       'edit this Item')

    if request.method == 'POST':
        item.title = request.form['title']
        item.description = request.form['description']
        item.category_id = request.form['category_id']

        if not item.is_valid():
            flash('Item fields are invalid, please fill all required fields')
            return redirect(url_for('edit_item', item_title=item_title))

        repository.session.commit()
        flash('\'%s\' successfully edited' % item_title)

        return redirect(url_for('show_catalog'))

    # GET
    categories = repository.get_categories()
    if not categories:
        return 'There is no categories in the Database.'

    return render_template('item/edit.html', item=item, categories=categories)


@app.route('/catalog/<item_title>/delete', methods=['GET', 'POST'])
@login_required
def delete_item(item_title):
    """Endpoint that both for GET and POST methods to delete item.

    Methods:
        GET: Serve the delete item page.
        POST: Delete item from the database.

    Args:
        item_title: Item title.

    Returns:
        Delete item page or redirect to the catalog page.
    """
    item = repository.get_item_by_title_url(item_title)

    if not item:
        # When there is no Item show the user the delete page with the message
        # of there is no such Item
        return render_template('item/delete.html')

    # Checks whether the item belong to the current user
    if current_user.id is not item.user_id:
        return render_template('not-authorized.html',
                               message='You do not have permission to '
                                       'delete this Item')

    if request.method == 'POST':
        repository.delete_item(item)
        flash('\'%s\' successfully deleted' % item_title)

        return redirect(url_for('show_catalog'))

    # GET
    return render_template('item/delete.html', item=item)


@app.route('/catalog/<item_title>.json')
def item_json(item_title):
    """Endpoint returning item with the given item title as JSON.

    Args:
        item_title: Item title.

    Returns:
        The item as JSON.
    """
    item = repository.get_item_by_title_url(item_title)
    if item:
        return jsonify(item=item.serialize)

    return jsonify()


# Authentication ------------------------------------------------------------ #
@login_manager.user_loader
def load_user(user_id):
    """Define the method of login_manager to load the logged in user to the
    session as current user.

    Args:
        user_id: User id

    Returns:
        User object
    """
    return repository.get_user_by_id(user_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Endpoint that both for GET and POST methods to register as new user.

    Methods:
        GET: Serve the register page.
        POST: Add new user to the database.

    Returns:
        Register page or redirect to catalog page.
    """
    if request.method == 'POST':
        data = request.form

        # Check that user with that email not exists
        if repository.get_user_by_email(data['email']):
            flash('User with this email already exists')
            return redirect(url_for('register'))

        # Create new user
        user = repository.create_user(data['email'], data['first_name'],
                                      data['last_name'], data['password'])
        # Validate user data
        if not user:
            flash('User fields are invalid, please fill all required fields')
            return redirect(url_for('register'))

        login_user(user)
        flash('You have successfully registered')
        return redirect(url_for('show_catalog'))

    # GET
    return render_template('register.html')


@app.route('/login')
def login():
    """Endpoint that serve the login page.

    Returns:
        Login page.
    """
    # Create state token
    state = uuid.uuid4().hex
    login_session['state'] = state

    return render_template('login.html', state=state,
                           GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID)


@app.route('/logout')
def logout():
    """Endpoint for logout current user from the session.

    Returns:
        Redirect to the catalog page.
    """
    logout_user()

    # If using google oauth, disconnect it
    if login_session.get('oauth_provider') == 'google':
        gdisconnect()

    # Clear login session
    login_session.pop('state', None)
    login_session.pop('access_token', None)
    login_session.pop('gplus_id', None)
    login_session.pop('oauth_provider', None)

    return redirect(url_for('show_catalog'))


@app.route('/oauth', methods=['POST'])
def oauth():
    """Endpoint for authorization a new login session as POST method.

    Checks for token validate and password.

    Returns:
        Redirect to the last page or to catalog page.
    """
    # Validate state token
    if request.args['state'] != login_session['state']:
        flash('Invalid state token')
        return redirect(url_for('login'))

    # Get the user entity
    user = repository.get_user_by_email(request.form['email'])

    # Get the next parameter from the request
    next_param = request.args.get('next')

    # Validate email and password
    if not user or not user.verify_password(request.form['password']):
        flash('Invalid Email or Password')
        return redirect(url_for('login', next=next_param))

    # Login the user
    login_user(user)
    flash('You are successfully logged in')

    # Redirect the user to the next parameter (or to catalog page)
    if next_param:
        next_param = urllib.unquote_plus(next_param)
    return redirect(next_param or url_for('show_catalog'))


def make_json_response(message, status_code=200):
    """Makes response object as JSON with the given message
    and with Status code Success 200.

    Args:
        message: The message of the response object.
        status_code: The status code of the response object. Defaults to 200

    Returns:
        Redirect to the catalog page.
    """
    response = make_response(json.dumps(message), status_code)
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Endpoint for authorization a new login session with Google OAuth 2.0
    as POST method.
    Checks for token validate and authorization of Google.

    Returns:
        Redirect to the last page or to catalog page.
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        return make_json_response('Invalid state token.', 401)

    # Get authorization code
    authCode = request.data

    # Try to exchange authorization code for refresh and access tokens
    try:
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(authCode)
    except FlowExchangeError:
        return make_json_response('Failed to exchange the authorization code.',
                                  401)

    # Validate the access token.
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % credentials.access_token)
    http = httplib2.Http()
    result = json.loads(http.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        return make_json_response(result.get('error'), 500)

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        return make_json_response(
            "Token's user ID doesn't match given user ID.", 401)

    # Verify that the access token is valid for this app.
    if result['issued_to'] != GOOGLE_CLIENT_ID:
        return make_json_response("Token's client ID does not match app's.",
                                  401)

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        return make_json_response('Current user is already connected.')

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    login_session['oauth_provider'] = 'google'

    # Get user info
    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    user_info = requests.get(userinfo_url, params=params).json()

    # Check if user exists, if not create new one
    user = repository.get_user_by_email(user_info['email'])
    if not user:
        user = repository.create_user(user_info['email'],
                                      user_info['given_name'],
                                      user_info['family_name'], None)
        if not user:
            return make_json_response(
                "Cannot fetch required data to create new user.", 401)

    # Login the user
    login_user(user)
    flash('You are successfully logged in')

    return make_json_response('Successfully logged in.')


@app.route('/gdisconnect')
def gdisconnect():
    """Endpoint for logout current user from the session and revoke the access
    token of Google OAuth 2.0.

    Returns:
        Success or failed with message as JSON
    """
    # Check if there is singed in user
    access_token = login_session.get('access_token')
    if access_token is None:
        return make_json_response('Current user not connected.', 401)

    # Make a call to revoke access token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    http = httplib2.Http()
    result = http.request(url, 'GET')[0]

    # Return success or failed
    if result['status'] == '200':
        return make_json_response('Successfully logged out.')
    else:
        return make_json_response('Failed to revoke token for given user.',
                                  400)


# --------------------------------------------------------------------------- #

if __name__ == '__main__':
    app.secret_key = 'f4e228586f2c45ba93def7a1b721baed'
    app.run('0.0.0.0', 8000)
