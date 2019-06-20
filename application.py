import urllib
import uuid

from flask import Flask, request, render_template, url_for, redirect, \
    jsonify, flash
from flask import session as login_session
from flask_login import login_user, logout_user, current_user, LoginManager, \
    login_required

import repository
from database_structure import Item

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# INDEX (Catalog) ----------------------------------------------------------- #
@app.route('/')
@app.route('/catalog')
def show_catalog():
    categories = repository.get_categories()

    items = repository.session.query(Item) \
        .order_by(Item.added_at.desc()) \
        .limit(10) \
        .all()

    return render_template('catalog.html', categories=categories, items=items)


@app.route('/catalog.json')
def catalog_json():
    categories = repository.get_categories()
    if categories:
        return jsonify(
            categories=[category.serialize for category in categories])

    return jsonify(categories=[])


# Categories ---------------------------------------------------------------- #
@app.route('/catalog/<category_name>/items')
def show_category(category_name):
    category = repository.get_category_by_name_url(category_name)

    categories = repository.get_categories()

    return render_template('category.html', categories=categories,
                           category=category)


@app.route('/catalog/<category_name>/items.json')
def category_json(category_name):
    category = repository.get_category_by_name_url(category_name)
    return jsonify(category=category.serialize)


# Items --------------------------------------------------------------------- #
@app.route('/catalog/<item_title>')
def show_item(item_title):
    item = repository.get_item_by_title_url(item_title)
    return render_template('item/item.html', item=item)


@app.route('/catalog/items/new', methods=['GET', 'POST'])
@login_required
def new_item():
    if request.method == 'POST':
        item = Item(title=request.form['title'],
                    description=request.form['description'],
                    category_id=request.form['category_id'],
                    user=current_user)

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
    item = repository.get_item_by_title_url(item_title)
    if item:
        return jsonify(item=item.serialize)

    return jsonify()


# Authentication ------------------------------------------------------------ #
@login_manager.user_loader
def load_user(user_id):
    return repository.get_user_by_id(user_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        user = repository.create_user(data['email'], data['first_name'],
                                      data['last_name'], data['password'])

        if user:
            login_user(user)
            flash('You have successfully registered')
            return redirect(url_for('show_catalog'))

        flash('User with this email already exists')
        return redirect(url_for('register'))

    # GET
    return render_template('register.html')


@app.route('/login')
def login():
    # Create state token
    state = uuid.uuid4().hex
    login_session['state'] = state

    return render_template('login.html', state=state)


@app.route('/logout')
def logout():
    logout_user()
    login_session.pop('token', None)
    return redirect(url_for('show_catalog'))


@app.route('/oauth', methods=['POST'])
def oauth():
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


# --------------------------------------------------------------------------- #

if __name__ == '__main__':
    app.secret_key = 'f4e228586f2c45ba93def7a1b721baed'
    app.run('0.0.0.0', 8000)
