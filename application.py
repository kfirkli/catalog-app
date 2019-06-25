from flask import Flask, request, render_template, url_for, redirect, jsonify

import repository
from database_structure import Item

app = Flask(__name__)


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
def new_item():
    if request.method == 'POST':
        item = Item(title=request.form['title'],
                    description=request.form['description'],
                    category_id=request.form['category_id'])

        repository.create_item(item)

        return redirect(url_for('show_catalog'))

    # GET
    categories = repository.get_categories()
    if not categories:
        return 'There is no categories in the Database.'

    return render_template('item/new.html', categories=categories)


@app.route('/catalog/<item_title>/edit', methods=['GET', 'POST'])
def edit_item(item_title):
    item = repository.get_item_by_title_url(item_title)

    if request.method == 'POST':
        item.title = request.form['title']
        item.description = request.form['description']
        item.category_id = request.form['category_id']

        repository.session.commit()
        return redirect(url_for('show_catalog'))

    # GET
    categories = repository.get_categories()
    if not categories:
        return 'There is no categories in the Database.'

    return render_template('item/edit.html', item=item, categories=categories)


@app.route('/catalog/<item_title>/delete', methods=['GET', 'POST'])
def delete_item(item_title):
    item = repository.get_item_by_title_url(item_title)

    if request.method == 'POST':
        repository.delete_item(item)

        return redirect(url_for('show_catalog'))

    # GET
    return render_template('item/delete.html', item=item)


@app.route('/catalog/<item_title>.json')
def item_json(item_title):
    item = repository.get_item_by_title_url(item_title)
    if item:
        return jsonify(item=item.serialize)

    return jsonify()


# --------------------------------------------------------------------------- #

if __name__ == '__main__':
    app.run('0.0.0.0', 8000)
