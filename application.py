from flask import Flask, request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_structure import Base

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# INDEX (Catalog) ----------------------------------------------------------- #
@app.route('/')
@app.route('/catalog')
def show_catalog():
    return 'show Categories | latest items'


@app.route('/catalog.json')
def catalog_json():
    return 'catalog json'


# Categories ---------------------------------------------------------------- #
@app.route('/catalog/<category_name>/items')
def show_category(category_name):
    return 'show category: %s | items' % category_name


@app.route('/catalog/<category_name>/items.json')
def category_json(category_name):
    return 'category: %s json' % category_name


# Items --------------------------------------------------------------------- #
@app.route('/catalog/<item_title>')
def show_item(item_title):
    return 'show item: %s' % item_title


@app.route('/catalog/items/new', methods=['GET', 'POST'])
def new_item():
    if request.method == 'POST':
        return 'new item added!'

    # GET
    return 'show new item'


@app.route('/catalog/<item_title>/edit', methods=['GET', 'POST'])
def edit_item(item_title):
    if request.method == 'POST':
        return 'item: %s edited!' % item_title

    # GET
    return 'show edit item %s' % item_title


@app.route('/catalog/<item_title>/delete', methods=['GET', 'POST'])
def delete_item(item_title):
    if request.method == 'POST':
        return 'item: %s deleted!' % item_title

    # GET
    return 'show delete item %s' % item_title


@app.route('/catalog/<item_title>.json')
def item_json(item_title):
    return 'item: %s json' % item_title


# --------------------------------------------------------------------------- #

if __name__ == '__main__':
    app.run('0.0.0.0', 8000)
