# Item Catalog

Web Application for Item Catalog

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

1. A FSND-Virtual-Machine of Udacity running (See instruction on [Fullstack Nanodegree VM repository](https://github.com/udacity/fullstack-nanodegree-vm)).
2. Clone this repository into your Virtual machine.

### Install additional python packages

1. Install the python package 'flask_login'
```
sudo pip install flask_login
```

## Initialize the database

The categories table must be initialize, otherwise you can't select categories in the app.  
_You can initialize it with your own categories or using the following scripts_  

You have 2 options:

1. Initialize only the categories table.

```
python init_categories.py
```

2. Initialize the categories table and some items for example.

_Note that this script will add items as user id of 1 and 2, so be careful which users get the ownership on them.  
Consider to register the two first users first._

```
python init_categories_and_items.py
```

## Running

1. Execute the application 
```
python application.py
```

2. Navigate your browser to [http://localhost:8000/](http://localhost:8000/)

## Built With

* [Flask](http://flask.pocoo.org/) - The web framework
* [SQLAlchemy](https://www.sqlalchemy.org/) - The Database Toolkit for Python
* [Jinja2](https://rometools.github.io/rome/) - The web template engine (Integrated in Flask)

## Authors

* **Kfir Klichevski** - *Initial work* - [kklichevski](https://github.com/kklichevski)