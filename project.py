#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, User, CatalogItem

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import re
from unicodedata import normalize

# Loads the JSON from Google and define the application name
CLIENT_ID = json.loads(open ('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"

#Connect to Database and create database session
engine = create_engine('sqlite:///itemlist.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a slug based on text (in this case, the name of the item) to be used
# as a link
_punct_re = re.compile(r'[\t !"#$%&\'()*\-/<=>?@\[\\\]^_`{|},.]+')
def slugify(text, delim=u'-'):
    """Generates an slightly worse ASCII-only slug."""
    result = []
    for word in _punct_re.split(text.lower()):
        word = normalize('NFKD', word).encode('ascii', 'ignore')
        if word:
            result.append(word)
    return unicode(delim.join(result))

@app.route('/login')
def showLogin():
    """Show login page if user is not logged in. If user is logged in, redirect
    to main page with flash message"""
    if 'username' in login_session:
        flash('You are already logged in.')
        return(redirect(url_for('mainPage')))
    else:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Log user in through Google account"""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # login_session['credentials'] = credentials

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash("You are now logged in as %s" % login_session['username'])
    print "done!"
    return output

@app.route('/gdisconnect')
def gdisconnect():
    """Disconnects user that logged in with Google account"""
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/logout')
def logout():
    """Logs user out"""
    if 'provider' in login_session:
        gdisconnect()
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('mainPage'))
    else:
        flash("You were not logged in")
        return redirect(url_for('mainPage'))

@app.route('/catalog.json')
def catalogJSON():
    """JSON endpoint for catalog items"""
    items = session.query(CatalogItem).all()
    return jsonify(catalog_items= [item.serialize for item in items])

@app.route('/')
def mainPage():
    """Main page, showing categories and 10 most recent items"""
    categories = session.query(Category).all()
    items = session.query(CatalogItem).order_by(desc(CatalogItem.created_at)).limit(10)
    return(render_template('main_page.html', categories = categories, items = items))

@app.route('/catalog/new', methods=['GET','POST'])
def newCatalogItem():
    """Create new catalog item if user is logged in"""
    if 'username' in login_session:
        categories = session.query(Category).all()
        if request.method == 'POST':
            category = session.query(Category).filter_by(name=request.form['category']).one()
            newItem = CatalogItem(name=request.form['name'],
                                  description=request.form['description'],
                                  slug=slugify(request.form['name']),
                                  category_id=category.id,
                                  user_id=login_session['user_id'])
            session.add(newItem)
            session.commit()
            return(redirect(url_for('mainPage')))
        else:
            return(render_template('new_catalog_item.html', categories = categories))
    else:
        flash('You must be logged in to create an item.')
        return(redirect(url_for('mainPage')))

@app.route('/catalog/<string:category_slug>/')
def showCategory(category_slug):
    """Show items for a certain category"""
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(slug=category_slug).one()
    category_items = session.query(CatalogItem).filter_by(category_id=category.id).all()
    print(category_items)
    return(render_template('show_category.html', category = category,
                           category_items = category_items,
                           categories = categories))

@app.route('/catalog/<string:category_slug>/<string:item_slug>/')
def showItem(category_slug, item_slug):
    """Show catalog item"""
    category = session.query(Category).filter_by(slug=category_slug).one()
    item = session.query(CatalogItem).filter_by(slug=item_slug).one()
    return(render_template('show_item.html', category = category, item = item))

@app.route('/catalog/<string:category_slug>/<string:item_slug>/edit', methods=['GET','POST'])
def editItem(category_slug, item_slug):
    """Edit catalog item if user is logged in and if user is the creator of the
    catalog item"""
    category = session.query(Category).filter_by(slug=category_slug).one()
    item = session.query(CatalogItem).filter_by(slug=item_slug).one()
    categories = session.query(Category).all()
    if 'username' in login_session:
        if login_session['user_id'] == item.user_id:
            if request.method == 'POST':
                new_category = session.query(Category).filter_by(name=request.form['category']).one()
                item.name = request.form['name']
                item.description = request.form['description']
                item.category_id = new_category.id
                session.add(item)
                session.commit()
                flash("Item successfully edited.")
                return(redirect(url_for('mainPage')))
            else:
                return(render_template('edit_item.html', category = category, item = item,
                                       categories = categories))
        else:
            flash('You do not have permission to edit this item.')
            return(redirect(url_for('mainPage')))
    else:
        flash('You must be logged in to edit this item.')
        return(redirect(url_for('mainPage')))


@app.route('/catalog/<string:category_slug>/<string:item_slug>/delete', methods=['GET','POST'])
def deleteItem(category_slug, item_slug):
    """Delete catalog item if user is logged in and is the creator of the
    catalog item."""
    category = session.query(Category).filter_by(slug=category_slug).one()
    item = session.query(CatalogItem).filter_by(slug=item_slug).one()
    if 'username' in login_session:
        if login_session['user_id'] == item.user_id:
            if request.method == 'POST':
                session.delete(item)
                session.commit()
                flash("Item successfully deleted.")
                return(redirect(url_for('mainPage')))
            else:
                return(render_template('delete_item.html', category = category, item = item))
        else:
            flash('You do not have permission to delete this item.')
            return(redirect(url_for('mainPage')))
    else:
        flash('You must be logged in to delete this item.')
        return(redirect(url_for('mainPage')))

# Below, helper functions for managing users
def createUser(login_session):
    newUser = User(name = login_session['username'], email = login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return(user.id)

def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return(user)

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return(user.id)
    except:
        return(None)

# Pass the login_session to all templates, so that it won't have to be passed
# in every function
@app.context_processor
def inject_user():
    return dict(login_session=login_session)


if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
