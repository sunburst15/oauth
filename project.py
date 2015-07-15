from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash

app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem

# step 2: create anti forgery state token
from flask import session as login_session
import random, string

# step 5: GConnect
from flask import make_response
import json
import google_oauth as goauth

CLIENT_ID = goauth.get_client_id('client_secrets.json')

#Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

def _generate_random_string(length):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) 
            for x in xrange(length))


def _save_to_session(key, value):
    login_session[key] = value


def _get_from_session(key):
    return login_session.get(key, None)


def _delete_from_session(key):
    login_session.pop(key, None)


def _get_json_response(message, httpcode):
    response = make_response(json.dumps(message), httpcode)
    response.headers['Content-Type'] = 'applicaton/json'
    return response



# step 2: create anti forgery state token
@app.route('/login')
def showLogin():
    state = _generate_random_string(length=32)
    _save_to_session('state', state)
    # step 3: create login page
    return render_template('login.html', STATE=state)


# step 5: Gconnect
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != _get_from_session('state'):
        return _get_json_response('Invalidate state', 401)

    # authorization code!
    auth_code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        credentials = goauth.get_credential_from_auth_code(auth_code,
                        'client_secrets.json', 'postmessage')

    except goauth.OAuthError as e:
        return _get_json_response('Failed to upgrade the auth code:' + e, 401)

    # check that the access token is valid
    access_token = credentials.access_token

    print access_token

    token_info = goauth.get_access_token_info(access_token)

    if token_info.get('error') is not None:
        return _get_json_response('error', 500)

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if token_info['user_id'] != gplus_id:
        return _get_json_response("Token user ID != given user ID", 401)
    if token_info['issued_to'] != CLIENT_ID:
        return _get_json_response("Token client ID != app's client ID", 401)

    # Check if user is already logged in
    stored_access_token = _get_from_session('access_token')
    stored_gplus_id = _get_from_session('gplus_id')

    if stored_access_token is not None and gplus_id == stored_gplus_id:
        _save_to_session('access_token', access_token)
        return _get_json_response('Current user is already connected', 200)
    
    # store the access token in the session for the later use.
    _save_to_session('access_token', access_token)
    _save_to_session('gplus_id', gplus_id)
    _save_to_session('revoke_uri', credentials.revoke_uri)

    # get user info
    userinfo = goauth.get_user_info(access_token)

    _save_to_session('username', userinfo['name'])
    _save_to_session('picture', userinfo['picture'])
    _save_to_session('email', userinfo['email'])

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# Step 6: Disconnect - revoke a current user's token and reset their login_session
@app.route("/logout")
def gdisconnect():
    access_token = _get_from_session('access_token')
    if access_token is None:
        return _get_json_response('Current user not connected', 401)

    revoke_uri = _get_from_session('revoke_uri')
    username = _get_from_session('username')

    print access_token

    result = goauth.revoke_access_token(access_token, revoke_uri)

    if result['status'] == '200':
        # reset the user's session
        _delete_from_session('access_token')
        _delete_from_session('gplus_id')
        _delete_from_session('revoke_uri')
        _delete_from_session('username')
        _delete_from_session('email')
        _delete_from_session('picture')

        flash("%s just logged out" % username)
    else:
        print result
        flash("cannot logout the session for %s" % username)
        
    return redirect(url_for('showRestaurants'))


#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
  restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
  return render_template('restaurants.html', restaurants=restaurants)


#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
  if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'])
      session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      session.commit()
      return redirect(url_for('showRestaurants'))
  else:
      return render_template('newRestaurant.html')


#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
  editedRestaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
  if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('showRestaurants'))
  else:
    return render_template('editRestaurant.html', restaurant = editedRestaurant)


#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET','POST'])
def deleteRestaurant(restaurant_id):
  restaurantToDelete = session.query(Restaurant).filter_by(id=restaurant_id).one()
  if request.method == 'POST':
    session.delete(restaurantToDelete)
    flash('%s Successfully Deleted' % restaurantToDelete.name)
    session.commit()
    return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))
  else:
    return render_template('deleteRestaurant.html',restaurant=restaurantToDelete)


#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    return render_template('menu.html', items = items, restaurant=restaurant)
     


#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
  restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
  if request.method == 'POST':
      newItem = MenuItem(name = request.form['name'], description=request.form['description'], price=request.form['price'], course=request.form['course'], restaurant_id=restaurant_id)
      session.add(newItem)
      session.commit()
      flash('New Menu %s Item Successfully Created' % (newItem.name))
      return redirect(url_for('showMenu', restaurant_id=restaurant_id))
  else:
      return render_template('newmenuitem.html', restaurant_id=restaurant_id)

#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):

    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit() 
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id=restaurant_id, menu_id = menu_id, item = editedItem)


#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one() 
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item=itemToDelete)


if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)

