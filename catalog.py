from flask import Flask, render_template, request, \
    redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from db import Base, User, AssetType, Asset
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from datetime import date
from wtforms import Form, IntegerField, DateField, \
    StringField, TextAreaField, SelectField, validators


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///fixedasset.db')
Base.metadata.bind = engine


DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    '''
    Renders the login page, for Oauth google account to login.
    '''
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits)
        for x in range(32))
    login_session['state'] = state
    return render_template('Login.html',
                           STATE=state,
                           LoginSession=login_session)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    '''
    Oauth authentication process for google account, when user confirmed that
    this webapp is allowed to access their userinfo, a one time authorization
    code will be given to the webapp, then webapp use the code to exchange for
    an access token, then use the token to access the users information even
    when the user is offline.
    This function also create a record in the local database for the loggin
    user, for local permission and authorization.
    '''
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')

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
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

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
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
                                 ('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'],
          'alert alert-success')
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return render_template('Logout.html', RESPONSE=response)
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return render_template('Logout.html', RESPONSE=response)


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


class AssetForm(Form):
    '''
    Use the WTForms to deal with form data, this class is defined so that the
    form data input by user can be conveniently validate and retrieve to an
    according object related to database.
    '''
    asset_type = SelectField('Asset Type')
    asset_name = StringField('Asset Name', [
        validators.Length(min=4, max=100),
        validators.DataRequired()
        ])
    asset_number = StringField('Asset Number', [
        validators.Length(min=4, max=100),
        validators.DataRequired(),
        ])
    cost = IntegerField('Asset Cost', [
        validators.DataRequired()
        ])
    purchase_date = DateField('Purchase Date', [
        validators.DataRequired()])
    description = TextAreaField('Description')


# JSON APIs that will ouput only the data as Javascript Object
@app.route('/asset_type/<string:asset_type>/assets/JSON')
def assetsByTypeJSON(asset_type):
    assets = session.query(Asset).filter_by(
        asset_type=asset_type).all()
    return jsonify(assets=[a.serialize for a in assets])


@app.route('/asset/<int:asset_id>/JSON')
def AssetJSON(asset_id):
    asset = session.query(Asset).filter_by(id=asset_id).one()
    return jsonify(asset=asset.serialize)


@app.route('/asset_type/JSON')
def assettypesJSON():
    assettypes = session.query(AssetType)
    return jsonify(assettypes=[at.serialize for at in assettypes])


@app.route('/allassets/JSON')
def allassetsJSON():
    allassets = session.query(Asset)
    return jsonify(allassets=[a.serialize for a in allassets])


@app.route('/')
def HomePage():
    '''
    It renders the home page of this webapp, which shows all the asset type
    currently have, and the most recently purchased fixed assets.
    '''
    alltypes = session.query(AssetType)
    assets = session.query(Asset).order_by(desc(Asset.purchase_date)).limit(8)
    return render_template('category.html',
                           LoginSession=login_session,
                           alltypes=alltypes,
                           assets=assets)


@app.route('/showcategory/<string:asset_type>')
def showCategory(asset_type):
    '''
    When click on a certain type on the home page, this function renders all
    the assets of that type.
    '''
    assets = session.query(Asset).filter_by(asset_type=asset_type).all()
    return render_template('showcategory.html',
                           LoginSession=login_session,
                           assets=assets,
                           asset_type=asset_type)


@app.route('/showassets')
def showAssets():
    '''
    This function renders all the assets currently have, and categorized by
    asset type.
    '''
    assets = session.query(Asset).order_by(asc(Asset.asset_number))
    alltypes = session.query(AssetType)
    return render_template('showassets.html',
                           assets=assets,
                           alltypes=alltypes,
                           LoginSession=login_session)


@app.route('/showassets/byuser')
def showAssetsByUser():
    '''
    show all assets and categorized by user.
    '''
    assets = session.query(Asset).order_by(asc(Asset.asset_number))
    users = session.query(User)
    return render_template('showassetsbyuser.html',
                           assets=assets,
                           users=users,
                           LoginSession=login_session)


@app.route('/asset_type', methods=['GET', 'POST'])
def AssetTypePage():
    '''
    It presents all the existed asset types along with a input field for
    creating new asset types, and checks the newly input asset type see
    if it is duplicate with existed one.
    '''
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        alltypes = session.query(AssetType)
        inputdata = request.form['asset_type']
        exist = session.query(AssetType).get(inputdata)
        if exist:
            flash('The Asset Type "%s" already exist' % inputdata,
                  'alert alert-danger')
            return redirect('/asset_type')
        if not inputdata:
            error = 'Asset Type should not be empty'
            return render_template('AssetType.html',
                                   LoginSession=login_session,
                                   error=error,
                                   alltypes=alltypes)
        else:
            newAssetType = AssetType(
                                     assettype=request.form['asset_type'],
                                     creatorid=login_session['user_id'],
                                     username=login_session['username'])
            session.add(newAssetType)
            session.commit()
            flash('New Asset Type "%s" Successfully Created'
                  % newAssetType.assettype, 'alert alert-success')
            return redirect('/asset_type')
    else:
        alltypes = session.query(AssetType)
        return render_template('AssetType.html',
                               LoginSession=login_session,
                               alltypes=alltypes)


@app.route('/asset_type/edit/<string:asset_type>', methods=['GET', 'POST'])
def editAssetType(asset_type):
    '''
    When click on edit of an asset type item, it points this function, first
    check if the current user is authorized, and later use the is_modified
    function of sqlalchemy to check if the object is modified, if not, use
    expunge to clean the session, if don't perform the expunge, it will result
    in error.
    Finally, take out all the related assets in database, and loop all of its
    asset type to be the value of renamed asset type.
    '''
    if 'username' not in login_session:
        return redirect('/login')
    at = session.query(AssetType).filter_by(assettype=asset_type).one()
    assettype = at.assettype
    if at.creatorid != login_session['user_id']:
        flash('You are not authorized to edit this asset type.\
              Please create your asset type in order to edit asset type.',
              'alert alert-danger')
        return redirect('/asset_type')
    if request.method == 'POST':
        at.assettype = request.form['asset_type']
        if not session.is_modified(at):
            flash('Asset Type "%s" remains not changed' % at.assettype,
                  'alert alert-info')
            session.expunge(at)
            return redirect(url_for('AssetTypePage'))
        session.expunge(at)
        exist = session.query(AssetType).get(at.assettype)
        if exist:
            flash('The Asset Type "%s" already exist' % at.assettype,
                  'alert alert-danger')
            return render_template('editAssetType.html',
                                   LoginSession=login_session,
                                   assettype=assettype,
                                   at=at)
        if not at.assettype:
            flash('Warning, changing the asset type will modify the asset type\
                  of related assets accordingly.', 'alert alert-danger')
            error = 'Asset Type should not be empty'
            return render_template('editAssetType.html',
                                   LoginSession=login_session,
                                   error=error,
                                   assettype=assettype,
                                   at=at)
        flash('Asset Type "%s" has been changed to "%s".'
              % (assettype, at.assettype), 'alert alert-success')
        assets = session.query(Asset).filter_by(asset_type=assettype).all()
        if assets:
            for a in assets:
                a.asset_type = at.assettype
                session.add(a)
                session.commit()
        session.add(at)
        session.commit()
        return redirect('/asset_type')
    flash('Warning, changing the asset type will modify the asset type\
          of related assets accordingly.', 'alert alert-danger')
    return render_template('editAssetType.html',
                           LoginSession=login_session,
                           assettype=assettype,
                           at=at)


@app.route('/asset_type/delete/<string:asset_type>', methods=['GET', 'POST'])
def deleteAssetType(asset_type):
    '''
    Perfomrs the delete action to asset type item, query to get a asset type
    object and compares its creatorid to the currently logged in user to check
    for permission.
    '''
    if 'username' not in login_session:
        return redirect('/login')
    at = session.query(AssetType).filter_by(assettype=asset_type).one()
    if at.creatorid != login_session['user_id']:
        flash('You are not authorized to delete this asset type.\
              Please create your asset type in order to delete asset type.',
              'alert alert-danger')
        return redirect('/asset_type')
    if request.method == 'POST':
        if request.form['confirm']:
            session.delete(at)
            flash('The Asset Type "%s" has been deleted.' % at.assettype,
                  'alert alert-success')
            session.commit()
            return redirect('/asset_type')
        else:
            return redirect('/asset_type')
    flash('Deleting the asset type will not delete the related assets, \
          and these assets will still show up when categorized by user \
          or in the Home page', 'alert alert-info')
    return render_template('deleteAssetType.html',
                           LoginSession=login_session,
                           at=at)


@app.route('/asset/create', methods=['GET', 'POST'])
def createAsset():
    '''
    If no asset type currently exist, it will flash in a message and redirect
    to the AssetType page fro new asset type creation.
    First, take all the asset types out of database, and loop it into as
    choices of the AssetForm object's asset type property.
    This function use the AssetForm class which built from wtforms library,
    to validate input data, if validate method returns true, use the ORM model
    to create an asset object and put it into database.
    '''
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        form = AssetForm(request.form)
        alltypes = session.query(AssetType)
        form.asset_type.choices = \
            [(t.assettype, t.assettype) for t in alltypes]
        validate = form.validate()
        if not validate:
            return render_template('createAsset.html',
                                   LoginSession=login_session,
                                   form=form)
        asn = form.asset_number.data
        exist = session.query(Asset).filter_by(asset_number=asn).one_or_none()
        if exist:
            flash('Asset Number "%s" already exist' % asn,
                  'alert alert-danger')
            return render_template('createAsset.html',
                                   LoginSession=login_session,
                                   form=form)
        else:
            newAsset = Asset(
                             asset_type=form.asset_type.data,
                             asset_name=form.asset_name.data,
                             asset_number=form.asset_number.data,
                             cost=form.cost.data,
                             purchase_date=form.purchase_date.data,
                             description=form.description.data,
                             managed_userid=getUserID(login_session['email']),
                             username=login_session['username'])
            session.add(newAsset)
            flash('New Asset "%s" has been created' % newAsset.asset_number,
                  'alert alert-success')
            session.commit()
            return redirect('/')
    else:
        form = AssetForm()
        alltypes = session.query(AssetType).all()
        if not alltypes:
            flash('Please create "asset type" first.', 'alert alert-info')
            return redirect('/asset_type')
        form.asset_type.choices = \
            [(t.assettype, t.assettype) for t in alltypes]
        return render_template('createAsset.html', LoginSession=login_session,
                               form=form)


@app.route('/asset/<int:id>/edit', methods=['GET', 'POST'])
def editAsset(id):
    '''
    This functin use the AssetForm class to validate the input data, and use
    is_modified function to check if the object has been modified, and also
    check for the asset number see if it duplicate with existed assets.
    '''
    if 'username' not in login_session:
        return redirect('/login')
    asset = session.query(Asset).filter_by(id=id).one()
    form = AssetForm(formdata=request.form, obj=asset)
    alltypes = session.query(AssetType).all()
    form.asset_type.choices = [(t.assettype, t.assettype) for t in alltypes]
    if asset.managed_userid != login_session['user_id']:
        flash('You are not authorized to edit this asset.\
              Please create your asset in order to edit asset.',
              'alert alert-danger')
        return redirect('/showassets')
    if request.method == 'POST' and form.validate():
        oldasn = asset.asset_number
        newasn = form.asset_number.data
        form.populate_obj(asset)
        if session.is_modified(asset) and oldasn == newasn:
            flash('The Asset "%s" has been updated' % newasn,
                  'alert alert-success')
            session.add(asset)
            session.commit()
            return redirect('/showassets')
        if oldasn != newasn:
            session.expunge(asset)
            exist = session.query(Asset).filter_by(asset_number=newasn)\
                .one_or_none()
            if exist:
                flash('The Asset number "%s" already exist' % newasn,
                      'alert alert-danger')
                return render_template('editasset.html',
                                       LoginSession=login_session,
                                       form=form, asset=asset)
            else:
                flash('The Asset "%s" has been updated' % newasn,
                      'alert alert-success')
                session.add(asset)
                session.commit()
                return redirect('/showassets')
        flash('Asset "%s" remains not changed' % oldasn, 'alert alert-info')
        return redirect('showassets')
    return render_template('editasset.html',
                           LoginSession=login_session,
                           form=form, asset=asset)


@app.route('/asset/<int:id>/delete', methods=['GET', 'POST'])
def deleteAsset(id):
    '''
    If user permission check passed, performs delete action to remove an
     asset record from database.
    '''
    if 'username' not in login_session:
        return redirect('/login')
    asset = session.query(Asset).filter_by(id=id).one()
    if asset.managed_userid != login_session['user_id']:
        flash('You are not authorized to delete this asset.\
              Please create your asset in order to delete asset.',
              'alert alert-danger')
        return redirect('/showassets')
    if request.method == 'POST':
        if request.form['confirm']:
            session.delete(asset)
            flash('The Asset "%s" has been deleted.' % asset.asset_number,
                  'alert alert-success')
            session.commit()
            return redirect('/showassets')
        else:
            return redirect('/showassets')
    return render_template('deleteasset.html',
                           LoginSession=login_session,
                           asset=asset,)


if __name__ == '__main__':
    app.secret_key = 'secret'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
