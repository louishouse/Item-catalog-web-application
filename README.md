### Purpose:
This project is a web portal which presents categories of items in record, along with CRUD functionalities to manipulate the data, using Oauth API from google with local permission.


### Files of this project:
| File name | Description |
| :---:     | :---        |
| catalog.py |		The main application code. | 
| db.py	    |		Contains the ORM model classes, be included in the catalog.py. | 
| client_secrets.json |	The app use this to access the Oauth API of google. | 
| fixedasset.db	|	Sqlite database file storing the current records. | 
| Templates folder | contains all the html templates file. | 
| static folder	|	contains the css file for html element styling. | 


### Before running this project, several installations are required, please refer to below list and related website for installation guide:
python 2.7	https://www.python.org/  
Flask		http://flask.pocoo.org/  
sqlalchemy 1.1	http://docs.sqlalchemy.org/en/rel_1_1/  
WTForms		https://wtforms.readthedocs.io/en/latest/  


### How to use:

1.Install all the required software and libraries mendtioned above.  
2.Under the project folder, execute the command 'python catalog.py'.  
3.Use browser to access the app with the url http://localhost:5000.  
