# Item Catalog - Felipe Galvão

To run this project locally and see that the tests passed, you have to follow
the steps below.

1. Clone the repository
2. Create the database running the code:

```
python database_setup.py
```

3. Populate the database with initial categories and items running:

```
python populate_db.py
```

4. On [Google developers console](https://console.developers.google.com/), create a new project, setup http://localhost:5000 as allowed Javascript origin and Authorized Redirect URI (in this one, also setup http://localhost:5000/login); download the JSON file with the client ID and the secret key and save it on the same folder as client_secrets.json
5. And finally, run the command below and then go to [localhost port 5000](http://localhost:5000/)

```
python project.py
```

Python version must be Python 2.
