from flask import Flask, render_template
import requests


API_NINJAS_KEY = "+PfEP0F78yN7Bv7RO0uw+A==myZNDLRXn8q1cxgk"
TRIVIA_URL = 'https://api.api-ninjas.com/v1/trivia'



app = Flask(__name__)

@app.route('/')
def index():
    resp = requests.get(TRIVIA_URL, headers={'X-Api-Key': API_NINJAS_KEY}).json()
    trivia=resp[0]
    return render_template('index.html', question=trivia['question'], answer=trivia['answer'])

app.run()
