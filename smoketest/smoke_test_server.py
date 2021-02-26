from flask import Flask, send_file

app = Flask(__name__)


@app.route('/api/v1/binary/<hsum>')
def api_info(hsum):
    return send_file('filedata.zip')