#!/usr/bin/env python
import os
from portal import app

UPLOAD_FOLDER = './data/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024 # The maximum file size is set to be 8MB

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, ssl_context=('./ssl/cert.pem', './ssl/key.pem'))
