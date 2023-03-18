#!/usr/bin/env python
import os
from portal import app

UPLOAD_FOLDER = './data/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

if __name__ == '__main__':
    # app.debug = False
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024 # The maximum file size is set to be 8MB
    app.run(host='localhost', port=8000, ssl_context=('./ssl/cert.pem', './ssl/key.pem'))
