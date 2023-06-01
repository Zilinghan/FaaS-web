from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

__author__ = 'Argonne National Lab'

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config.from_pyfile('portal.conf')

import portal.views