#!/usr/bin/env python

from portal import app

if __name__ == '__main__':
    app.run(host='localhost', port=5000,
            ssl_context=('./ssl/server.crt', './ssl/server.key'))
