#!/usr/bin/env python3

import json
import os

from tornado.escape import utf8
from tornado.ioloop import IOLoop
from tornado.options import define, options, parse_command_line, parse_config_file
from tornado.web import RequestHandler, Application, asynchronous, authenticated, HTTPError

from async_dropbox import DropboxMixin

define('port', default=33232)
define('flagfile', default='config.flags')
define('debug', default=False)
define('cookie_secret', default="3f8c0458deffeb471fc4142c1c0ad232")

# These don't have defaults; see README for details.
define('dropbox_consumer_key')
define('dropbox_consumer_secret')

def get_link_text(s1):
    import re
    flag = re.I|re.S
    p1 = r'https?://[\w/~%#-_=]+'
    iter1 = re.finditer(p1,s1,flag)
    l1 = []
    pos = 0
    for each in iter1:
        if len(s1[pos:each.start()]):
            text1 = s1[pos:each.start()],None
            l1.append(text1)
        link1 = each.group(),1
        l1.append(link1)
        pos = each.end()
    if(len(s1[pos:])):
        text1 = s1[pos:],None
        l1.append(text1)
    return l1

class BaseHandler(RequestHandler):
    def get_current_user(self):
        if self.get_secure_cookie("user"):
            o = json.loads(self.get_secure_cookie("user").decode('ascii'))
            for each in o['access_token']:
                if isinstance(o['access_token'][each],str):
                    o['access_token'][each] = bytes(o['access_token'][each],'ascii')
            print('o is')
            print(o)
            return o
        else:
            return None

    def get_access_token(self):
        # json turns this into unicode strings, but we need bytes for oauth
        # signatures.
        #return dict((utf8(k), utf8(v)) for (k, v) in self.current_user["access_token"].items())
        return self.current_user["access_token"]

class RootHandler(BaseHandler, DropboxMixin):
    @authenticated
    @asynchronous
    def get(self):
        self.dropbox_request('api', '/1/metadata/dropbox/', self.on_metadata,
                             self.get_access_token(),
                             list="true")
    
    def on_metadata(self, response):
        response.rethrow()
        metadata = json.load(response.buffer)
        self.render("index.html", metadata=metadata)

class TodoHandler(BaseHandler, DropboxMixin):
    @authenticated
    @asynchronous
    def get(self):
        print('ttt')
        print(self.get_access_token())
        self.dropbox_request('api-content', '/1/files/dropbox/test.json',
            self.on_gettodofile,
            self.get_access_token())

    def on_gettodofile(self, response):
        def get_list(m1):
            for a,b in m1.items():
                yield (b['time'],a,get_link_text(b['text']))
        response.rethrow()
        #obj1 = json.load(response.buffer.decode('ascii'))
        obj1 = json.loads(response.body.decode('ascii'))
        note1 = obj1['note1']
        l1 = list(get_list(note1))
        l1.sort(reverse=True)
        self.render("todo.html", texts=l1)

class AddHandler(BaseHandler, DropboxMixin):
    @authenticated
    @asynchronous
    def post(self):
        self.dropbox_request(
            'api-content',
            '/1/files_put/sandbox/%s' % self.get_argument('filename'),
            self.on_put_done,
            self.get_access_token(),
            put_body="Hi, I'm a text file!")

    def on_put_done(self, response):
        response.rethrow()
        self.redirect('/')

class DeleteHandler(BaseHandler, DropboxMixin):
    @authenticated
    @asynchronous
    def get(self):
        # This really shouldn't be a GET, but the point is to demonstrate
        # the dropbox api rather than demonstrate good web practices...
        self.dropbox_request(
            'api', '/1/fileops/delete', self.on_delete,
            self.get_access_token(),
            post_args=dict(
                root='sandbox',
                path=self.get_argument('path')))

    def on_delete(self, response):
        response.rethrow()
        self.redirect('/')

class CreateHandler(BaseHandler, DropboxMixin):
    @authenticated
    @asynchronous
    def post(self):
        self.dropbox_request(
            'api-content',
            '/1/files_put/sandbox/%s' % self.get_argument('filename'),
            self.on_put_done,
            self.get_access_token(),
            put_body="Hi, I'm a text file!")

    def on_put_done(self, response):
        response.rethrow()
        self.redirect('/')

class DropboxLoginHandler(BaseHandler, DropboxMixin):
    @asynchronous
    def get(self):
        if self.get_argument("oauth_token", None):
            self.get_authenticated_user(self._on_auth)
            return
        #print self.request.headers
        #print self.request.protocol
        self.authorize_redirect(callback_uri=self.request.full_url())

    def _on_auth(self, user):
        if not user:
            raise HTTPError(500, "Dropbox auth failed")
        user['access_token'].pop(b'uid')
        for each in user['access_token']:
            if isinstance(user['access_token'][each],bytes):
                user['access_token'][each] = \
                    user['access_token'][each].decode('ascii')
        print(user)
        self.set_secure_cookie("user", json.dumps(user))
        self.redirect('/todo')

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect("/todo")

def main():
    parse_command_line()
    flagfile = os.path.join(os.path.dirname(__file__), options.flagfile)
    parse_config_file(flagfile)

    settings = dict(
        login_url='/todo/login',
        debug=True,
        template_path=os.path.join(os.path.dirname(__file__), 'templates'),
        static_path=os.path.join(os.path.dirname(__file__), 'static'),

        cookie_secret=options.cookie_secret,
        dropbox_consumer_key=options.dropbox_consumer_key,
        dropbox_consumer_secret=options.dropbox_consumer_secret,
        )
    #print options.dropbox_consumer_key
    #print options.dropbox_consumer_secret
    app = Application([
            ('/', RootHandler),
            ('/todo/?', TodoHandler),
            ('/todo/add', AddHandler),
            ('/delete', DeleteHandler),
            ('/create', CreateHandler),
            ('/todo/login', DropboxLoginHandler),
            ('/todo/logout', LogoutHandler),
            ], **settings)
    app.listen(options.port,address='127.0.0.1',xheaders=True)
    IOLoop.instance().start()

if __name__ == '__main__':
    main()
