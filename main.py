import os
import re
import json

import webapp2
import jinja2

import string
import random
import hashlib
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "afsdlkjasf9845345lkjafakuf059rwjekrngja"


def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)


def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split("|")[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt():
    return "".join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(str(name) + str(pw) + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pw_hash(name, pw, h):
    salt = h.split("|")[1]
    if make_pw_hash(name, pw, salt) == h:
        return True


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def check_login(self, user):
        if user:
            username = self.user.username
        else:
            username = None
        return username

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @classmethod
    def by_id(cls, blogid):
        return Blog.get_by_id(blogid)


def users_key(group='default'):
    return db.Key.from_path("users", group)


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.EmailProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, username):
        u = User.all().filter("username =", username).get()
        return u

    @classmethod
    def register(cls, username, pw, email=None):
        pw_hash = make_pw_hash(username, pw)
        return User(parent=users_key(),
                    username=username,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username)
        if u and valid_pw_hash(username, password, u.pw_hash):
            return u


class Comment(db.Model):
    blog = db.ReferenceProperty(Blog, collection_name="comments")
    user = db.StringProperty()
    comment = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("comment.html", c=self)


class Like(db.Model):
    blog = db.ReferenceProperty(Blog, collection_name="likes")
    user = db.StringProperty()
    like = db.BooleanProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_count(cls, blog):
        count = Like.all().filter("blog =", blog).get()
        return count


class MainPage(Handler):
    def render_index(self):
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC LIMIT 10")

        self.render("home.html", blogs=blogs, username=self.check_login(self.user))

    def get(self):
        self.render_index()


class SubmitPage(Handler):
    def render_submit(self, subject="", content="", error="", username=""):

        self.render("newpost.html", subject=subject,
                    content=content, error=error,
                    username=self.check_login(self.user))

    def get(self):
        if self.user:
            self.render_submit()
        else:
            self.redirect("/signup")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            b = Blog(subject=subject, content=content,
                     author=self.user.username)
            b.put()

            id = b.key().id()

            self.redirect("/" + str(id))
        else:
            error = "Make sure to fill out both the title and post fields!"
            self.render_submit(subject, content, error,
                               username=self.check_login(self.user))


class PermalinkPage(Handler):
    def render_post(self, post_id):
        post = Blog.get_by_id(post_id)

        comments = post.comments

        commentcount = comments.count()

        if not post:
            self.error(404)
            return

        self.render("blogpage.html", post=post,
                    username=self.check_login(self.user),
                    comments=comments, commentcount=commentcount)

    def get(self, post_id):
        self.render_post(int(post_id))

    def post(self, post_id):
        comment = self.request.get("comment")

        blog = Blog.get_by_id(int(post_id))

        if not self.check_login(self.user):
            error = "You must be logged in to post a comment."
            self.render("blogpage.html", post=blog,
                        username=self.check_login(self.user),
                        error=error, comment=comment)
        elif comment == "":
            error = "There's no comment there!"
            self.render("blogpage.html", post=blog,
                        username=self.check_login(self.user),
                        error=error)
        else:
            user = self.user.username
            c = Comment(blog=blog, user=user, comment=comment)
            c.put()

            self.render_post(int(post_id))


class SignUpPage(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        else:
            u = User.by_name(username)
            if u:
                params['error_username'] = "User already exists."
                have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            if email:
                u = User.register(username, password, email)
            else:
                u = User.register(username, password)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class LogInPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class LogOutPage(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')


class WelcomePage(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.check_login(self.user))
        else:
            self.redirect("/signup")


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', SubmitPage),
    ("/signup", SignUpPage),
    ("/login", LogInPage),
    ("/logout", LogOutPage),
    ("/welcome", WelcomePage),
    ('/([0-9]+)', PermalinkPage)
], debug=True)
