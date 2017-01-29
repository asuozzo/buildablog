import os
import re

import webapp2
import jinja2

import string
import random
import hashlib
import hmac

from google.appengine.ext import ndb

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
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class Blog(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    author = ndb.StringProperty()
    commentcount = ndb.IntegerProperty(default=0)
    likecount = ndb.IntegerProperty(default=0)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @classmethod
    def by_id(cls, blogid):
        return Blog.get_by_id(blogid)


def users_key(group='default'):
    return ndb.Key("users", group)


class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, username):
        u = User.query().filter(User.username == username).get()
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


class Comment(ndb.Model):
    blog = ndb.KeyProperty(kind=Blog)
    blogtitle = ndb.StringProperty()
    bloglink = ndb.IntegerProperty()
    user = ndb.StringProperty()
    comment = ndb.TextProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("comment.html", c=self)


class Like(ndb.Model):
    blog = ndb.KeyProperty(kind=Blog)
    blogtitle = ndb.StringProperty()
    bloglink = ndb.IntegerProperty()
    user = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)


class MainPage(Handler):
    def get(self):
        blogs = Blog.query().order(-Blog.created).fetch(10)
        self.render("home.html", blogs=blogs,
                    username=self.check_login(self.user))


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

            id = b.key.integer_id()

            self.redirect("/" + str(id))
        else:
            error = "Make sure to fill out both the title and post fields!"
            self.render_submit(subject, content, error,
                               username=self.check_login(self.user))


class PermalinkPage(Handler):
    def render_post(self, post_id):
        post = Blog.by_id(post_id)

        comments = Comment.query(Comment.blog == post.key)
        likes = Like.query(Like.blog == post.key)

        username = self.check_login(self.user)
        userliked = False

        for like in likes:
            if username == like.user:
                userliked = True

        if not post:
            self.error(404)
            return

        self.render("blogpage.html", post=post,
                    username=username,
                    comments=comments,
                    userliked=userliked)

    def get(self, post_id):
        self.render_post(int(post_id))

    def post(self, post_id):
        button = self.request.get("submit")
        blog = Blog.by_id(int(post_id))

        if not self.check_login(self.user):
            self.redirect("/login")
        else:
            # Check which button the user pressed
            if button == "comment":
                comment = self.request.get("comment")

                if comment == "":
                    error = "There's no comment there!"
                    self.render("blogpage.html", post=blog,
                                username=self.check_login(self.user),
                                error=error)
                else:
                    user = self.user.username
                    blogtitle = blog.subject
                    bloglink = int(post_id)
                    c = Comment(parent=blog.key, blog=blog.key, user=user,
                                comment=comment, blogtitle=blogtitle,
                                bloglink=bloglink)
                    c.put()

            elif button == "like":
                user = self.user.username
                blogtitle = blog.subject
                bloglink = int(post_id)
                l = Like(parent=blog.key, user=user, blog=blog.key,
                         blogtitle=blogtitle, bloglink=bloglink)
                l.put()

            elif button == "unlike":
                user = self.user.username
                like = Like.gql("WHERE user = :1 LIMIT 1", user).get()
                like.key.delete()

            # Add revised comment/like count to the related blog entity
            blog.commentcount = Comment.query(ancestor=blog.key).count()
            blog.likecount = Like.query(ancestor=blog.key).count()
            blog.put()

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

        # validate signup form
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
            self.redirect('/profile')


class LogInPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/profile')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class LogOutPage(Handler):
    def get(self):
        self.logout()
        self.redirect('/login')


# Create a landing page for logged in user
class ProfilePage(Handler):
    def get(self):
        if self.user:
            # Get all items associated with the user
            blogs = Blog.query(Blog.author == self.user.username)
            comments = Comment.query(Comment.user == self.user.username)
            likes = Like.query(Like.user == self.user.username)
            self.render('profile.html', username=self.check_login(self.user),
                        blogs=blogs, comments=comments, likes=likes)
        else:
            self.redirect("/login")


# Edit a user's post
class EditPage(Handler):
    def render_edit(self, post_id):
        post = Blog.by_id(int(post_id))

        if post.author != self.check_login(self.user):
            self.redirect("/" + post_id)
        else:
            self.render("edit.html", username=self.user.username,
                        content=post.content, subject=post.subject,
                        type="post")

    def get(self, post_id):
        self.render_edit(post_id)

    def post(self, post_id):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            post = Blog.by_id(int(post_id))
            post.subject = subject
            post.content = content
            post.put()
            self.redirect("/" + post_id)
        else:
            error = "Make sure to fill out both the title and post fields!"
            self.render_submit(subject, content, error,
                               username=self.check_login(self.user))


# Edit a user's comment
class EditComment(Handler):
    def render_edit(self, post_id, comment_id):

        post = Blog.by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id), parent=post.key)

        if comment.user != self.check_login(self.user):
            self.redirect("/" + post_id)
        else:
            self.render("edit.html", username=self.user.username,
                        content=comment.comment, subject=post.subject,
                        type="comment")

    def get(self, post_id, comment_id):
        self.render_edit(post_id, comment_id)

    def post(self, post_id, comment_id):
        content = self.request.get("content")

        if content:
            post = Blog.by_id(int(post_id))
            comment = Comment.get_by_id(int(comment_id), parent=post.key)
            comment.comment = content
            comment.put()
            self.redirect("/" + post_id)
        else:
            error = "Make sure to there's text in the comment field!"
            self.render_submit(content, error,
                               username=self.check_login(self.user))


# Delete a page
class DeletePage(Handler):
    def render_delete(self, post_id):
        post = Blog.by_id(int(post_id))

        if post.author != self.check_login(self.user):
            self.redirect("/" + post_id)
        else:
            self.render("delete.html", username=self.user.username,
                        post=post, type="post")

    def get(self, post_id):
        self.render_delete(post_id)

    def post(self, post_id):
        post = Blog.by_id(int(post_id))
        post.key.delete()
        self.redirect("/profile")


# Delete a comment
class DeleteComment(Handler):
    def render_delete(self, post_id, comment_id):
        post = Blog.by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id), parent=post.key)

        if comment.user != self.check_login(self.user):
            self.redirect("/" + post_id)
        else:
            self.render("delete.html", username=self.user.username,
                        comment=comment, post=post, type="comment")

    def get(self, post_id, comment_id):
        self.render_delete(post_id, comment_id)

    def post(self, post_id, comment_id):
        post = Blog.by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id), parent=post.key)

        comment.key.delete()
        self.redirect("/profile")


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', SubmitPage),
    ('/([0-9]+)/edit', EditPage),
    ('/([0-9]+)/comment/([0-9]+)/edit', EditComment),
    ('/([0-9]+)/comment/([0-9]+)/delete', DeleteComment),
    ('/([0-9]+)/delete', DeletePage),
    ("/signup", SignUpPage),
    ("/login", LogInPage),
    ("/logout", LogOutPage),
    ("/profile", ProfilePage),
    ('/([0-9]+)', PermalinkPage)
], debug=True)
