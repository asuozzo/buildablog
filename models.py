from google.appengine.ext import ndb
from helpers import *


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
        return Blog.get_by_id(int(blogid))


def check_valid_post(f):
    # @wraps(f)
    def wrapper(self, post_id):
        key = ndb.Key(Blog, int(post_id))
        post = key.get()

        if post:
            return f(self, post_id)
        else:
            self.redirect("/404")
            return
    return wrapper


def user_owns_post(f):
    def wrapper(self, post_id):
        key = Blog.by_id(post_id)


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


def user_logged_in(f):
    def wrapper(self):
        if self.user:
            self.redirect("/")
        else:
            return f(self)
    return wrapper


def check_valid_user(f):
    def wrapper(self):
        if self.user:
            user = User.by_name(self.user.username)
            if user:
                return f(self)
            else:
                self.redirect("/login")
                return
        else:
            self.redirect("/login")
            return
    return wrapper


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


def check_valid_comment(f):
    def wrapper(self, post_id, comment_id):
        post = Blog.by_id(post_id).key
        key = ndb.Key(Comment, int(comment_id), parent=post)
        comment = key.get()

        if comment:
            return f(self, post_id, comment_id)
        else:
            self.redirect("/404")
            return
    return wrapper


class Like(ndb.Model):
    blog = ndb.KeyProperty(kind=Blog)
    blogtitle = ndb.StringProperty()
    bloglink = ndb.IntegerProperty()
    user = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)
