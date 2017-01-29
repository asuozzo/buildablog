import webapp2
import os
import re

import jinja2

import string
import random

import hmac
import hashlib

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
