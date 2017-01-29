from helpers import *
from handlers import *
from models import Blog
from models import User
from models import Comment
from models import Like


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', SubmitPage),
    ('/([0-9]+)/edit', EditPage),
    ('/([0-9]+)/comment/([0-9]+)/edit', EditComment),
    ('/([0-9]+)/delete', DeletePage),
    ('/([0-9]+)/comment/([0-9]+)/delete', DeleteComment),
    ("/signup", SignUpPage),
    ("/login", LogInPage),
    ("/logout", LogOutPage),
    ("/profile", ProfilePage),
    ('/([0-9]+)', PermalinkPage)
], debug=True)
