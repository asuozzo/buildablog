from helpers import *
from handlers import *
from models import Blog
from models import User
from models import Comment
from models import Like


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', SubmitPage),
    ('/post/([0-9]+)/edit', EditPage),
    ('/post/([0-9]+)/comment/([0-9]+)/edit', EditComment),
    ('/post/([0-9]+)/delete', DeletePage),
    ('/post/([0-9]+)/comment/([0-9]+)/delete', DeleteComment),
    ("/signup", SignUpPage),
    ("/login", LogInPage),
    ("/logout", LogOutPage),
    ("/profile", ProfilePage),
    ('/post/([0-9]+)', PermalinkPage),
    ('/404', NotFoundPage),
    ("/post/([0-9]+)/like", LikeHandler),
    ("/post/([0-9]+)/comment", CommentHandler)
], debug=True)
