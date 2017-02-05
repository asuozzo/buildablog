import webapp2
from helpers import *
from models import *


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


class MainPage(Handler):
    '''The main blog landing page'''
    def get(self):
        blogs = Blog.query().order(-Blog.created).fetch(10)
        self.render("home.html", blogs=blogs,
                    username=self.check_login(self.user))


class SubmitPage(Handler):
    '''Create a new post'''
    def render_submit(self, subject="", content="", error="", username=""):

        self.render("newpost.html", subject=subject,
                    content=content, error=error,
                    username=self.check_login(self.user))

    def get(self):
        if self.user:
            self.render_submit()
        else:
            self.redirect("/login")

    def post(self):
        if self.user:
            subject = self.request.get("subject")
            content = self.request.get("content")

            if subject and content:
                b = Blog(subject=subject, content=content,
                         author=self.user.username)
                b.put()

                id = b.key.integer_id()

                self.redirect("/post/" + str(id))
            else:
                error = "Make sure to fill out both the title and post fields!"
                self.render_submit(subject, content, error,
                                   username=self.check_login(self.user))
        else:
            self.redirect("/login")


class PermalinkPage(Handler):
    '''The landing page for each blog post'''
    def render_post(self, post_id):
        post = Blog.by_id(post_id)

        comments = Comment.query(ancestor=post.key)
        likes = Like.query(ancestor=post.key)

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

    @check_valid_post
    def get(self, post_id):
        self.render_post(int(post_id))

    @check_valid_post
    def post(self, post_id):
        button = self.request.get("submit")
        blog = Blog.by_id(post_id)

        if not self.check_login(self.user):
            self.redirect("/login")
        # else:
        #     # Check which button the user pressed
        #     if button == "comment":
        #         comment = self.request.get("comment")

        #         if comment == "":
        #             error = "There's no comment there!"
        #             self.render("blogpage.html", post=blog,
        #                         username=self.check_login(self.user),
        #                         error=error)
        #         else:
        #             user = self.user.username
        #             blogtitle = blog.subject
        #             bloglink = int(post_id)
        #             c = Comment(parent=blog.key, blog=blog.key, user=user,
        #                         comment=comment, blogtitle=blogtitle,
        #                         bloglink=bloglink)
        #             c.put()

        #     # Add revised comment/like count to the related blog entity
        #     blog.commentcount = Comment.query(ancestor=blog.key).count()
        #     blog.likecount = Like.query(ancestor=blog.key).count()
        #     blog.put()

        self.render_post(int(post_id))


class SignUpPage(Handler):
    '''Sign up a new user'''
    @user_logged_in
    def get(self):
        self.render("signup.html")

    @user_logged_in
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
    '''Log the user in'''
    @user_logged_in
    def get(self):
        self.render("login.html")

    @user_logged_in
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
    '''Log the user out'''
    def get(self):
        self.logout()
        self.redirect('/login')


class ProfilePage(Handler):
    ''' Display a profile page with a logged-in user's activity '''
    @check_valid_user
    def get(self):
        # Get all items associated with the user
        blogs = Blog.query(Blog.author == self.user.username)
        comments = Comment.query(Comment.user == self.user.username)
        likes = Like.query(Like.user == self.user.username)
        self.render('profile.html', username=self.check_login(self.user),
                    blogs=blogs, comments=comments, likes=likes)


class EditPage(Handler):
    ''' Edit a user's post '''
    def render_edit(self, post_id):
        post = Blog.by_id(post_id)

        if post.author != self.check_login(self.user):
            self.redirect("/post/" + post_id)
        else:
            self.render("edit.html", username=self.user.username,
                        content=post.content, subject=post.subject,
                        type="post", post_id=post_id)

    @check_valid_post
    def get(self, post_id):
        self.render_edit(post_id)

    @check_valid_post
    def post(self, post_id):
        post = Blog.by_id(post_id)

        if post.author != self.check_login(self.user):
            self.redirect("/post/" + post_id)
        else:
            subject = self.request.get("subject")
            content = self.request.get("content")

            if subject and content:
                post = Blog.by_id(post_id)
                post.subject = subject
                post.content = content
                post.put()
                self.redirect("/post/" + post_id)
            else:
                error = "Make sure to fill out both the title and post fields!"
                self.render_edit(subject, content, error,
                                 username=self.check_login(self.user))


class EditComment(Handler):
    ''' Edit a user's comment '''
    def render_edit(self, post_id, comment_id):

        post = Blog.by_id(post_id)
        comment = Comment.get_by_id(int(comment_id), parent=post.key)

        if comment.user != self.check_login(self.user):
            self.redirect("/post/" + post_id)
        else:
            self.render("edit.html", username=self.user.username,
                        content=comment.comment, subject=post.subject,
                        type="comment", post_id=post_id)

    @check_valid_comment
    def get(self, post_id, comment_id):
        self.render_edit(post_id, comment_id)

    @check_valid_comment
    def post(self, post_id, comment_id):
        post = Blog.by_id(post_id)
        comment = Comment.get_by_id(int(comment_id), parent=post.key)

        if comment.user != self.check_login(self.user):
            self.redirect("/post/" + post_id)
        else:
            content = self.request.get("content")

            if content:
                comment.comment = content
                comment.put()
                self.redirect("/post/" + post_id)
            else:
                error = "Make sure to there's text in the comment field!"
                self.render_edit(content, error,
                                 username=self.check_login(self.user))


class DeletePage(Handler):
    ''' Delete a page '''
    def render_delete(self, post_id):
        post = Blog.by_id(post_id)

        if post.author != self.check_login(self.user):
            self.redirect("post/" + post_id)
        else:
            self.render("delete.html", username=self.user.username,
                        post=post, type="post", post_id=post_id)

    @check_valid_post
    def get(self, post_id):
        self.render_delete(post_id)

    @check_valid_post
    def post(self, post_id):
        post = Blog.by_id(post_id)

        if post.author != self.check_login(self.user):
            self.redirect("/post/" + post_id)
        else:
            post.key.delete()
            self.redirect("/profile")


class DeleteComment(Handler):
    '''Delete a comment'''
    def render_delete(self, post_id, comment_id):
        post = Blog.by_id(post_id)
        comment = Comment.get_by_id(int(comment_id), parent=post.key)

        if comment.user != self.check_login(self.user):
            self.redirect("/post/" + post_id)
        else:
            self.render("delete.html", username=self.user.username,
                        comment=comment, post=post, type="comment",
                        post_id=post_id)

    @check_valid_comment
    def get(self, post_id, comment_id):
        self.render_delete(post_id, comment_id)

    @check_valid_comment
    def post(self, post_id, comment_id):
        post = Blog.by_id(post_id)
        comment = Comment.get_by_id(int(comment_id), parent=post.key)

        if comment.user != self.check_login(self.user):
            self.redirect("/post/" + post_id)
        else:
            comment.key.delete()
            self.redirect("/profile")


class NotFoundPage(Handler):
    def get(self):
        self.render("404.html", username=self.user.username)


class LikeHandler(Handler):
    @check_valid_post
    def post(self, post_id):
        user = self.user.username
        post = Blog.by_id(post_id)
        if post.author != user:
            like = Like.gql("WHERE user = :1 AND blog = :2 LIMIT 1",
                            user, post.key).get()
            if like:
                like.key.delete()
            else:
                blogtitle = post.subject
                bloglink = int(post_id)
                l = Like(parent=post.key, user=user, blog=post.key,
                         blogtitle=blogtitle, bloglink=bloglink)
                l.put()

        self.redirect("/post/"+post_id)


class CommentHandler(Handler):
    @check_valid_post
    def post(self, post_id):
        blog = Blog.by_id(post_id)
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

        # Add revised comment/like count to the related blog entity
        blog.commentcount = Comment.query(ancestor=blog.key).count()
        blog.likecount = Like.query(ancestor=blog.key).count()
        blog.put()

        self.redirect("/post/" + post_id)
