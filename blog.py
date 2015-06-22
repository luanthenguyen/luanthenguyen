import os
import re
import random
import hashlib
import hmac
import logging
import json
from datetime import datetime
from string import letters
import webapp2
import jinja2
from google.appengine.api import memcache
from google.appengine.api import users
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
secret = 'fart'
CACHE  = {}
def cache (key = "",  update = False):
    global CACHE
    if (update != False or key not in CACHE):
        if(key == 'front'):
	    posts = greetings = Post.all().order('-created')
	    CACHE[key]= [posts,datetime.now()]
	    return CACHE[key]
        else:
	    post_id = key
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
	    posts = db.get(key)
	    CACHE[post_id]= [posts,datetime.now()]
	    return CACHE[post_id]
    else:
        return CACHE[key]
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

class MainPage(BaseHandler):
  def get(self):
      self.write('Hello!')
      self.redirect('/wiki')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)
 

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d



class BlogFront(BaseHandler):
    def get(self):
        key = "front"
	posts = cache(key)[0]
	QUERIED  = datetime.now() - cache(key)[1]
        if self.format == 'html':
            self.render('front.html', posts = posts, queried  = QUERIED.seconds )
        else:
            return self.render_json([p.as_dict() for p in posts])

class PostPage(BaseHandler):
    def get(self, post_id):
        post = cache(post_id)
	if not post:
            self.error(404)
            return
        if self.format == 'html':
	    QUERIED  = datetime.now() - post[1]
            self.render("permalink.html", post = post[0],queried=QUERIED.seconds)
	   # self.redirect('/unit3/welcome')
        else:
            self.render_json(post.as_dict())

class NewPost(BaseHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
	    cache(key = 'front',update = True)
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BaseHandler):
    def get(self):
        self.render("signup-form.html", hide =True)

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/unit3/welcome')

class Login(BaseHandler):
    def get(self):
        self.render('login-form.html', hide = True)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/wiki')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')

class Unit3Welcome(BaseHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BaseHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')
class Flushcache(BaseHandler):
    def get(self):
        global CACHE
	CACHE.clear()
        self.redirect('/blog')
##################################################################


class Wikientry(db.Model):
    content = db.TextProperty(required = True)
    title = db.StringProperty(required = False)
    link = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now_add = True)
    creater = db.StringProperty(required = False)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    @classmethod
    def by_link(cls, link):
        u = db.GqlQuery("select * from Wikientry where link=:1 limit 1", link)
        return u
    @classmethod
    def by_id(cls, key_id):
        u = cls.get_by_id(int(key_id))
	return u
    @classmethod
    def add_entry(cls, content, link,creater,title):
        return Wikientry(content = content,link = link,creater = creater,title = title)
    @classmethod
    def edit(cls, link, content,creater,title):
        return Wikientry(link = link,
                    content = content,creater = creater,title = title)
    def by_creater(cls, creater):
        u = db.GqlQuery("select * from Wikientry where creater=:1", creater)
	return u
    @classmethod
    def toppage(cls,link):
	#u = db.GqlQuery("select * from Wikientry order by last_modified DESC GROUP BY link")
	u =  Wikientry.all()
	u.order("-last_modified");
	return u

def cache_wiki(key ="",update = False):
    global CACHE
    #not in cache
    if key =="wikifront" or update == True:
    	posts = Wikientry.toppage(key)
	CACHE["wikifront"] = posts
	return CACHE["wikifront"]
    if (update != False or key not in CACHE): # not in cache
        entry = Wikientry.by_link(key)
	#get entry
	my_entry = entry.fetch(1)
	logging.info(my_entry)
	if my_entry:# in database
	    logging.info(my_entry[0].content)
	    CACHE[key]= [my_entry[0].content,my_entry[0].creater,my_entry[0].title]
	    return CACHE[key]
        else: #new page
	    content = ""
	    CACHE[key]= [content,"",""]
	    return CACHE[key]
    else:#can't find
	logging.info('%s' %CACHE[key])
        return CACHE[key]

class WikiPage(BaseHandler):
    def get(self,post_id):
        page = cache_wiki(post_id,update=False)
	page_key=self.request.get('v');
	logging.info(page_key)
	if page_key and page_key.isdigit():
	    entry = Wikientry.by_id(page_key)
	    my_entry = entry
	    self.render('wiki-page.html',edit_link = (post_id+"?v=%s"%page_key),content = my_entry.content,creater=my_entry.creater)
	elif (page != ""):
	    logging.info(page)
	    if cache_wiki(post_id)[1]:
		creater = "admin"
	    else:
		creater = cache_wiki(post_id)[1]
	    self.render('wiki-page.html',edit_link = post_id,content = page[0],creater=creater)
        else:
	    if self.user:
	        self.redirect('/_edit%s'%post_id)
	    else:
	        self.redirect('/login')
class EditPage(BaseHandler):
    def get(self,post_id):
	logging.info(post_id)
	page_key=self.request.get('v');
	logging.info(page_key)
	if page_key and page_key.isdigit():
	    entry = Wikientry.by_id(page_key)
	    my_entry = entry
	    self.render('edit.html',edit_link = (post_id+"?v=%s"%page_key),content = my_entry.content,creater=my_entry.creater,title=my_entry.title)
	else:
	    content = cache_wiki(post_id)
            self.render('edit.html',edit_link = post_id,content = content[0],creater=content[1],title = content[2])
    def post(self,post_id):
        content = self.request.get('content')
	logging.info( "content is %s"%content)
	logging.info(post_id)
	title = self.request.get('title')
	if self.user:
	    logging.info(content+"-----------"+cache_wiki(post_id)[0])
	    if not title:
	    	logging.info(cache_content)
		self.render('edit.html',edit_link = post_id,content = content,creater = cache_wiki(post_id)[1],error = "please insert title")
	    cache_content = cache_wiki(post_id)[0]
	    cache_title = cache_wiki(post_id)[2]
	    if  content:
		if content != cache_content or title != cache_title : #edited
	    	    logging.info(post_id)
	            entry = Wikientry.add_entry(content = content,link = post_id,creater = self.user.name,title= title)
		    entry.put()
		    CACHE[post_id] = [content,self.user.name,title]
		    cache_wiki("wikifront",True)
		    self.redirect(post_id)
		else:
		    self.redirect(post_id)
	    else:
		self.render('edit.html',title = title,edit_link = post_id,content = content,creater = cache_wiki(post_id)[1],error = "please insert content")
	else:
	    self.redirect("/login")

class HistoryPage(BaseHandler):
    def get(self,post_id):
	logging.info(post_id)
        pages = Wikientry.all().filter("link =", post_id).order("-last_modified")
	if pages:
	    logging.info(pages)
	    self.render('history-page.html',edit_link = post_id,pages = pages)
	else:
	    self.redirect('/_edit'+post_id)

class Wikifront(BaseHandler):
    def get(self):
    	posts = cache_wiki("wikifront")
	logging.error(posts)
        self.render('wiki-front.html',hide = True,posts = posts)

class Portfolio(BaseHandler):
    def get(self):
        self.render('portfolio.html')
class Game(BaseHandler):
    def get(self):
        self.render('game.html')


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?(?:.json)?', BlogFront),
                               ('/blog/([0-9]+)(?:.json)?', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/?/signup', Register),
                               ('/login/?', Login),
                               ('/logout/?', Logout),
                               ('/portfolio/?', Portfolio),
                              ('/birdydashup/?', Game),
		   				  ('/_edit'+PAGE_RE, EditPage),
			       ('/_history'+PAGE_RE, HistoryPage),
                               ('/unit3/welcome', Unit3Welcome),
			       ('/blog/flush/?', Flushcache),
			       ('/wiki/?',Wikifront),
			       (PAGE_RE, WikiPage),
                               ],
                              debug=True)