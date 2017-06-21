import re
import pymysql
import hashlib
from outcome_request import *

TSUGI_PREFIX = ''

# TODO: Need a configuration mechanism

# TODO: Connections stuff needs to be pulled out somewhere
# This also needs to let connections go after
# a while - it is far too simple

class TsugiLaunch():
    """Holds the launch data for a Tsugi Launch
    """
    user = None
    context = None
    link = None
    result = None
    service = None
    connection = None
    complete = False
    valid = False
    message = None
    detail = None
    redirecturl = None
    ltirow = None
    TSUGI_CONNECTION = None

    def __init__(self, CFG) :
        self.CFG = CFG
        emptyrow = dict()
        self.load(emptyrow)

    def load(self, ltirow) : 
        self.ltirow = dict(ltirow) # copy 
        self.key = TsugiKey(self)
        self.context = TsugiContext(self)
        self.user = TsugiUser(self)
        self.link = TsugiLink(self)
        self.service = TsugiService(self)
        self.result = TsugiResult(self, self.service)

    def get_connection(self) :
        if self.TSUGI_CONNECTION is not None : return self.TSUGI_CONNECTION

        self.TSUGI_CONNECTION = pymysql.connect(host='localhost',
                             user='ltiuser',
                             port=8889,
                             password='ltipassword',
                             db='tsugi',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)

        # print "Opening connection..."
        return self.TSUGI_CONNECTION

    def close_connection(self) :
        if self.TSUGI_CONNECTION is None : return
        # print "Closing connection..."
        self.TSUGI_CONNECTION.close()
        self.TSUGI_CONNECTION = None

    def adjust_sql(self, sql) :
        '''Let us use the PDO style substitution variables as well
        as solve the table prefix.'''

        global TSUGI_PREFIX
        sql = re.sub(r':([a-z0-9_]+)',r'%(\1)s',sql)
        return sql.replace('{$p}', TSUGI_PREFIX)

    def lti_sha256(self, value) :
        if value is None : return value
        return hashlib.sha256(value).hexdigest()

class TsugiKey() :
    def __init__(self, launch) :
        self.launch = launch      # reference
        self.id = launch.ltirow.get('key_id')
        # self.title = launch.ltirow.get('key_title')
        # self.settings = launch.ltirow.get('key_settings')

class TsugiContext() :
    def __init__(self, launch) :
        self.launch = launch      # reference
        self.id = launch.ltirow.get('context_id')
        self.title = launch.ltirow.get('context_title')
        self.settings = launch.ltirow.get('context_settings')

class TsugiUser() :
    def __init__(self, launch) :
        self.launch = launch      # reference
        self.id = launch.ltirow.get('user_id')
        self.displayname = launch.ltirow.get('user_displayname')
        self.email = launch.ltirow.get('user_email')
        self.image = launch.ltirow.get('user_image')
        self.role = int(launch.ltirow.get('role',0))

    def instructor(self) : return self.role >= 1000
    def tenantAdmin(self) : return self.role >= 5000
    def rootAdmin(self) : return self.role >= 10000

class TsugiLink() :
    def __init__(self, launch) :
        self.launch = launch      # reference
        self.id = launch.ltirow.get('link_id')
        self.title = launch.ltirow.get('link_title')
        self.path = launch.ltirow.get('link_path')
        self.settings = launch.ltirow.get('link_settings')
        self.settings_url = launch.ltirow.get('link_settings_url')

class TsugiService() :
    def __init__(self, launch) :
        self.launch = launch      # reference
        self.id = launch.ltirow.get('link_id')
        self.url = launch.ltirow.get('service_key')

class TsugiResult() :
    def __init__(self, launch, service) :
        self.launch = launch      # reference
        self.id = launch.ltirow.get('link_id')
        self.service = service
        self.sourcedid = launch.ltirow.get('sourcedid')
        self.url = launch.ltirow.get('result_url')

    def setGrade(self,grade,comment) :
        print 'setGrade', grade, comment
        print 'Source', self.sourcedid, self.service.url
        print 'secret,key',self.launch.ltirow.get('secret'),self.launch.ltirow.get('key_key')

        # outcome = ims_lti_py.OutcomeRequest( { 'score': grade,
        # outcome = dce_lti_py.OutcomeRequest( { 'score': grade,
        outcome = OutcomeRequest( { 'score': grade,
            'lis_outcome_service_url': self.service.url,
            'lis_result_sourcedid': self.sourcedid,
            'consumer_key': self.launch.ltirow.get('key_key'),
            'consumer_secret': self.launch.ltirow.get('secret')
        })

        # outcome.post_replace_result(grade, {'text': comment})
        outcome.post_replace_result(grade)
        print "Grade sent..."


