

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

    def __init__(self, CFG) :
        self.CFG = CFG

    def load(self, ltirow) : 
        self.ltirow = dict(ltirow) # copy 
        self.key = TsugiKey(self)
        self.context = TsugiContext(self)
        self.user = TsugiUser(self)
        self.link = TsugiLink(self)
        self.service = TsugiService(self)
        self.result = TsugiResult(self, self.service)

class TsugiKey() :
    def __init__(self, launch) :
        self.launch = launch      # reference
        self.id = launch.ltirow['key_id']
        # self.title = launch.ltirow['key_title']
        # self.settings = launch.ltirow['key_settings']

class TsugiContext() :
    def __init__(self, launch) :
        self.launch = launch      # reference
        self.id = launch.ltirow['context_id']
        self.title = launch.ltirow['context_title']
        self.settings = launch.ltirow['context_settings']

class TsugiUser() :
    def __init__(self, launch) :
        self.launch = launch      # reference
        self.id = launch.ltirow['user_id']
        self.displayname = launch.ltirow['user_displayname']
        self.email = launch.ltirow['user_email']
        self.image = launch.ltirow['user_image']
        self.role = int(launch.ltirow['role'])

    def instructor(self) : return self.role >= 1000
    def tenantAdmin(self) : return self.role >= 5000
    def rootAdmin(self) : return self.role >= 10000

class TsugiLink() :
    def __init__(self, launch) :
        self.launch = launch      # reference
        self.id = launch.ltirow['link_id']
        self.title = launch.ltirow['link_title']
        self.path = launch.ltirow['link_path']
        self.settings = launch.ltirow['link_settings']
        self.settings_url = launch.ltirow['link_settings_url']

class TsugiService() :
    def __init__(self, launch) :
        self.launch = launch      # reference
        self.id = launch.ltirow['link_id']
        self.url = launch.ltirow['service_key']

class TsugiResult() :
    def __init__(self, launch, service) :
        self.launch = launch      # reference
        self.id = launch.ltirow['link_id']
        self.service = service
        self.sourcedid = launch.ltirow['sourcedid']
        self.url = launch.ltirow['result_url']

