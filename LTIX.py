
# import pymysql
import urllib
import trivialstore as trivialstore
from LTIX_classes import *

# Hey Leah Culver, 2007 called and thanked you for your OAuth code
import oauth as oauth

def web2py(request, response, db, session):

    print "POST Vars"
    print request.post_vars

    launch = TsugiLaunch('TBD')
    # launch._adapter = db._adapter

    if 'lti_message_type' in request.post_vars and 'oauth_nonce' in request.post_vars :
        pass
    else :
        if '_TSUGI_ROW' in session : 
            launch.load(session['_TSUGI_ROW'])
            launch.success = True
            return launch
        return launch

    my_post = extract_post(request.post_vars)
    print "Extracted POST", my_post
    try:
        ltirow = load_all(launch, my_post)
    finally:
        launch.close_connection()

    print "Loaded Row", ltirow
    key = ltirow['key_key']
    secret = ltirow['secret']

    url = '%s://%s%s' % (request.env.wsgi_url_scheme, request.env.http_host,
               request.env.request_uri)

    print "Key, Secret, URL", key,secret, url

    # Check secret...
    verify_signature(request.post_vars, url, key, secret, launch)
    if launch.message : 
        response.headers['X-Tsugi-Error-Detail'] = launch.detail
        return launch

    print "Signature verified"
    try:
        actions = adjust_data(launch, ltirow, my_post)
    finally:
        launch.close_connection()

    print "Adjusted", actions

    launch.load(ltirow)
    launch.valid = True
    session['_TSUGI_ROW'] = ltirow
    launch.close_connection()
    return launch

def verify_signature(post, url, key, secret, launch) :
    oauth_request = oauth.OAuthRequest.from_request('POST', url, None, post)
    ts = trivialstore.TrivialDataStore()
    trivialstore.secret = secret
    server = oauth.OAuthServer(ts)
    server.add_signature_method(oauth.OAuthSignatureMethod_HMAC_SHA1())
    consumer = oauth.OAuthConsumer(key,secret)
    try:
        verify = server._check_signature(oauth_request, consumer, None)
    except oauth.OAuthError as oae:
        print "OAuth Failed"
        print oae.mymessage
        retval = oae.mymessage
        launch.detail = retval
        launch.message = retval
        pos = retval.find(' Expected signature base string: ')
        if pos > 0 : launch.message = retval[:pos]

        url = post.get('launch_presentation_return_url')
        if url is not None:
            parms = { 'lti_errorlog' : launch.detail,
                'lti_errormsg' : launch.message }
            if '?' in url : url += '&'
            else : url += '?'
            url += urllib.urlencode(parms)
            print url
            launch.redirecturl = url

def extract_post(post) :
    '''Map the POST data into our internal ltirow format where all the
    data has unique keys.'''

    # Remove "custom_" from the beginning of fields
    fixed = dict()
    for (k,v) in post.items():
        if k.startswith('custom_') :
            nk = k[7:]
            if v.startswith('$') :
                sv = v[1:].lower().replace('.','_')
                if sv == nk : continue
            if nk not in fixed : fixed[nk] = v
        fixed[k] = v

    # print "Fixed", fixed
    ret = dict()

    for table in TSUGI_DB_TO_ROW_FIELDS :
        # First row is table name, second row is key PK + FK's
        # [name in db, name in lti object (if different), name(s) from the post data]
        for column in table[2:] :
            if len(column) < 3 : continue
            if column[0].endswith('_sh256') : continue
            if column[1] in ret : continue
            if type(column[2]) == type([]) :
                post_fields = column[2]
            else:
                post_fields = [column[2]]
            for post_field in post_fields:
                if post_field in fixed :
                    ret[column[1]] = fixed[post_field]

    # Fields not represented in the table
    ret['nonce'] = fixed.get('oauth_nonce', None)

    # Dispayname business logic from LTI 2.x
    if ( 'user_displayname' in ret ) :
        pass
    elif ( fixed.get('custom_person_name_given') and fixed.get('custom_person_name_family') ) :
        ret['user_displayname'] = fixed['custom_person_name_given']+' '+fixed['custom_person_name_family']
    elif ( fixed.get('custom_person_name_given') ) :
        ret['user_displayname'] = fixed['custom_person_name_given']
    elif ( fixed.get('custom_person_name_family') ) :
        ret['user_displayname'] = fixed['custom_person_name_family']

    # Displayname busuness logic from LTI 1.x
    elif ( fixed.get('lis_person_name_full') ) :
        ret['user_displayname'] = fixed['lis_person_name_full']
    elif ( fixed.get('lis_person_name_given') and fixed.get('lis_person_name_family') ) :
        ret['user_displayname'] = fixed['lis_person_name_given']+' '+fixed['lis_person_name_family']
    elif ( fixed.get('lis_person_name_given') ) :
        ret['user_displayname'] = fixed['lis_person_name_given']
    elif ( fixed.get('lis_person_name_family') ) :
        ret['user_displayname'] = fixed['lis_person_name_family']

    # Trim out repeated spaces and/or weird whitespace from the user_displayname
    if ( ret.get('user_displayname') ) :
        ret['user_displayname'] = re.sub( '\s+', ' ', ret.get('user_displayname') ).strip()

    # Get the role
    ret['role'] = 0
    roles = ''
    if ( fixed.get('custom_membership_role') ) : # From LTI 2.x
        roles = fixed['custom_membership_role']
    elif ( fixed.get('roles') ) : # From LTI 1.x
        roles = fixed['roles']

    if ( len(roles) > 0 ) :
        roles = roles.lower()
        if ( roles.find('instructor') >=0 ) : ret['role'] = 1000
        if ( roles.find('administrator') >=0 ) : ret['role'] = 5000

    return ret


def load_all(launch, post_data) :
    '''Do a series of LEFT JOINs across all the tables to extract whatever
    data we have for the incoming POST request.'''
    global TSUGI_DB_TO_ROW_FIELDS

    sql = 'SELECT nonce,\n        '
    first = True
    # First row is table name, second row is key PK + FK's
    # [name in db, name in lti object (if different), name(s) from the post data]
    for table in TSUGI_DB_TO_ROW_FIELDS :
        alias = None
        table_name = table[0]
        if not first :
            sql += ',\n        '
        first = False
        alias = table[1][0][:1]
        sql += alias + '.' + table[1][0]
        count = 0
        for field in table[2:]:
            if type(field) == type([]) :
                row_name = field[1]
                field = field[0]
            else :
                row_name = None

            # Nice spacing
            count = count + 1
            if count >= 3 :
                sql += ',\n        '
                count = 0
            else :
                sql += ', '

            sql += alias + '.' + field
            if row_name is not None:
                sql += ' AS ' + row_name

    # Add the JOINs
    prefix = ''
    sql += """\nFROM {$p}lti_key AS k
        LEFT JOIN {$p}lti_nonce AS n ON k.key_id = n.key_id AND n.nonce = %(nonce)s
        LEFT JOIN {$p}lti_context AS c ON k.key_id = c.key_id AND c.context_sha256 = %(context)s
        LEFT JOIN {$p}lti_link AS l ON c.context_id = l.context_id AND l.link_sha256 = %(link)s
        LEFT JOIN {$p}lti_user AS u ON k.key_id = u.key_id AND u.user_sha256 = %(user)s
        LEFT JOIN {$p}lti_membership AS m ON u.user_id = m.user_id AND c.context_id = m.context_id
        LEFT JOIN {$p}lti_result AS r ON u.user_id = r.user_id AND l.link_id = r.link_id
        LEFT JOIN {$p}profile AS p ON u.profile_id = p.profile_id
        LEFT JOIN {$p}lti_service AS s ON k.key_id = s.key_id AND s.service_sha256 = %(service)s
        """.replace('{$p}',prefix)

    # Add support for soft delete
    sql += """\nWHERE k.key_sha256 = %(key)s
        AND (k.deleted IS NULL OR k.deleted = 0)
        AND (c.deleted IS NULL OR c.deleted = 0)
        AND (l.deleted IS NULL OR l.deleted = 0)
        AND (u.deleted IS NULL OR u.deleted = 0)
        AND (m.deleted IS NULL OR m.deleted = 0)
        AND (r.deleted IS NULL OR r.deleted = 0)
        AND (p.deleted IS NULL OR p.deleted = 0)
        AND (s.deleted IS NULL OR s.deleted = 0)
        """

    # There should only be 1 :)
    sql += "\nLIMIT 1"

    # print sql

    # The parameters
    service = None
    if 'service_key' in post_data and post_data['service_key'] is not None:
        service = hashlib.sha256(post_data['service_key']).hexdigest()

    parms = {
        'key': hashlib.sha256(post_data['key_key']).hexdigest(),
        'nonce': post_data['nonce'][:128],
        'context': hashlib.sha256(post_data['context_key']).hexdigest(),
        'link': hashlib.sha256(post_data['link_key']).hexdigest(),
        'user': hashlib.sha256(post_data['user_key']).hexdigest(),
        'service': service
    }

    # print parms

    result = launch.sql_execute(sql, parms)
    return result

def do_insert(launch, core_object, ltirow, post, actions) :
    '''Look through the post data and check if there is new data
    not yet in the database, and if there is new data insert it
    and update the ltirow object.'''

    global TSUGI_DB_TO_ROW_FIELDS
    table_name = 'lti_'+core_object
    id_column = core_object+'_id'
    key_column = core_object+'_key'
    sha_column = core_object+'_sha256'

    table = None
    for check in TSUGI_DB_TO_ROW_FIELDS:
        if table_name == check[0] :
            table = check
            break

    if table is None :
        print "ERROR: Could not find table", table_name
        return

    if table[1][0] != id_column :
        print "Expecting ",id_column,"as key for", table_name, "found", table[1]
        return

    # Check if this is an externally indexed table
    external = False
    for column in table:
        if column[0].endswith('_sha256') : external = True

    # We already have a primary key - all good
    if ltirow.get(id_column) is not None : return

    # We need a logical key and do not have one...
    if external and post.get(key_column) is None:
        if core_object != 'service' :
            print "Unable to find logical key for",core_object,key_column
        return

    columns = '( created_at, updated_at'
    subs = '( NOW(), NOW()'
    parms = {}

    # First row is table name, second row is key PK + FK's
    # [name in db, name in lti object (if different), name(s) from the post data]

    # Add FK's
    for fk in table[1][1:] :
        columns += ', '+fk
        subs += ', :'+fk
        if ltirow.get(fk) is None :
            print 'Cannot insert', core_object,'without FK', fk
            return
        parms[fk] = ltirow[fk]

    # Add data
    for field in table[2:] :
        columns += ', '+field[0]
        subs += ', :'+field[0]
        if field[0] == sha_column :
            parms[field[0]] = launch.lti_sha256(post[key_column])
        else :
            parms[field[0]] = post.get(field[1])

    sql = launch.adjust_sql("INSERT INTO {$p}"+table_name+ "\n" +
        columns + " )\n" + "VALUES\n" + subs + " )\n")

    print sql
    print parms

    ltirow[id_column] = launch.sql_insert(sql, parms)

    # [0] is table_name, [1] is primary key
    for field in table[2:] :
        if field[0] == sha_column :
            ltirow[field[1]] = launch.lti_sha256(post[key_column])
        else :
            ltirow[field[1]] = post.get(field[1])
        actions.append("=== Inserted "+core_object+" id="+str(ltirow[id_column]))

def do_update(launch, core_object, ltirow, post, actions) :
    '''Look at the post data, and if there is a mismatch between
    ltirow (the data from the database) and the post data, update the
    database and the ltirow data.'''

    global TSUGI_DB_TO_ROW_FIELDS
    table_name = 'lti_'+core_object
    id_column = core_object+'_id'

    table = None
    for check in TSUGI_DB_TO_ROW_FIELDS:
        if table_name == check[0] :
            table = check
            break

    if table is None :
        print "ERROR: Could not find table", table_name
        return

    if table[1][0] != id_column :
        print "Expecting ",id_column,"as key for", table_name, "found", table[1]
        return

    # We should already have a primary key
    if ltirow.get(id_column) is None : return

    connection = launch.get_connection()

    # Update mismatched data
    for field in table[2:] :
        if '_sha256' in field[0] : continue   # Don't update logical key
        if post.get(field[1]) is None : continue
        if ltirow[field[1]] == post.get(field[1]) : continue
        sql = launch.adjust_sql('UPDATE {$p}'+table_name+ ' SET '+field[0]+'=:value WHERE '+id_column+' = :id')

        parms = {'value': post.get(field[1]), 'id': ltirow.get(id_column)}

        # print sql
        # print parms

        launch.sql_update(sql, parms)

        ltirow[field[1]] = post.get(field[1])
        actions.append("=== Updated "+core_object+" "+field[1]+"="+str(post.get(field[1]))+" id="+str(ltirow[id_column]))

# The payoff for table driven code - take a look at
# https://github.com/tsugiproject/tsugi-php/blob/master/src/Core/LTIX.php#L753
# for the PHP version of adjustData() :)
def adjust_data(launch, ltirow, post) :
    '''Make sure that any data from the post is inserted / updated
    in the database and also copied to the "ltirow".  If new records are
    inserted, their PK's are placed in ltirow as well.
    '''

    global TSUGI_DB_TO_ROW_FIELDS

    connection = launch.get_connection()
    actions = list()

    # Note - Never do this for key - dangerous!
    core_lti = ['context', 'user', 'link', 'membership', 'service', 'result']

    for core in core_lti:
        do_insert(launch, core, ltirow, post, actions)

    for core in core_lti:
        do_update(launch, core, ltirow, post, actions)

    return actions

'''
TSUGI_DB_TO_ROW_FIELDS is the data structure that drives Tsugi's core operations

(1) extract_post - parsing post data to internal values
(2) load_all - retrieving data from the core tables
(3) adjust_data - make sure that post data is inserted / updated into DB

Each row works as follows:
- the first row is the name of the table (sans prefix)
- the second row is the primary key (if any) followed by the foreign keys (if any)
- The rest of the rows are
  [name in db, name in lti object (if different), name(s) from the post data]

Database columns that end in _key are the "logical key" for the row, but these are
run through sha256 and stored in the _sha256 columns which is marked in the
DB as the actual logical key for the row.  This approach is taken to allow
the _key values be text and unindexed and apply the index to the _sha256
column instead.

Also, there is no need to add 'custom_' to the post data names, this is
automatically handled in extract_post()

If you look at the other languages, there is a lot of cut/pasted/tweaked straight
line code with subtle changes in each version.   This is a table driven approach
that is more complex but less likely to have cut/paste errors.  Also I use lists
to maintain order and to make this easier to port to new languages.
'''

TSUGI_DB_TO_ROW_FIELDS = [
        ['lti_key', # No sha256 because we don't insert key rows
            ['key_id'],
            ['key_key','key_key','oauth_consumer_key'],
            'secret' ,
            'new_secret',
            ['settings_url', 'key_settings_url'],
        ],
        ['lti_context',
            ['context_id', 'key_id'],
            ['context_key', 'context_key', ['context_id', 'courseoffering_sourcedid']],
            'context_sha256',
            ['title', 'context_title', 'context_title'],
            ['settings', 'context_settings', None],  # Don't take from Post
            ['settings_url', 'context_settings_url'],
            'ext_memberships_id',   # LTI 1.x Extension
            'ext_memberships_url',  # LTI 1.x Extension
            'lineitems_url',        # LTI 2.x Custom
            'memberships_url'       # LTI 2.x Custom
        ],
        ['lti_link',
            ['link_id', 'context_id'],
            ['link_key','link_key', 'resource_link_id'],
            'link_sha256',
            ['path', 'link_path'],
            ['title', 'link_title', 'resource_link_title'],
            ['settings', 'link_settings', None],  # Don't take from Post
            ['settings_url', 'link_settings_url']
        ],
        ['lti_user',
            ['user_id', 'key_id'],
            ['user_key', 'user_key', ['user_id', 'person_sourcedid']],
            'user_sha256',
            ['subscribe', 'user_subscribe'],
            ['displayname', 'user_displayname', ['lis_person_name_full', 'person_name_full'] ],
            ['email', 'user_email', ['lis_person_contact_email_primary', 'person_email_primary'] ],
            ['image', 'user_image'],
        ],
        ['lti_membership',
            ['membership_id', 'user_id', 'context_id'],
            'role',
            'role_override'   # Make sure to think this one through
        ],
        ['lti_result',
            ['result_id', 'link_id', 'user_id', 'service_id'],
            'grade',
            'result_url',
            ['sourcedid', 'sourcedid', 'lis_result_sourcedid'],
        ],
        ['profile',
            ['profile_id', 'key_id'],
            ['displayname', 'profile_displayname'],
            ['email', 'profile_email'],
            ['subscribe', 'profile_subscribe']
        ],
        ['lti_service',
            ['service_id' , 'key_id'],
            'service_sha256',
            ['service_key', 'service_key', 'lis_outcome_service_url']
        ]
    ]

def patch_table() :
    """Patch the table of core variables

    Go through the table and insure that all of the row fields are three
    element lists for [db field, row object field, post field]

    The format of the file is:
        [table name,
        [PK, FK, FK],
        [name in db, name in lti object (if different), name(s) from the post data],
        ...

    We ignore rows 0, and 1, and then for the rest of the rows, if there
    is one field, it is duplicated to fields 1 and 2.  If there are two
    fields, the second is duplicated ot the third.
    """
    global TSUGI_DB_TO_ROW_FIELDS
    for tc in range(len(TSUGI_DB_TO_ROW_FIELDS)) :
        table = TSUGI_DB_TO_ROW_FIELDS[tc]
        for fc in range(len(table)) :
            if fc == 0 : continue;  # skip table name
            if fc == 1 : continue;  # skip PK/FK row
            if type(table[fc]) == type([]) and len(table[fc]) == 3 : continue

            # When there are two fields, duplicate the second as last
            if type(table[fc]) == type([]) and len(table[fc]) == 2 :
                TSUGI_DB_TO_ROW_FIELDS[tc][fc].append(table[fc][1])
                continue

            # When there is one field, use it as second and third
            field = table[fc]
            TSUGI_DB_TO_ROW_FIELDS[tc][fc] = [field,field,field]


# Actually patch the table.
patch_table()
