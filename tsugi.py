
import re
import pymysql
import hashlib

# https://github.com/idan/oauthlib/blob/master/oauthlib/oauth1/rfc5849/endpoints/base.py
# https://github.com/idan/oauthlib/blob/master/oauthlib/oauth1/rfc5849/endpoints/signature_only.py
# from oauthlib.oauth1 import SignatureOnlyEndpoint
# import oauthlib.oauth1.rfc5849.signature as signature

import oauth as oauth
import trivialstore as trivialstore


TSUGI_CONNECTION = None
TSUGI_PREFIX = ''

''' 
TSUGI_DB_TO_ROW_FIELDS is the data structure that drives Tsugi's core operations

(1) extract_post - parsing post data to internal values
(2) load_all - retrieving data from the core tables
(3) adjust_data - make sure that post data is inserted / updated into DB

Each row works as follows:
- the first row is the name of the table (sans prefix)
- the second row is the primary key (if any) followed by the foreign keys (if any)
- The rest of the rows are
  [name in db, name in lti object (if different)]

Database columns that end in _key are the "logical key" for the row, but these are
run through sha256 and stored in the _sha256 columns which is marked in the
DB as the actual logical key for the row.  This approach is taken to allow
the _key values be text and unindexed and apply the index to the _sha256
column instead.

If you look at the other languages, there is a lot of cut/pasted/tweaked straight
line code with subtle changes in each version.   This is a table driven approach
that is more complex but less likely to have cut/paste errors.  Also I use lists
to maintain order and to make this easier to port to new languages.
'''

TSUGI_DB_TO_ROW_FIELDS = [
        ['lti_key',
            ['key_id'],
            'key_key',  # No sha256 because we don't insert key rows
            'secret' ,
            'new_secret',
            ['settings_url', 'key_settings_url'],
        ],
        ['lti_nonce',
            'nonce'  # No primary key - jsut a logical key
        ],
        ['lti_context',
            ['context_id', 'key_id'],
            'context_key',
            'context_sha256',
            ['title', 'context_title'],
            ['settings_url', 'context_settings_url'],
            'ext_memberships_id',
            'ext_memberships_url',
            'lineitems_url',
            'memberships_url'
        ],
        ['lti_link',
            ['link_id', 'context_id'],
            'link_key',
            'link_sha256',
            ['path', 'link_path'],
            ['title', 'link_title'],
            ['settings', 'link_settings'],
            ['settings_url', 'link_settings_url']
        ],
        ['lti_user',
            ['user_id', 'key_id'],
            'user_key' ,
            'user_sha256',
            ['subscribe', 'user_subscribe'],
            ['displayname', 'user_displayname'],
            ['email', 'user_email'],
            ['image', 'user_image'],
        ],
        ['lti_membership',
            ['membership_id', 'user_id', 'context_id'],
            'role',
            'role_override'   # Make sure to think this one through
        ],
        ['lti_result',
            ['result_id', 'link_id', 'user_id'],
            'grade',
            'result_url',
            'sourcedid'
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
            ['service_key', 'service']
        ]
    ]

# TODO: This needs to be pulled out somewhere
# This also needs to let connections go after
# a while - it is far too simple
def get_connection() :
    global TSUGI_CONNECTION
    if TSUGI_CONNECTION is not None : return TSUGI_CONNECTION

    TSUGI_CONNECTION = pymysql.connect(host='localhost',
                             user='ltiuser',
                             port=8889,
                             password='ltipassword',
                             db='tsugi',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)

    return TSUGI_CONNECTION

def web2py(request, response, session):

    for tc in range(len(TSUGI_DB_TO_ROW_FIELDS)) :
        table = TSUGI_DB_TO_ROW_FIELDS[tc]
        for fc in range(len(table)) :
            if fc == 0 : continue;  # skip table name
            if type(table[fc]) == type([]) : continue
            field = table[fc]
            TSUGI_DB_TO_ROW_FIELDS[tc][fc] = [field,field]

    print TSUGI_DB_TO_ROW_FIELDS
    my_post = extract_post(request.post_vars)
    print "Extracted POST", my_post
    row = load_all(my_post)
    print "Loaded Row", row
    key = row['key_key']
    secret = row['secret']

    url = '%s://%s%s' % (request.env.wsgi_url_scheme, request.env.http_host,
               request.env.request_uri)

    print "Key, Secret, URL", key,secret, url

    oauth_request = oauth.OAuthRequest.from_request('POST', url, None, request.post_vars)
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
        response.headers['X-Tsugi-Error-Detail'] = oae.mymessage
        return

    print '----- Success ----'
    print verify

    actions = adjust_data(row, my_post)
    print "Adjusted", actions

def extract_post(post) :
    fixed = dict()
    for (k,v) in post.items():
        if k.startswith('custom_') :
            nk = k[7:]
            if v.startswith('$') :
                sv = v[1:].lower().replace('.','_')
                if sv == nk : continue
            if nk not in fixed : fixed[nk] = v
        fixed[k] = v

    #print(fixed)
    ret = dict()

    ret['key'] = fixed.get('oauth_consumer_key', None)
    ret['nonce'] = fixed.get('oauth_nonce', None)

    link_key = fixed.get('resource_link_id', None)
    link_key = fixed.get('custom_resource_link_id', link_key)
    ret['link_key'] = link_key

    user_key = fixed.get('person_sourcedid', None)
    user_key = fixed.get('user_id', user_key)
    user_key = fixed.get('custom_user_id', user_key)
    ret['user_key'] = user_key

    context_key = fixed.get('courseoffering_sourcedid', None)
    context_key = fixed.get('context_id', context_key)
    context_key = fixed.get('custom_context_id', context_key)
    ret['context_key'] = context_key

    # LTI 1.x settings and Outcomes
    ret['service'] = fixed.get('lis_outcome_service_url', None)
    ret['sourcedid'] = fixed.get('lis_result_sourcedid', None)

    # LTI 2.x settings and Outcomes
    ret['result_url'] = fixed.get('custom_result_url', None)
    ret['link_settings_url'] = fixed.get('custom_link_settings_url', None)
    ret['context_settings_url'] = fixed.get('custom_context_settings_url', None)

    # LTI 2.x Services
    ret['ext_memberships_id'] = fixed.get('ext_memberships_id', None)
    ret['ext_memberships_url'] = fixed.get('ext_memberships_url', None)
    ret['lineitems_url'] = fixed.get('lineitems_url', None)
    ret['memberships_url'] = fixed.get('memberships_url', None)

    ret['context_title'] = fixed.get('context_title', None)
    ret['link_title'] = fixed.get('resource_link_title', None)

    # Getting email from LTI 1.x and LTI 2.x
    ret['user_email'] = fixed.get('lis_person_contact_email_primary', None)
    ret['user_email'] = fixed.get('custom_person_email_primary', ret['user_email'])

    # Displayname from LTI 2.x
    if ( fixed.get('custom_person_name_full') ) :
        ret['user_displayname'] = fixed['custom_person_name_full']
    elif ( fixed.get('custom_person_name_given') and fixed.get('custom_person_name_family') ) :
        ret['user_displayname'] = fixed['custom_person_name_given']+' '+fixed['custom_person_name_family']
    elif ( fixed.get('custom_person_name_given') ) :
        ret['user_displayname'] = fixed['custom_person_name_given']
    elif ( fixed.get('custom_person_name_family') ) :
        ret['user_displayname'] = fixed['custom_person_name_family']

    # Displayname from LTI 1.x
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

def load_all(post_data) :
    global TSUGI_DB_TO_ROW_FIELDS

    sql = 'SELECT '
    first = True
    for table in TSUGI_DB_TO_ROW_FIELDS :
        alias = None
        table_name = table[0]
        if not first :
            sql += ', '
        first = False
        alias = table[1][0][:1]
        sql += alias + '.' + table[1][0]
        for field in table[2:]:
            if type(field) == type([]) :
                row_name = field[1]
                field = field[0]
            else :
                row_name = None
            sql += ', ' + alias + '.' + field
            if row_name is not None:
                sql += ' AS ' + row_name
        sql += '\n  '

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
    if 'service' in post_data :
        service = hashlib.sha256(post_data['service']).hexdigest()

    parms = {
        'key': hashlib.sha256(post_data['key']).hexdigest(),
        'nonce': post_data['nonce'][:128],
        'context': hashlib.sha256(post_data['context_key']).hexdigest(),
        'link': hashlib.sha256(post_data['link_key']).hexdigest(),
        'user': hashlib.sha256(post_data['user_key']).hexdigest(),
        'service': service
    }

    # print parms

    connection = get_connection()
    with connection.cursor() as cursor:
        # Read a single record
        cursor.execute(sql, parms)
        result = cursor.fetchone()

    return result

def adjust_sql(sql) :
    global TSUGI_PREFIX
    sql = re.sub(r':([a-z0-9_]+)',r'%(\1)s',sql)
    return sql.replace('{$p}', TSUGI_PREFIX)

def lti_sha256(value) :
    if value is None : return value
    return hashlib.sha256(value).hexdigest()

def do_insert(core_object, row, post, actions) :
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
    if row.get(id_column) is not None : return

    # We need a logical key and do not have one...
    if external and post.get(key_column) is None:
        if core_object != 'service' :
            print "Unable to find logical key for",core_object,key_column
        return

    connection = get_connection()

    columns = '( created_at, updated_at'
    subs = '( NOW(), NOW()'
    parms = {}

    # [0] is table_name, [1] is primary key and foreign keys
    # Add FK's
    for fk in table[1][1:] :
        columns += ', '+fk
        subs += ', :'+fk
        if row.get(fk) is None :
            print 'Cannot insert', core_object,'without FK', fk
            return
        parms[fk] = row[fk]

    # Add data
    for field in table[2:] :
        columns += ', '+field[0]
        subs += ', :'+field[0]
        if field[0] == sha_column :
            parms[field[0]] = lti_sha256(post[key_column])
        else :
            parms[field[0]] = post.get(field[1])

    sql = adjust_sql("INSERT INTO {$p}"+table_name+ "\n" +
        columns + " )\n" + "VALUES\n" + subs + " )\n")

    print sql
    print parms

    with connection.cursor() as cursor:
        # Read a single record
        cursor.execute(sql, parms)
        row[id_column] = cursor.lastrowid
        # [0] is table_name, [1] is primary key
        for field in table[2:] :
            if field[0] == sha_column :
                row[field[1]] = lti_sha256(post[key_column])
            else :
                row[field[1]] = post.get(field[1])
        actions.append("=== Inserted "+core_object+" id="+str(row[id_column]))
        connection.commit()

def do_update(core_object, row, post, actions) :
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
    if row.get(id_column) is None : return

    connection = get_connection()

    # Add data
    for field in table[2:] :
        if '_sha256' in field[0] : continue   # Don't update logical key
        # print "Check",field[1],row[field[1]],post.get(field[1])
        if row[field[1]] == post.get(field[1]) : continue
        sql = adjust_sql('UPDATE {$p}'+table_name+ ' SET '+field[0]+'=:value WHERE '+id_column+' = :id')

        parms = {'value': post.get(field[1]), 'id': row.get(id_column)}

        # print sql
        # print parms

        with connection.cursor() as cursor:
            # Read a single record
            cursor.execute(sql, parms)
            row[field[1]] = post.get(field[1])
            actions.append("=== Updated "+core_object+" "+field[1]+"="+post.get(field[1])+" id="+str(row[id_column]))
            connection.commit()


# The payoff for table driven code - take a look at 
# https://github.com/tsugiproject/tsugi-php/blob/master/src/Core/LTIX.php#L753
# for the PHP version of adjustData() :)
def adjust_data(row, post) :
    global TSUGI_DB_TO_ROW_FIELDS

    connection = get_connection()
    actions = list()

    core_lti = ['context', 'user', 'link', 'membership', 'result', 'service']

    for core in core_lti:
        do_insert(core, row, post, actions)

    for core in core_lti:
        do_update(core, row, post, actions)

    return actions

