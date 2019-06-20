import json
import psycopg2

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', 'ip-src', 'ip-dst', 'AS'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'L. Aaron Kaplan <kaplan@cert.at>', 'description': 'Module to access intelmqs eventdb', 'module-type': ['expansion', 'hover']}
moduleconfig = ['username', 'password', 'hostname', 'database']


def connect(user, password, host, dbname):
    try:
        conn = psycopg2.connect(database=dbname,  user=user,  host=host,  password=password)
    except Exception as e:
        print("I am unable to connect to the database: %s" %e)
    return conn


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    #if request.get('hostname'):
    #    toquery = request['hostname']
    #elif request.get('domain'):
    #    toquery = request['domain']
    if request.get('ip-src'):
        toquery = request['ip-src']
    #elif request.get('ip-dst'):
    #    toquery = request['ip-dst']
    #elif request.get('AS'):
    #    toquery = request['AS']
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    if (request.get('config')):
        if (request['config'].get('username') is None) or (request['config'].get('password') is None):
            misperrors['error'] = 'intelmq eventdb authentication is missing'
            return misperrors

    conn = connect(request['config']['username'], request['config']['password'], request['config']['hostname'], request['config']['database'])
    cur = conn.cursor()
    SQL1 = 'SELECT COUNT(*) from events where "source.ip" = \'%s\'' %(toquery)
    try:
        cur.execute(SQL1)
    except Exception as e:
        misperrors['error'] = 'can not query database'
        print(e)
        return misperrors

    results = cur.fetchone()

    out = ''
    out = out + "{} ".format(results[0]) + " results found in the DB"

    r = {'results': [{'types': mispattributes['output'], 'values': out}]}
    conn.close()
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
