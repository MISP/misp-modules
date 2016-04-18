import redis

port = 6379
hostname = '127.0.0.1'

def selftest(enable=True):
    if not enable:
        return False
    r = redis.StrictRedis(host='localhost', port=port)
    try:
        r.set('test','selftest')
    except:
        return 'Redis not running or not installed. Helper will be disabled.'
