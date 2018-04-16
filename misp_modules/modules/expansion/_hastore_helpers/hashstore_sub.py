#!/usr/bin/env python3
# -*- coding: utf-8 -*
import zmq, json, time, hashlib
import redis #redis-cli INFO | grep ^db

# you need to execute this script to update your hashstore database from each add/edit/delet attributes
# You can add this to /var/www/MISP/tools/misp_zmq

# zmq configuration from misp configuration
zmq_host = "127.0.0.1"
zmq_port = "50000"
zmq_protocol = "tcp"

# redis configuration where is store your hashstore
redis_conf = {
    'host': '127.0.0.1',
    'port': 6379,
    'db': 7,
}


context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect("{}://{}:{}".format(zmq_protocol, zmq_host, zmq_port))
socket.setsockopt(zmq.SUBSCRIBE, b'')

poller = zmq.Poller()
poller.register(socket, zmq.POLLIN)

hashStore = redis.Redis(**redis_conf)

while True:
    socks = dict(poller.poll(timeout=None))
    if socket in socks and socks[socket] == zmq.POLLIN:
        message = socket.recv()
        topic, s, m = message.decode('utf-8').partition(" ")
        jsonevent = json.loads(m)
        jsonattr = None
        
       
               
        if 'Attribute' in jsonevent:

            jsonattr = jsonevent['Attribute']
            value = jsonattr["value"].encode('utf-8')
            hash_object = hashlib.sha256(value).hexdigest()
            if 'action' in jsonevent:
                # print(jsonevent['action'])
                if 'delete' in jsonevent['action']:
                    hashStore.srem(hash_object, jsonattr["uuid"])
                elif 'add' in jsonevent['action']:
                    hashStore.sadd(hash_object, jsonattr["uuid"])
                else:
                    # Edit case 
                    # add new value and remove the last
                    hashStore.sadd(hash_object, jsonattr["uuid"])
                    # remove old value
                    if jsonevent.get('attribute_diff'):
                        if jsonevent['attribute_diff'].get('value'):
                            old_value = jsonevent['attribute_diff']['value'].encode('utf-8')
                            
                            old_hash_object = hashlib.sha256(old_value).hexdigest()
                            hashStore.srem(old_hash_object, jsonattr["uuid"])
                            
                            # print(old_value)
                            # print(hashStore.smembers(old_hash_object))
                            # if the last member is deleted, the set is deleted
                            # and exist return False
                            # print(hashStore.exists(old_hash_object))

            # print(value)
            # print(hashStore.smembers(hash_object))
        time.sleep(2)