import datetime
import json
from queue import Queue
from threading import Thread
from uuid import uuid4
from .utils.utils import query_post_query, query_get_module
from . import home_core as HomeModel
import uuid
from . import db
from .db_class.db import History, History_Tree, Session_db
from flask import session as sess 

sessions = list()

class Session_class:
    def __init__(self, request_json, query_as_same=False, parent_id=None) -> None:
        self.uuid = str(uuid4())
        self.thread_count = 4
        self.jobs = Queue(maxsize=0)
        self.threads = []
        self.stopped = False
        self.result_stopped = dict()
        self.result = dict()
        self.query = request_json["query"]
        self.input_query = request_json["input"]
        self.modules_list = request_json["modules"]
        self.nb_errors = 0
        self.config_module = self.config_module_setter(request_json, query_as_same, parent_id)
        self.query_date = datetime.datetime.now(tz=datetime.timezone.utc)

    
    def util_config_as_same(self, child, parent_id):
        if child["uuid"] == parent_id:
            return child["config"]
        elif "children" in child:
            for c in child["children"]:
                return self.util_config_as_same(c, parent_id)

    
    def config_module_setter(self, request_json, query_as_same, parent_id):
        """Setter for config for all modules used"""
        flag = False
        if query_as_same:
            current_query_val = sess.get(sess.get("current_query"))
            if current_query_val:
                if current_query_val["uuid"] == parent_id:
                    return current_query_val["config"]
                else:
                    for child in current_query_val["children"]:
                        res = self.util_config_as_same(child, parent_id)
                        if res:
                            flag = True
                            return res
        if not flag:
            for query in self.modules_list:
                if not query in request_json["config"]:
                    request_json["config"][query] = {}
                    module = HomeModel.get_module_by_name(query)
                    mcs = HomeModel.get_module_config_module(module.id)
                    for mc in mcs:
                        config_db = HomeModel.get_config(mc.config_id)
                        request_json["config"][query][config_db.name] = mc.value
        return request_json["config"]

    def start(self):
        """Start all worker"""
        for i in range(len(self.modules_list)):
            #need the index and the url in each queue item.
            self.jobs.put((i, self.modules_list[i]))
        for _ in range(self.thread_count):
            worker = Thread(target=self.process)
            worker.daemon = True
            worker.start()
            self.threads.append(worker)

    def status(self):
        """Status of the current queue"""
        if self.jobs.empty():
            self.stop()

        total = len(self.modules_list)
        remaining = max(self.jobs.qsize(), len(self.threads))
        complete = total - remaining
        registered = len(self.result)

        return {
            'id': self.uuid,
            'total': total,
            'complete': complete,
            'remaining': remaining,
            'registered': registered,
            'stopped' : self.stopped,
            "nb_errors": self.nb_errors
            }

    def stop(self):
        """Stop the current queue and worker"""
        self.jobs.queue.clear()

        for worker in self.threads:
            worker.join(3.5)

        self.threads.clear()
        sessions.remove(self)
        self.save_info()

    def process(self):
        """Threaded function for queue processing."""
        while not self.jobs.empty():
            work = self.jobs.get()

            modules = query_get_module()
            loc_query = {}
            # If Misp format
            for module in modules:
                if module["name"] == work[1]:
                    if "format" in module["mispattributes"]:
                        loc_query = {
                            "type": self.input_query,
                            "value": self.query,
                            "uuid": str(uuid.uuid4())
                        }
                    break
            
            loc_config = {}
            if work[1] in self.config_module:
                loc_config = self.config_module[work[1]]
                
            if loc_query:
                send_to = {"module": work[1], "attribute": loc_query, "config": loc_config}
            else:
                send_to = {"module": work[1], self.input_query: self.query, "config": loc_config}
            res = query_post_query(send_to)
            # print(res)
            if "error" in res:
                self.nb_errors += 1
            self.result[work[1]] = res

            self.jobs.task_done()
        return True
    
    def get_result(self):
        return self.result
    
    def save_info(self):
        """Save info in the db"""
        s = Session_db(
            uuid=str(self.uuid),
            modules_list=json.dumps(self.modules_list),
            query_enter=self.query,
            input_query=self.input_query,
            config_module=json.dumps(self.config_module),
            result=json.dumps(self.result),
            nb_errors=self.nb_errors,
            query_date=self.query_date
        )
        db.session.add(s)
        db.session.commit()

        h = History(
            session_id=s.id
        )
        db.session.add(h)
        db.session.commit()

        histories = History.query.all()
        
        while len(histories) > 200:
            history = History.query.order_by(History.id).all()
            session = Session_db.query.filter_by(id=history[0].session_id)
            if not History_Tree.query.filter_by(session_uuid=session.uuid):
                Session_db.query.filter_by(id=history[0].session_id).delete()
            History.query.filter_by(id=history[0].id).delete()

            histories = History.query.all()

        db.session.commit()
        return