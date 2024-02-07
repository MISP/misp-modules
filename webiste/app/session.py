import json
from queue import Queue
from threading import Thread
from uuid import uuid4
from .utils.utils import query_post_query, query_get_module
from . import home_core as HomeModel
import uuid
from . import db
from .db_class.db import History, Session_db
from sqlalchemy import func


sessions = list()

class Session_class:
    def __init__(self, request_json) -> None:
        self.id = str(uuid4())
        self.thread_count = 4
        self.jobs = Queue(maxsize=0)
        self.threads = []
        self.stopped = False
        self.result_stopped = dict()
        self.result = dict()
        self.expansion = self.expansion_setter(request_json)
        self.hover = self.hover_setter(request_json)
        self.query = request_json["query"]
        self.input_query = request_json["input"]
        self.glob_query = self.expansion + self.hover
        self.nb_errors = 0
        self.config_module = self.config_module_setter(request_json)

    def expansion_setter(self, request_json):
        if "expansion" in request_json:
            return request_json["expansion"]
        return []
        
    def hover_setter(self, request_json):
        if "hover" in request_json:
            return request_json["hover"]
        return []
    
    def config_module_setter(self, request_json):
        if request_json["config"]:
            for query in self.glob_query:
                if not query in request_json["config"]:
                    request_json["config"][query] = {}
                    module = HomeModel.get_module_by_name(query)
                    mcs = HomeModel.get_module_config_module(module.id)
                    for mc in mcs:
                        config_db = HomeModel.get_config(mc.config_id)
                        request_json["config"][query][config_db.name] = mc.value
            return request_json["config"]
        return {}

    def start(self):
        """Start all worker"""
        for i in range(len(self.glob_query)):
            #need the index and the url in each queue item.
            self.jobs.put((i, self.glob_query[i]))
        for _ in range(self.thread_count):
            worker = Thread(target=self.process)
            worker.daemon = True
            worker.start()
            self.threads.append(worker)

    def status(self):
        """Status of the current queue"""
        if self.jobs.empty():
            self.stop()

        total = len(self.glob_query)
        remaining = max(self.jobs.qsize(), len(self.threads))
        complete = total - remaining
        registered = len(self.result)

        return {
            'id': self.id,
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
            print(res)
            if "error" in res:
                self.nb_errors += 1
            self.result[work[1]] = res

            self.jobs.task_done()
        return True
    
    def get_result(self):
        return self.result
    
    def save_info(self):
        s = Session_db(
            uuid=str(self.id),
            glob_query=json.dumps(self.glob_query),
            query_enter=self.query,
            input_query=self.input_query,
            config_module=json.dumps(self.config_module),
            result=json.dumps(self.result),
            nb_errors=self.nb_errors
        )
        db.session.add(s)
        db.session.commit()

        h = History(
            session_id=s.id
        )
        db.session.add(h)
        db.session.commit()

        histories = History.query.all()
        
        while len(histories) > 3:
            history = History.query.order_by(History.id).all()
            Session_db.query.filter_by(id=history[0].session_id).delete()
            History.query.filter_by(id=history[0].id).delete()

            histories = History.query.all()

        db.session.commit()
        return