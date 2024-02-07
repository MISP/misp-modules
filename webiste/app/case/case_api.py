from flask import Blueprint, request
from . import case_core as CaseModel
from . import common_core as CommonModel
from . import task_core as TaskModel
from . import case_core_api as CaseModelApi

from flask_restx import Api, Resource
from ..decorators import api_required, editor_required

api_case_blueprint = Blueprint('api_case', __name__)
api = Api(api_case_blueprint,
        title='Flowintel-cm API', 
        description='API to manage a case management instance.', 
        version='0.1', 
        default='GenericAPI', 
        default_label='Generic Flowintel-cm API', 
        doc='/doc/'
    )



@api.route('/all')
@api.doc(description='Get all cases')
class GetCases(Resource):
    method_decorators = [api_required]
    def get(self):
        cases = CommonModel.get_all_cases()
        return {"cases": [case.to_json() for case in cases]}, 200

@api.route('/not_completed')
@api.doc(description='Get all not completed cases')
class GetCases_not_completed(Resource):
    method_decorators = [api_required]
    def get(self):
        cases = CommonModel.get_case_by_completed(False)
        return {"cases": [case.to_json() for case in cases]}, 200
    
@api.route('/completed')
@api.doc(description='Get all completed cases')
class GetCases_not_completed(Resource):
    method_decorators = [api_required]
    def get(self):
        cases = CommonModel.get_case_by_completed(True)
        return {"cases": [case.to_json() for case in cases]}, 200


@api.route('/<cid>')
@api.doc(description='Get a case', params={'cid': 'id of a case'})
class GetCase(Resource):
    method_decorators = [api_required]
    def get(self, cid):
        case = CommonModel.get_case(cid)
        if case:
            case_json = case.to_json()
            orgs = CommonModel.get_orgs_in_case(cid)
            case_json["orgs"] = list()
            for org in orgs:
                case_json["orgs"].append({"id": org.id, "uuid": org.uuid, "name": org.name})
            
            return case_json, 200
        return {"message": "Case not found"}, 404
    
    
@api.route('/title', methods=["POST"])
@api.doc(description='Get a case by title')
class GetCaseTitle(Resource):
    method_decorators = [api_required]
    @api.doc(params={"title": "Title of a case"})
    def post(self):
        if "title" in request.json:
            case = CommonModel.get_case_by_title(request.json["title"])
            if case:
                case_json = case.to_json()
                orgs = CommonModel.get_orgs_in_case(case.id)
                case_json["orgs"] = [{"id": org.id, "uuid": org.uuid, "name": org.name} for org in orgs]            
                return case_json, 200
            return {"message": "Case not found"}, 404
        return {"message": "Need to pass a title"}, 404
    

@api.route('/<cid>/complete')
@api.doc(description='Complete a case', params={'cid': 'id of a case'})
class CompleteCase(Resource):
    method_decorators = [editor_required, api_required]
    def get(self, cid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            case = CommonModel.get_case(cid)
            if case:
                if CaseModel.complete_case(cid, current_user):
                    return {"message": f"Case {cid} completed"}, 200
                return {"message": f"Error case {cid} completed"}, 400
            return {"message": "Case not found"}, 404
        return {"message": "Permission denied"}, 403
    

@api.route('/<cid>/create_template', methods=["POST"])
@api.doc(description='Create a template form case', params={'cid': 'id of a case'})
class CreateTemplate(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={"title_template": "Title for the template that will be create"})
    def post(self, cid):
        if "title_template" in request.json:
            if CommonModel.get_case(cid):
                new_template = CaseModel.create_template_from_case(cid, request.json["title_template"])
                if type(new_template) == dict:
                    return new_template
                return {"template_id": new_template.id}, 201
            return {"message": "Case not found"}, 404
        return {"message": "'title_template' is missing"}, 400


@api.route('/<cid>/recurring', methods=['POST'])
@api.doc(description='Set a case recurring')
class RecurringCase(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={
        "once": "Date(%Y-%m-%d)", 
        "daily": "Boolean", 
        "weekly": "Date(%Y-%m-%d). Start date.", 
        "monthly": "Date(%Y-%m-%d). Start date.",
        "remove": "Boolean"
    })
    def post(self, cid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            if request.json:
                verif_dict = CaseModelApi.verif_set_recurring(request.json)

                if "message" not in verif_dict:
                    CaseModel.change_recurring(verif_dict, cid, current_user)
                    return {"message": "Recurring changed"}, 200
                return verif_dict
            return {"message": "Please give data"}, 400
        return {"message": "Permission denied"}, 403


@api.route('/<cid>/tasks')
@api.doc(description='Get all tasks for a case', params={'cid': 'id of a case'})
class GetTasks(Resource):
    method_decorators = [api_required]
    def get(self, cid):
        case = CommonModel.get_case(cid)
        if case:
            tasks = list()
            for task in case.tasks:
                tasks.append(task.to_json())

            return tasks, 200
        return {"message": "Case not found"}, 404


@api.route('/<cid>/task/<tid>')
@api.doc(description='Get a specific task for a case', params={"cid": "id of a case", "tid": "id of a task"})
class GetTask(Resource):
    method_decorators = [api_required]
    def get(self, cid, tid):
        task = CommonModel.get_task(tid)
        if task:
            if int(cid) == task.case_id:
                loc = dict()
                loc["users_assign"], loc["is_current_user_assign"] = TaskModel.get_users_assign_task(task.id, CaseModelApi.get_user_api(request.headers["X-API-KEY"]))
                loc["task"] = task.to_json()
                return loc, 200
            else:
                return {"message": "Task not in this case"}, 404
        return {"message": "Task not found"}, 404

@api.route('/<cid>/delete')
@api.doc(description='Delete a case', params={'cid': 'id of a case'})
class DeleteCase(Resource):
    method_decorators = [editor_required, api_required]
    def get(self, cid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            if CaseModel.delete_case(cid, current_user):
                return {"message": "Case deleted"}, 200
            return {"message": "Error case deleted"}, 400
        return {"message": "Permission denied"}, 403


@api.route('/<cid>/task/<tid>/delete')
@api.doc(description='Delete a specific task in a case', params={'cid': 'id of a case', "tid": "id of a task"})
class DeleteTask(Resource):
    method_decorators = [editor_required, api_required]
    def get(self, cid, tid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            task = CommonModel.get_task(tid)
            if task:
                if int(cid) == task.case_id:
                    if TaskModel.delete_task(tid, current_user):
                        return {"message": "Task deleted"}, 200
                    else:
                        return {"message": "Error task deleted"}, 400
                else:
                    return {"message": "Task not in this case"}, 404
            return {"message": "Task not found"}, 404
        return {"message": "Permission denied"}, 403
        

@api.route('/create', methods=['POST'])
@api.doc(description='Create a case')
class CreateCase(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={
        "title": "Required. Title for a case", 
        "description": "Description of a case", 
        "deadline_date": "Date(%Y-%m-%d)", 
        "deadline_time": "Time(%H-%M)"
    })
    def post(self):
        user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])

        if request.json:
            verif_dict = CaseModelApi.verif_create_case_task(request.json, True)

            if "message" not in verif_dict:
                case = CaseModel.create_case(verif_dict, user)
                return {"message": f"Case created, id: {case.id}"}, 201

            return verif_dict, 400
        return {"message": "Please give data"}, 400


@api.route('/<cid>/create_task', methods=['POST'])
@api.doc(description='Create a new task to a case', params={'cid': 'id of a case'})
class CreateTask(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={
        "title": "Required. Title for a task", 
        "description": "Description of a task",
        "url": "Link to a tool or a ressource",
        "deadline_date": "Date(%Y-%m-%d)", 
        "deadline_time": "Time(%H-%M)"
    })
    def post(self, cid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            if request.json:
                verif_dict = CaseModelApi.verif_create_case_task(request.json, False)

                if "message" not in verif_dict:
                    task = TaskModel.create_task(verif_dict, cid, current_user)
                    return {"message": f"Task created for case id: {cid}"}, 201
                return verif_dict, 400
            return {"message": "Please give data"}, 400
        return {"message": "Permission denied"}, 403


@api.route('/<id>/edit', methods=['POST'])
@api.doc(description='Edit a case', params={'id': 'id of a case'})
class EditCase(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={"title": "Title for a case", "description": "Description of a case", "deadline_date": "Date(%Y-%m-%d)", "deadline_time": "Time(%H-%M)"})
    def post(self, id):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(id, current_user) or current_user.is_admin():
            if request.json:
                verif_dict = CaseModelApi.verif_edit_case(request.json, id)

                if "message" not in verif_dict:
                    CaseModel.edit_case(verif_dict, id, current_user)
                    return {"message": f"Case {id} edited"}, 200

                return verif_dict, 400
            return {"message": "Please give data"}, 400
        return {"message": "Permission denied"}, 403


@api.route('/<cid>/task/<tid>/edit', methods=['POST'])
@api.doc(description='Edit a task in a case', params={'cid': 'id of a case', "tid": "id of a task"})
class EditTake(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={"title": "Title for a case", "description": "Description of a case", "deadline_date": "Date(%Y-%m-%d)", "deadline_time": "Time(%H-%M)"})
    def post(self, cid, tid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            if request.json:
                task = CommonModel.get_task(tid)
                if task:
                    if int(cid) == task.case_id:
                        verif_dict = CaseModelApi.verif_edit_task(request.json, tid)

                        if "message" not in verif_dict:
                            TaskModel.edit_task_core(verif_dict, tid, current_user)
                            return {"message": f"Task {tid} edited"}, 200

                        return verif_dict, 400
                    else:
                        return {"message": "Task not in this case"}, 404
                else:
                    return {"message": "Task not found"}, 404
            return {"message": "Please give data"}, 400
        return {"message": "Permission denied"}, 403


@api.route('/<cid>/task/<tid>/complete')
@api.doc(description='Complete a task in a case', params={'cid': 'id of a case', "tid": "id of a task"})
class CompleteTake(Resource):
    method_decorators = [editor_required, api_required]
    def get(self, cid, tid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            task = CommonModel.get_task(tid)
            if task:
                if int(cid) == task.case_id:
                    if TaskModel.complete_task(tid, current_user):
                        return {"message": f"Task {tid} completed"}, 200
                    return {"message": f"Error task {tid} completed"}, 400
                else:
                    return {"message": "Task not in this case"}, 404
            return {"message": "Task not found"}, 404
        return {"message": "Permission denied"}, 403


@api.route('/<cid>/task/<tid>/get_note')
@api.doc(description='Get note of a task in a case', params={'cid': 'id of a case', "tid": "id of a task"})
class GetNoteTask(Resource):
    method_decorators = [api_required]
    def get(self, cid, tid):
        task = CommonModel.get_task(tid)
        if task:
            if int(cid) == task.case_id:
                return {"note": task.notes}, 200
            else:
                return {"message": "Task not in this case"}, 404
        return {"message": "Task not found"}, 404


@api.route('/<cid>/task/<tid>/modif_note', methods=['POST'])
@api.doc(description='Edit note of a task in a case', params={'cid': 'id of a case', "tid": "id of a task"})
class ModifNoteTask(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={"note": "note to create or modify"})
    def post(self, cid, tid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            if "note" in request.json:
                task = CommonModel.get_task(tid)
                if task:
                    if int(cid) == task.case_id:
                        if TaskModel.modif_note_core(tid, current_user, request.json["note"]):
                            return {"message": f"Note for task {tid} edited"}, 200
                        return {"message": f"Error Note for task {tid} edited"}, 400
                    else:
                        return {"message": "Task not in this case"}, 404
                return {"message": "Task not found"}, 404
            return {"message": "Key 'note' not found"}, 400
        return {"message": "Permission denied"}, 403



@api.route('/<cid>/add_org', methods=['POST'])
@api.doc(description='Add an org to the case', params={'cid': 'id of a case'})
class AddOrgCase(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={"name": "Name of the organisation", "oid": "id of the organisation"})
    def post(self, cid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            if "name" in request.json:
                org = CommonModel.get_org_by_name(request.json["name"])
            elif "oid" in request.json:
                org = CommonModel.get_org(request.json["oid"])
            else:
                return {"message": "Required an id or a name of an Org"}, 400

            if org:
                if not CommonModel.get_org_in_case(org.id, cid):
                    if CaseModel.add_orgs_case({"org_id": [org.id]}, cid, current_user):
                        return {"message": f"Org added to case {cid}"}, 200
                    return {"message": f"Error Org added to case {cid}"}, 400
                return {"message": "Org already in case"}, 400
            return {"message": "Org not found"}, 404
        return {"message": "Permission denied"}, 403


@api.route('/<cid>/remove_org/<oid>', methods=['GET'])
@api.doc(description='Add an org to the case', params={'cid': 'id of a case', "oid": "id of an org"})
class RemoveOrgCase(Resource):
    method_decorators = [editor_required, api_required]
    def get(self, cid, oid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            org = CommonModel.get_org(oid)

            if org:
                if CommonModel.get_org_in_case(org.id, cid):
                    if CaseModel.remove_org_case(cid, org.id, current_user):
                        return {"message": f"Org deleted from case {cid}"}, 200
                    return {"message": f"Error Org deleted from case {cid}"}, 400
                return {"message": "Org not in case"}, 404
            return {"message": "Org not found"}, 404
        return {"message": "Permission denied"}, 403


@api.route('/<cid>/take_task/<tid>', methods=['GET'])
@api.doc(description='Assign current user to the task', params={'cid': 'id of a case', "tid": "id of a task"})
class AssignTask(Resource):
    method_decorators = [editor_required, api_required]
    def get(self, cid, tid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            task = CommonModel.get_task(tid)

            if task:
                if int(cid) == task.case_id:
                    if TaskModel.assign_task(tid, user=current_user, current_user=current_user, flag_current_user=True):
                        return {"message": f"Task Take"}, 200
                    return {"message": f"Error Task Take"}, 400
                return {"message": "Task not in this case"}, 404
            return {"message": "Task not found"}, 404
        return {"message": "Permission denied"}, 403


@api.route('/<cid>/remove_assignment/<tid>', methods=['GET'])
@api.doc(description='Remove assigment of current user to the task', params={'cid': 'id of a case', "tid": "id of a task"})
class RemoveOrgCase(Resource):
    method_decorators = [editor_required, api_required]
    def get(self, cid, tid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            task = CommonModel.get_task(tid)
            if task:
                if int(cid) == task.case_id:
                    if TaskModel.remove_assign_task(tid, user=current_user, current_user=current_user, flag_current_user=True):
                        return {"message": f"Removed from assignment"}, 200
                    return {"message": f"Error Removed from assignment"}, 400
                return {"message": "Task not in this case"}, 404
            return {"message": "Task not found"}, 404
        return {"message": "Permission denied"}, 403
    

@api.route('/<cid>/get_all_users', methods=['GET'])
@api.doc(description='Get list of user that can be assign', params={'cid': 'id of a case'})
class GetAllUsers(Resource):
    method_decorators = [api_required]
    def get(self, cid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        case = CommonModel.get_case(cid)
        if case:
            users_list = list()
            for org in CommonModel.get_all_users_core(case):
                for user in org.users:
                    if not user == current_user:
                        users_list.append(user.to_json())
            return {"users": users_list}, 200
        return {"message": "Case not found"}, 404


@api.route('/<cid>/task/<tid>/assign_users', methods=['POST'])
@api.doc(description='Assign users to a task', params={'cid': 'id of a case', "tid": "id of a task"})
class AssignUser(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={"users_id": "List of user id"})
    def post(self, cid, tid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            task = CommonModel.get_task(tid)
            if task:
                if int(cid) == task.case_id:
                    users_list = request.json["users_id"]
                    for user in users_list:
                        TaskModel.assign_task(tid, user=user, current_user=current_user, flag_current_user=False)
                    return {"message": "Users Assigned"}, 200
                return {"message": "Task not in this case"}, 404
            return {"message": "Task not found"}, 404
        return {"message": "Permission denied"}, 403


@api.route('/<cid>/task/<tid>/remove_assign_user', methods=['POST'])
@api.doc(description='Remove an assign user to a task', params={'cid': 'id of a case', "tid": "id of a task"})
class AssignUser(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={"user_id": "Id of a user"})
    def post(self, cid, tid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            task = CommonModel.get_task(tid)
            if task:
                if int(cid) == task.case_id:
                    user_id = request.json["user_id"]
                    if TaskModel.remove_assign_task(tid, user=user_id, current_user=current_user, flag_current_user=False):
                        return {"message": "User Removed from assignment"}, 200
                return {"message": "Task not in this case"}, 404
            return {"message": "Task not found"}, 404
        return {"message": "Permission denied"}, 403
    


@api.route('/<cid>/task/<tid>/change_status', methods=['POST'])
@api.doc(description='Change status of a task', params={'cid': 'id of a case', "tid": "id of a task"})
class ChangeStatus(Resource):
    method_decorators = [editor_required, api_required]
    @api.doc(params={"status_id": "Id of the new status"})
    def post(self, cid, tid):
        current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            task = CommonModel.get_task(tid)
            if task:
                if int(cid) == task.case_id:
                    if TaskModel.change_task_status(request.json["status_id"], task, current_user):
                        return {"message": "Status changed"}, 200
                return {"message": "Task not in this case"}, 404
            return {"message": "Task not found"}, 404
        return {"message": "Permission denied"}, 403


@api.route('/list_status', methods=['GET'])
@api.doc(description='List all status')
class ChangeStatus(Resource):
    method_decorators = [api_required]
    def get(self):
        return [status.to_json() for status in CommonModel.get_all_status()], 200
    

@api.route('/<cid>/history', methods=['GET'])
@api.doc(description='Get history of a case', params={'cid': 'id of a case'})
class ChangeStatus(Resource):
    method_decorators = [api_required]
    def get(self, cid):
        case = CommonModel.get_case(cid)
        if case:
            history = CommonModel.get_history(case.uuid)
            if history:
                return {"history": history}
            return {"history": None}
        return {"message": "Case Not found"}, 404

 
@api.route('/<cid>/task/<tid>/files')
@api.doc(description='Get list of files', params={"cid": "id of a case", "tid": "id of a task"})
class DownloadFile(Resource):
    method_decorators = [api_required]
    def get(self, cid, tid):
        case = CommonModel.get_case(cid)
        if case:
            task = CommonModel.get_task(tid)
            if task:
                file_list = [file.to_json() for file in task.files]
                return {"files": file_list}, 200
            return {"message": "Task Not found"}, 404
        return {"message": "Case Not found"}, 404

@api.route('/<cid>/task/<tid>/upload_file')
@api.doc(description='Upload a file')
class UploadFile(Resource):
    method_decorators = [api_required]
    @api.doc(params={})
    def post(self, cid, tid):
        case = CommonModel.get_case(cid)
        if case:
            current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
            if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
                task = CommonModel.get_task(tid)
                if task:
                    if TaskModel.add_file_core(task, request.files, current_user):
                        return {"message": "File added"}, 200
                return {"message": "Task Not found"}, 404
            return {"message": "Permission denied"}, 403
        return {"message": "Case Not found"}, 404
    

@api.route('/<cid>/task/<tid>/download_file/<fid>')
@api.doc(description='Download a file', params={"cid": "id of a case", "tid": "id of a task", "fid": "id of a file"})
class DownloadFile(Resource):
    method_decorators = [api_required]
    def get(self, cid, tid, fid):
        case = CommonModel.get_case(cid)
        if case:
            current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
            if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
                task = CommonModel.get_task(tid)
                if task:
                    file = CommonModel.get_file(fid)
                    if file and file in task.files:
                        return TaskModel.download_file(file)
                return {"message": "Task Not found"}, 404
            return {"message": "Permission denied"}, 403
        return {"message": "Case Not found"}, 404
    
@api.route('/<cid>/task/<tid>/delete_file/<fid>')
@api.doc(description='Delete a file', params={"cid": "id of a case", "tid": "id of a task", "fid": "id of a file"})
class DeleteFile(Resource):
    method_decorators = [api_required]
    @api.doc(params={
        })
    def get(self, cid, tid, fid):
        case = CommonModel.get_case(cid)
        if case:
            current_user = CaseModelApi.get_user_api(request.headers["X-API-KEY"])
            if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
                task = CommonModel.get_task(tid)
                if task:
                    file = CommonModel.get_file(fid)
                    if file and file in task.files:
                        if TaskModel.delete_file(file, task, current_user):
                            return {"message": "File Deleted"}, 200
                return {"message": "Task Not found"}, 404
            return {"message": "Permission denied"}, 403
        return {"message": "Case Not found"}, 404