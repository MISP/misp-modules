import json
from flask import Blueprint, render_template, redirect, jsonify, request, flash
from .form import CaseForm, CaseEditForm, AddOrgsCase, RecurringForm
from flask_login import login_required, current_user
from . import case_core as CaseModel
from . import common_core as CommonModel
from . import task_core as TaskModel
from ..db_class.db import Task_Template, Case_Template
from ..decorators import editor_required
from ..utils.utils import form_to_dict, check_tag

case_blueprint = Blueprint(
    'case',
    __name__,
    template_folder='templates',
    static_folder='static'
)

from .task import task_blueprint
case_blueprint.register_blueprint(task_blueprint)

##########
# Render #
##########


@case_blueprint.route("/", methods=['GET', 'POST'])
@login_required
def index():
    """List all cases"""
    return render_template("case/case_index.html")

@case_blueprint.route("/create_case", methods=['GET', 'POST'])
@login_required
def create_case():
    """Create a case"""
    form = CaseForm()
    form.template_select.choices = [(template.id, template.title) for template in Case_Template.query.all()]
    form.template_select.choices.insert(0, (0," "))

    form.tasks_templates.choices = [(template.id, template.title) for template in Task_Template.query.all()]
    form.tasks_templates.choices.insert(0, (0," "))
    
    if form.validate_on_submit():
        tag_list = request.form.getlist("tags_select")
        cluster_list = request.form.getlist("clusters_select")
        if CommonModel.check_tag(tag_list):
            if CommonModel.check_cluster(cluster_list):
                form_dict = form_to_dict(form)
                form_dict["tags"] = tag_list
                form_dict["clusters"] = cluster_list
                case = CaseModel.create_case(form_dict, current_user)
                flash("Case created", "success")
                return redirect(f"/case/{case.id}")
            return render_template("case/create_case.html", form=form)
        return render_template("case/create_case.html", form=form)
    return render_template("case/create_case.html", form=form)

@case_blueprint.route("/<cid>", methods=['GET', 'POST'])
@login_required
def view(cid):
    """View a case"""
    case = CommonModel.get_case(cid)
    if case:
        present_in_case = CaseModel.get_present_in_case(cid, current_user)
        return render_template("case/case_view.html", case=case.to_json(), present_in_case=present_in_case)
    return render_template("404.html")


@case_blueprint.route("/edit/<cid>", methods=['GET','POST'])
@login_required
@editor_required
def edit_case(cid):
    """Edit the case"""
    if CommonModel.get_case(cid):
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            form = CaseEditForm()

            if form.validate_on_submit():
                tag_list = request.form.getlist("tags_select")
                cluster_list = request.form.getlist("clusters_select")
                if CommonModel.check_tag(tag_list):
                    if CommonModel.check_cluster(cluster_list):
                        form_dict = form_to_dict(form)
                        form_dict["tags"] = tag_list
                        form_dict["clusters"] = cluster_list
                        CaseModel.edit_case(form_dict, cid, current_user)
                        flash("Case edited", "success")
                        return redirect(f"/case/{cid}")
                    return render_template("case/edit_case.html", form=form)
                return render_template("case/edit_case.html", form=form)
            else:
                case_modif = CommonModel.get_case(cid)
                form.description.data = case_modif.description
                form.title.data = case_modif.title
                form.deadline_date.data = case_modif.deadline
                form.deadline_time.data = case_modif.deadline

            return render_template("case/edit_case.html", form=form)
        else:
            flash("Access denied", "error")
    else:
        return render_template("404.html")
    return redirect(f"/case/{id}")


@case_blueprint.route("/<cid>/add_orgs", methods=['GET', 'POST'])
@login_required
@editor_required
def add_orgs(cid):
    """Add orgs to the case"""

    if CommonModel.get_case(cid):
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            form = AddOrgsCase()
            case_org = CommonModel.get_org_in_case_by_case_id(cid)
            org_list = list()
            for org in CommonModel.get_org_order_by_name():
                if case_org:
                    flag = False
                    for c_o in case_org:
                        if c_o.org_id == org.id:
                            flag = True
                    if not flag:
                        org_list.append((org.id, f"{org.name}"))
                else:
                    org_list.append((org.id, f"{org.name}"))

            form.org_id.choices = org_list
            form.case_id.data = cid

            if form.validate_on_submit():
                form_dict = form_to_dict(form)
                CaseModel.add_orgs_case(form_dict, cid, current_user)
                flash("Orgs added", "success")
                return redirect(f"/case/{cid}")

            return render_template("case/add_orgs.html", form=form)
        else:
            flash("Access denied", "error")
    else:
        return render_template("404.html")
    return redirect(f"/case/{cid}")


@case_blueprint.route("/<cid>/recurring", methods=['GET', 'POST'])
@login_required
@editor_required
def recurring(cid):
    """Recurring form"""

    if CommonModel.get_case(cid):
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            form = RecurringForm()
            form.case_id.data = cid

            # List orgs and users in and verify if all users of an org are currently notify
            orgs_in_case = CommonModel.get_orgs_in_case(cid)
            orgs_to_return = list()
            for org in orgs_in_case:
                loc = org.to_json()
                loc["users"] = list()
                cp_checked_user = 0
                cp_users = 0
                for user in org.users:
                    cp_users += 1
                    loc_user = user.to_json()
                    if CommonModel.get_recu_notif_user(cid, user.id):
                        loc_user["checked"] = True
                        cp_checked_user += 1
                    else:
                        loc_user["checked"] = False
                    loc["users"].append(loc_user)
                # if all users in an org are notify, then check the org checkbox
                if cp_checked_user == cp_users:
                    loc["checked"] = True
                else:
                    loc["checked"] = False
                orgs_to_return.append(loc)

            if form.validate_on_submit():
                form_dict = form_to_dict(form)
                if not CaseModel.change_recurring(form_dict, cid, current_user):
                    flash("Recurring empty", "error")
                    return redirect(f"/case/{cid}/recurring")
                if not form_dict["remove"]:
                    CaseModel.notify_user_recurring(request.form.to_dict(), cid, orgs_in_case)
                flash("Recurring set", "success")
                return redirect(f"/case/{cid}")
            
            return render_template("case/case_recurring.html", form=form, orgs=orgs_to_return)
        
        flash("Action not allowed", "warning")
        return redirect(f"/case/{cid}")
    
    return render_template("404.html")


############
# Function #
#  Route   #
############

@case_blueprint.route("/get_cases_page", methods=['GET'])
@login_required
def get_cases():
    """Return all cases"""
    page = request.args.get('page', 1, type=int)
    tags = request.args.get('tags')
    taxonomies = request.args.get('taxonomies')
    or_and = request.args.get("or_and")

    cases = CaseModel.sort_by_status(page, tags, taxonomies, or_and, completed=False)
    role = CommonModel.get_role(current_user).to_json()

    loc = CaseModel.regroup_case_info(cases, current_user)
    return jsonify({"cases": loc["cases"], "role": role, "nb_pages": cases.pages}), 200


@case_blueprint.route("/search", methods=['GET'])
@login_required
def search():
    """Return cases matching search terms"""
    text_search = request.args.get("text")
    cases = CommonModel.search(text_search)
    if cases:
        return {"cases": [case.to_json() for case in cases]}, 200
    return {"message": "No case", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/<cid>/delete", methods=['GET'])
@login_required
@editor_required
def delete(cid):
    """Delete the case"""

    if CommonModel.get_case(cid):
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            if CaseModel.delete_case(cid, current_user):
                return {"message": "Case deleted", "toast_class": "success-subtle"}, 200
            else:
                return {"message": "Error case deleted", 'toast_class': "danger-subtle"}, 400
        return {"message": "Action not allowed", "toast_class": "warning-subtle"}, 401
    return {"message": "Case no found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/<cid>/get_case_info", methods=['GET'])
@login_required
def get_case_info(cid):
    """Return all info of the case"""
    case = CommonModel.get_case(cid)
    if case:    
        tasks = TaskModel.sort_by_status_task_core(case, current_user, completed=False)

        o_in_c = CommonModel.get_orgs_in_case(case.id)
        orgs_in_case = [o_c.to_json() for o_c in o_in_c]
        permission = CommonModel.get_role(current_user).to_json()
        present_in_case = CaseModel.get_present_in_case(cid, current_user)

        return jsonify({"case": case.to_json(), "tasks": tasks, "orgs_in_case": orgs_in_case, "permission": permission, "present_in_case": present_in_case, "current_user": current_user.to_json()}), 200
    return {"message": "Case not found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/<cid>/complete_case", methods=['GET'])
@login_required
@editor_required
def complete_case(cid):
    """Complete the case"""
    if CommonModel.get_case(cid):
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            if CaseModel.complete_case(cid, current_user):
                flash("Case Completed")
                if request.args.get('revived', 1) == "true":
                    return {"message": "Case Revived", "toast_class": "success-subtle"}, 200
                return {"message": "Case completed", "toast_class": "success-subtle"}, 200
            else:
                if request.args.get('revived', 1) == "true":
                    return {"message": "Error case revived", 'toast_class': "danger-subtle"}, 400
                return {"message": "Error case completed", 'toast_class': "danger-subtle"}, 400
        return {"message": "Action not allowed", "toast_class": "warning-subtle"}, 401
    return {"message": "Case not found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/<cid>/remove_org/<oid>", methods=['GET'])
@login_required
@editor_required
def remove_org_case(cid, oid):
    """Remove an org to the case"""

    if CommonModel.get_case(cid):
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            if CaseModel.remove_org_case(cid, oid, current_user):
                return {"message": "Org removed from case", "toast_class": "success-subtle"}, 200
            return {"message": "Error removing org from case", "toast_class": "danger-subtle"}, 400
        return {"message": "Action not allowed", "toast_class": "warning-subtle"}, 401
    return {"message": "Case not found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/<cid>/change_status", methods=['POST'])
@login_required
@editor_required
def change_status(cid):
    """Change the status of the case"""
    
    status = request.json["status"]
    case = CommonModel.get_case(cid)

    if CommonModel.get_case(cid):
        if CaseModel.get_present_in_case(cid, current_user) or current_user.is_admin():
            CaseModel.change_status_core(status, case, current_user)
            return {"message": "Status changed", "toast_class": "success-subtle"}, 200
        return {"message": "Action not allowed", "toast_class": "warning-subtle"}, 401
    return {"message": "Case not found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/get_status", methods=['GET'])
@login_required
def get_status():
    """Get status"""

    status = CommonModel.get_all_status()
    status_list = list()
    for s in status:
        status_list.append(s.to_json())
    return jsonify({"status": status_list}), 200


@case_blueprint.route("/sort_by_ongoing", methods=['GET'])
@login_required
def sort_by_ongoing():
    """Sort Case by living one"""
    page = request.args.get('page', 1, type=int)
    tags = request.args.get('tags')
    taxonomies = request.args.get('taxonomies')
    or_and_taxo = request.args.get("or_and_taxo")

    galaxies = request.args.get('galaxies')
    clusters = request.args.get('clusters')
    or_and_galaxies = request.args.get("or_and_galaxies")

    cases_list = CaseModel.sort_by_status(page, taxonomies, galaxies, tags, clusters, or_and_taxo, or_and_galaxies, completed=False)
    return CaseModel.regroup_case_info(cases_list, current_user)



@case_blueprint.route("/sort_by_finished", methods=['GET'])
@login_required
def sort_by_finished():
    """Sort Case by finished one"""
    page = request.args.get('page', 1, type=int)
    tags = request.args.get('tags')
    taxonomies = request.args.get('taxonomies')
    or_and_taxo = request.args.get("or_and_taxo")

    galaxies = request.args.get('galaxies')
    clusters = request.args.get('clusters')
    or_and_galaxies = request.args.get("or_and_galaxies")

    cases_list = CaseModel.sort_by_status(page, taxonomies, galaxies, tags, clusters, or_and_taxo, or_and_galaxies, completed=True)
    return CaseModel.regroup_case_info(cases_list, current_user)


@case_blueprint.route("/ongoing", methods=['GET'])
@login_required
def ongoing_sort_by_filter():
    """Sort by filter for living case"""
    page = request.args.get('page', 1, type=int)
    filter = request.args.get('filter')
    tags = request.args.get('tags')
    taxonomies = request.args.get('taxonomies')
    or_and_taxo = request.args.get("or_and_taxo")

    galaxies = request.args.get('galaxies')
    clusters = request.args.get('clusters')
    or_and_galaxies = request.args.get("or_and_galaxies")

    if filter:
        cases_list, nb_pages = CaseModel.sort_by_filter(filter, page, taxonomies, galaxies, tags, clusters, or_and_taxo, or_and_galaxies, completed=False)
        return CaseModel.regroup_case_info(cases_list, current_user, nb_pages)
    return {"message": "No filter pass"}


@case_blueprint.route("/finished", methods=['GET'])
@login_required
def finished_sort_by_filter():
    """Sort by filter for finished task"""
    page = request.args.get('page', 1, type=int)
    filter = request.args.get('filter')
    tags = request.args.get('tags')
    taxonomies = request.args.get('taxonomies')
    or_and_taxo = request.args.get("or_and_taxo")

    galaxies = request.args.get('galaxies')
    clusters = request.args.get('clusters')
    or_and_galaxies = request.args.get("or_and_galaxies")

    if filter:
        cases_list, nb_pages = CaseModel.sort_by_filter(filter, page, taxonomies, galaxies, tags, clusters, or_and_taxo, or_and_galaxies, completed=True)
        return CaseModel.regroup_case_info(cases_list, current_user, nb_pages)
    return {"message": "No filter pass"}


@case_blueprint.route("/<cid>/get_all_users", methods=['GET'])
@login_required
def get_all_users(cid):
    """Get all user in case"""

    case = CommonModel.get_case(cid)
    if case:
        users_list = list()
        orgs = CommonModel.get_all_users_core(case)
        for org in orgs:
            for user in org.users:
                if not user == current_user:
                    users_list.append(user.to_json())
        return {"users_list": users_list}
    return {"message": "Case not found"}, 404


@case_blueprint.route("/<cid>/get_assigned_users/<tid>", methods=['GET'])
@login_required
def get_assigned_users(cid, tid):
    """Get assigned users to the task"""

    if CommonModel.get_case(cid):
        users, _ = TaskModel.get_users_assign_task(tid, current_user)
        return users
    return {"message": "Case not found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/<cid>/download", methods=['GET'])
@login_required
def download_case(cid):
    """Download a case"""

    case = CommonModel.get_case(cid)
    if case:
        task_list = list()
        for task in case.tasks:
            task_list.append(task.download())
        return_dict = case.download()
        return_dict["tasks"] = task_list
        return jsonify(return_dict), 200, {'Content-Disposition': f'attachment; filename=case_{case.title}.json'}
    return {"message": "Case not found", 'toast_class': "danger-subtle"}, 404



@case_blueprint.route("/<cid>/fork", methods=['POST'])
@login_required
def fork_case(cid):
    """Assign current user to the task"""

    if CommonModel.get_case(cid):
        if "case_title_fork" in request.json:
            case_title_fork = request.json["case_title_fork"]

            new_case = CaseModel.fork_case_core(cid, case_title_fork, current_user)
            if type(new_case) == dict:
                return new_case
            return {"new_case_id": new_case.id}, 201
        return {"message": "'case_title_fork' is missing", 'toast_class': "danger-subtle"}, 400
    return {"message": "Case not found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/get_all_case_title", methods=['GET'])
@login_required
def get_all_case_title():
    data_dict = dict(request.args)
    if CommonModel.get_case_by_title(data_dict["title"]):
        flag = True
    else:
        flag = False
    
    return {"title_already_exist": flag}


@case_blueprint.route("/<cid>/create_template", methods=['POST'])
@login_required
@editor_required
def create_template(cid):
    if CommonModel.get_case(cid):
        if "case_title_template" in request.json:
            case_title_template = request.json["case_title_template"]

            new_template = CaseModel.create_template_from_case(cid, case_title_template)
            if type(new_template) == dict:
                return new_template
            return {"template_id": new_template.id}, 201
        return {"message": "'case_title_template' is missing", 'toast_class': "danger-subtle"}, 400
    return {"message": "Case not found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/get_all_case_template_title", methods=['GET'])
@login_required
def get_all_case_template_title():
    data_dict = dict(request.args)
    if CommonModel.get_case_template_by_title(data_dict["title"]):
        flag = True
    else:
        flag = False
    
    return {"title_already_exist": flag}


@case_blueprint.route("/history/<cid>", methods=['GET'])
@login_required
def history(cid):
    case = CommonModel.get_case(cid)
    if case:
        history = CommonModel.get_history(case.uuid)
        if history:
            return {"history": history}
        return {"history": None}
    return {"message": "Case Not found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/get_taxonomies", methods=['GET'])
@login_required
def get_taxonomies():
    return {"taxonomies": CommonModel.get_taxonomies()}, 200

@case_blueprint.route("/get_tags", methods=['GET'])
@login_required
def get_tags():
    data_dict = dict(request.args)
    if "taxonomies" in data_dict:
        taxos = json.loads(data_dict["taxonomies"])
        return {"tags": CommonModel.get_tags(taxos)}, 200
    return {"message": "'taxonomies' is missing", 'toast_class': "warning-subtle"}, 400


@case_blueprint.route("/get_taxonomies_case/<cid>", methods=['GET'])
@login_required
def get_taxonomies_case(cid):
    case = CommonModel.get_case(cid)
    if case:
        tags = CommonModel.get_case_tags(case.id)
        taxonomies = []
        if tags:
            taxonomies = [tag.split(":")[0] for tag in tags]
        return {"tags": tags, "taxonomies": taxonomies}
    return {"message": "Case Not found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/get_galaxies", methods=['GET'])
@login_required
def get_galaxies():
    return {"galaxies": CommonModel.get_galaxies()}, 200


@case_blueprint.route("/get_clusters", methods=['GET'])
@login_required
def get_clusters():
    if "galaxies" in request.args:
        galaxies = request.args.get("galaxies")
        galaxies = json.loads(galaxies)
        return {"clusters": CommonModel.get_clusters_galaxy(galaxies)}, 200
    return {"message": "'galaxies' is missing", 'toast_class': "warning-subtle"}, 400


@case_blueprint.route("/get_galaxies_case/<cid>", methods=['GET'])
@login_required
def get_galaxies_case(cid):
    case = CommonModel.get_case(cid)
    if case:
        clusters = CommonModel.get_case_clusters(case.id)
        galaxies = []
        if clusters:
            for cluster in clusters:
                loc_g = CommonModel.get_galaxy(cluster.galaxy_id)
                if not loc_g.name in galaxies:
                    galaxies.append(loc_g.name)
                index = clusters.index(cluster)
                clusters[index] = cluster.tag
        return {"clusters": clusters, "galaxies": galaxies}
    return {"message": "Case Not found", 'toast_class': "danger-subtle"}, 404


@case_blueprint.route("/get_modules", methods=['GET'])
@login_required
def get_modules():
    return {"modules": CaseModel.get_modules()}, 200
    # return {"message": "'galaxies' is missing", 'toast_class': "warning-subtle"}, 400


@case_blueprint.route("/get_instance_module", methods=['GET'])
@login_required
def get_instance_module():
    if "module" in request.args:
        module = request.args.get("module")
    return {"instances": CaseModel.get_instance_module_core(module, current_user.id)}, 200
