import os
import ast
import uuid
import datetime

from app.utils.utils import get_modules_list, MODULES, MODULES_CONFIG
from .. import db
from ..db_class.db import *
from sqlalchemy import desc, and_
from ..notification import notification_core as NotifModel
from dateutil import relativedelta
from ..tools.tools_core import create_case_from_template

from . import common_core as CommonModel
from . import task_core as TaskModel


def delete_case(cid, current_user):
    """Delete a case by is id"""
    case = CommonModel.get_case(cid)
    if case:
        # Delete all tasks in the case
        for task in case.tasks:
            TaskModel.delete_task(task.id, current_user)

        history_path = os.path.join(CommonModel.HISTORY_FOLDER, str(case.uuid))
        if os.path.isfile(history_path):
            try:
                os.remove(history_path)
            except:
                return False

        NotifModel.create_notification_all_orgs(f"Case: '{case.id}-{case.title}' was deleted", cid, html_icon="fa-solid fa-trash", current_user=current_user)

        Case_Tags.query.filter_by(case_id=case.id).delete()
        Case_Galaxy_Tags.query.filter_by(case_id=case.id).delete()
        Case_Org.query.filter_by(case_id=case.id).delete()
        db.session.delete(case)
        db.session.commit()
        return True
    return False


def complete_case(cid, current_user):
    """Complete case by is id"""
    case = CommonModel.get_case(cid)
    if case is not None:
        case.completed = not case.completed
        if case.completed:
            case.status_id = Status.query.filter_by(name="Finished").first().id
            for task in case.tasks:
                TaskModel.complete_task(task.id, current_user)
            NotifModel.create_notification_all_orgs(f"Case: '{case.id}-{case.title}' is now completed", cid, html_icon="fa-solid fa-square-check", current_user=current_user)
        else:
            case.status_id = Status.query.filter_by(name="Created").first().id
            NotifModel.create_notification_all_orgs(f"Case: '{case.id}-{case.title}' is now revived", cid, html_icon="fa-solid fa-heart-circle-plus", current_user=current_user)

        CommonModel.update_last_modif(cid)
        db.session.commit()
        CommonModel.save_history(case.uuid, current_user, "Case completed")
        return True
    return False


def create_case(form_dict, user):
    """Add a case to the DB"""
    if "template_select" in form_dict and not 0 in form_dict["template_select"]:
        for template in form_dict["template_select"]:
            if Case_Template.query.get(template):
                case = create_case_from_template(template, form_dict["title_template"], user)
    else:
        deadline = CommonModel.deadline_check(form_dict["deadline_date"], form_dict["deadline_time"])
        case = Case(
            title=form_dict["title"],
            description=form_dict["description"],
            uuid=str(uuid.uuid4()),
            creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
            last_modif=datetime.datetime.now(tz=datetime.timezone.utc),
            deadline=deadline,
            status_id=1,
            owner_org_id=user.org_id
        )
        db.session.add(case)
        db.session.commit()

        for tags in form_dict["tags"]:
            tag = CommonModel.get_tag(tags)
            
            case_tag = Case_Tags(
                tag_id=tag.id,
                case_id=case.id
            )
            db.session.add(case_tag)
            db.session.commit()
        
        for clusters in form_dict["clusters"]:
            cluster = CommonModel.get_cluster_by_name(clusters)
            
            case_galaxy = Case_Galaxy_Tags(
                cluster_id=cluster.id,
                case_id=case.id
            )
            db.session.add(case_galaxy)
            db.session.commit()

        if "tasks_templates" in form_dict and not 0 in form_dict["tasks_templates"]:
            for tid in form_dict["tasks_templates"]:
                task = Task_Template.query.get(tid)
                t = Task(
                    uuid=str(uuid.uuid4()),
                    title=task.title,
                    description=task.description,
                    url=task.url,
                    creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
                    last_modif=datetime.datetime.now(tz=datetime.timezone.utc),
                    case_id=case.id,
                    status_id=1
                )
                db.session.add(t)
                db.session.commit()

                for t_t in Task_Template_Tags.query.filter_by(task_id=task.id).all():
                    task_tag = Task_Tags(
                        task_id=t.id,
                        tag_id=t_t.tag_id
                    )
                    db.session.add(task_tag)
                    db.session.commit()

                for t_t in Task_Template_Galaxy_Tags.query.filter_by(task_id=task.id).all():
                    task_galaxy = Task_Galaxy_Tags(
                        task_id=t.id,
                        cluster_id=t_t.cluster_id
                    )
                    db.session.add(task_galaxy)
                    db.session.commit()

        # Add the current user's org to the case
        case_org = Case_Org(
            case_id=case.id, 
            org_id=user.org_id
        )
        db.session.add(case_org)
        db.session.commit()

    CommonModel.save_history(case.uuid, user, "Case Created")

    return case


def edit_case(form_dict, cid, current_user):
    """Edit a case to the DB"""
    case = CommonModel.get_case(cid)
    deadline = CommonModel.deadline_check(form_dict["deadline_date"], form_dict["deadline_time"])

    case.title = form_dict["title"]
    case.description=form_dict["description"]
    case.deadline=deadline

    ## Tags
    case_tag_db = Case_Tags.query.filter_by(case_id=case.id).all()
    for tags in form_dict["tags"]:
        tag = CommonModel.get_tag(tags)

        if not tags in case_tag_db:
            case_tag = Case_Tags(
                tag_id=tag.id,
                case_id=case.id
            )
            db.session.add(case_tag)
            db.session.commit()
    
    for c_t_db in case_tag_db:
        if not c_t_db in form_dict["tags"]:
            Case_Tags.query.filter_by(id=c_t_db.id).delete()
            db.session.commit()

    ## Clusters
    case_cluster_db = Case_Galaxy_Tags.query.filter_by(case_id=case.id).all()
    for clusters in form_dict["clusters"]:
        cluster = CommonModel.get_cluster_by_name(clusters)

        if not clusters in case_cluster_db:
            case_galaxy_tag = Case_Galaxy_Tags(
                cluster_id=cluster.id,
                case_id=case.id
            )
            db.session.add(case_galaxy_tag)
            db.session.commit()
    
    for c_t_db in case_cluster_db:
        if not c_t_db in form_dict["clusters"]:
            Case_Galaxy_Tags.query.filter_by(id=c_t_db.id).delete()
            db.session.commit()

    CommonModel.update_last_modif(cid)
    db.session.commit()

    CommonModel.save_history(case.uuid, current_user, f"Case edited")


def add_orgs_case(form_dict, cid, current_user):
    """Add orgs to case in th DB"""
    for org_id in form_dict["org_id"]:
        case_org = Case_Org(
            case_id=cid, 
            org_id=org_id
        )
        db.session.add(case_org)
        case = CommonModel.get_case(cid)
        NotifModel.create_notification_org(f"{CommonModel.get_org(org_id).name} add to case: '{case.id}-{case.title}'", cid, org_id, html_icon="fa-solid fa-sitemap", current_user=current_user)

    CommonModel.update_last_modif(cid)
    db.session.commit()
    case = CommonModel.get_case(cid)
    CommonModel.save_history(case.uuid, current_user, f"Org {org_id} added")
    return True


def remove_org_case(case_id, org_id, current_user):
    """Remove an org from a case"""
    case_org = Case_Org.query.filter_by(case_id=case_id, org_id=org_id).first()
    if case_org:
        db.session.delete(case_org)

        case = CommonModel.get_case(case_id)
        NotifModel.create_notification_org(f"{CommonModel.get_org(org_id).name} removed from case: '{case.id}-{case.title}'", case_id, org_id, html_icon="fa-solid fa-door-open", current_user=current_user)

        CommonModel.update_last_modif(case_id)
        db.session.commit()
        case = CommonModel.get_case(case_id)
        CommonModel.save_history(case.uuid, current_user, f"Org {org_id} removed")
        return True
    return False


def get_present_in_case(case_id, user):
    """Return if current user is present in a case"""
    orgs_in_case = CommonModel.get_orgs_in_case(case_id)

    present_in_case = False
    for org in orgs_in_case:
        if org.id == user.org_id:
            present_in_case = True

    return present_in_case


def change_status_core(status, case, current_user):
    case.status_id = status
    CommonModel.update_last_modif(case.id)
    db.session.commit()
    CommonModel.save_history(case.uuid, current_user, "Case Status changed")

    return True


def regroup_case_info(cases, user, nb_pages=None):
    loc = dict()
    loc["cases"] = list()
    
    for case in cases:
        present_in_case = get_present_in_case(case.id, user)
        case_loc = case.to_json()
        case_loc["present_in_case"] = present_in_case
        case_loc["current_user_permission"] = CommonModel.get_role(user).to_json()

        loc["cases"].append(case_loc)
    if nb_pages:
        loc["nb_pages"] = nb_pages
    else:
        try:
            loc["nb_pages"] = cases.pages
        except:
            pass

    return loc


def build_case_query(page, completed, tags=None, taxonomies=None, galaxies=None, clusters=None, filter=None):
    query = Case.query
    conditions = [Case.completed == completed]

    if tags or taxonomies:
        query = query.join(Case_Tags, Case_Tags.case_id == Case.id)
        query = query.join(Tags, Case_Tags.tag_id == Tags.id)
        if tags:
            tags = ast.literal_eval(tags)
            conditions.append(Tags.name.in_(list(tags)))

        if taxonomies:
            taxonomies = ast.literal_eval(taxonomies)
            query = query.join(Taxonomy, Taxonomy.id == Tags.taxonomy_id)
            conditions.append(Taxonomy.name.in_(list(taxonomies)))

    if clusters or galaxies:
        query = query.join(Case_Galaxy_Tags, Case_Galaxy_Tags.case_id == Case.id)
        query = query.join(Cluster, Case_Galaxy_Tags.cluster_id == Cluster.id)
        if clusters:
            clusters = ast.literal_eval(clusters)
            conditions.append(Cluster.name.in_(list(clusters)))

        if galaxies:
            galaxies = ast.literal_eval(galaxies)
            query = query.join(Galaxy, Galaxy.id == Cluster.galaxy_id)
            conditions.append(Galaxy.name.in_(list(galaxies)))

    if filter:
        query.order_by(desc(filter))
    
    return query.filter(and_(*conditions)).paginate(page=page, per_page=25, max_per_page=50)


def sort_by_status(page, taxonomies=[], galaxies=[], tags=[], clusters=[], or_and_taxo="true", or_and_galaxies="true", completed=False):
    cases = build_case_query(page, completed, tags, taxonomies, galaxies, clusters)

    if tags:
        tags = ast.literal_eval(tags)
    if taxonomies:
        taxonomies = ast.literal_eval(taxonomies)

    if galaxies:
        galaxies = ast.literal_eval(galaxies)
    if clusters:
        clusters = ast.literal_eval(clusters)

    if tags or taxonomies or galaxies or clusters:
        if or_and_taxo == "false":
            glob_list = []

            for case in cases:
                tags_db = case.to_json()["tags"]
                loc_tag = [tag["name"] for tag in tags_db]
                taxo_list = [Taxonomy.query.get(tag["taxonomy_id"]).name for tag in tags_db]

                if (not tags or all(item in loc_tag for item in tags)) and \
                (not taxonomies or all(item in taxo_list for item in taxonomies)):
                    glob_list.append(case)

            cases = glob_list
        if or_and_galaxies == "false":
            glob_list = []

            for case in cases:
                clusters_db = case.to_json()["clusters"]
                loc_cluster = [cluster["name"] for cluster in clusters_db]
                galaxies_list = [Galaxy.query.get(cluster["galaxy_id"]).name for cluster in clusters_db]

                if (not clusters or all(item in loc_cluster for item in clusters)) and \
                (not galaxies or all(item in galaxies_list for item in galaxies)):
                    glob_list.append(case)

            cases = glob_list
    else:
        cases = Case.query.filter_by(completed=completed).paginate(page=page, per_page=25, max_per_page=50)
    return cases


def sort_by_filter(filter, page, taxonomies=[], galaxies=[], tags=[], clusters=[], or_and_taxo="true", or_and_galaxies="true", completed=False):
    cases = build_case_query(page, completed, tags, taxonomies, galaxies, clusters, filter)
    nb_pages = cases.pages
    if tags:
        tags = ast.literal_eval(tags)
    if taxonomies:
        taxonomies = ast.literal_eval(taxonomies)

    if galaxies:
        galaxies = ast.literal_eval(galaxies)
    if clusters:
        clusters = ast.literal_eval(clusters)

    if tags or taxonomies or galaxies or clusters:
        if or_and_taxo == "false":
            glob_list = []

            for case in cases:
                tags_db = case.to_json()["tags"]
                loc_tag = [tag["name"] for tag in tags_db]
                taxo_list = [Taxonomy.query.get(tag["taxonomy_id"]).name for tag in tags_db]

                if (not tags or all(item in loc_tag for item in tags)) and \
                (not taxonomies or all(item in taxo_list for item in taxonomies)):
                    glob_list.append(case)

            cases = glob_list
        if or_and_galaxies == "false":
            glob_list = []

            for case in cases:
                clusters_db = case.to_json()["clusters"]
                loc_cluster = [cluster["name"] for cluster in clusters_db]
                galaxies_list = [Galaxy.query.get(cluster["galaxy_id"]).name for cluster in clusters_db]

                if (not clusters or all(item in loc_cluster for item in clusters)) and \
                (not galaxies or all(item in galaxies_list for item in galaxies)):
                    glob_list.append(case)

            cases = glob_list
    else:
        cases = Case.query.filter_by(completed=completed).order_by(desc(filter)).paginate(page=page, per_page=25, max_per_page=50)
        nb_pages = cases.pages

    # for deadline filter, only case with a deadline defined is required
    loc = list()
    for case in cases:
        if getattr(case, filter):
            loc.append(case)
    return loc, nb_pages


def fork_case_core(cid, case_title_fork, user):
    case_title_stored = CommonModel.get_case_by_title(case_title_fork)
    if case_title_stored:
        return {"message": "Error, title already exist"}
    case = CommonModel.get_case(cid)

    case_json = case.to_json()
    case_json["title"] = case_title_fork

    if case.deadline:
        case_json["deadline_date"] = datetime.datetime.strptime(case_json["deadline"].split(" ")[0], "%Y-%m-%d").date()
        case_json["deadline_time"] = datetime.datetime.strptime(case_json["deadline"].split(" ")[1], "%H:%M").time()
    else:
        case_json["deadline_date"] = None
        case_json["deadline_time"] = None

    new_case = create_case(case_json, user)

    for task in case.tasks:
        task_json = task.to_json()
        if task.deadline:
            task_json["deadline_date"] = datetime.datetime.strptime(task_json["deadline"].split(" ")[0], "%Y-%m-%d").date()
            task_json["deadline_time"] = datetime.datetime.strptime(task_json["deadline"].split(" ")[1], "%H:%M").time()
        else:
            task_json["deadline_date"] = None
            task_json["deadline_time"] = None

        TaskModel.create_task(task_json, new_case.id, user)
    return new_case


def create_template_from_case(cid, case_title_template):
    if Case_Template.query.filter_by(title=case_title_template).first():
        return {"message": "Error, title already exist"}
    
    case = CommonModel.get_case(cid)
    new_template = Case_Template(
        uuid=str(uuid.uuid4()),
        title=case_title_template,
        description=case.description
    )
    db.session.add(new_template)
    db.session.commit()

    for c_t in Case_Tags.query.filter_by(case_id=case.id).all():
        case_tag = Case_Template_Tags(
            case_id=new_template.id,
            tag_id=c_t.tag_id
        )
        db.session.add(case_tag)
        db.session.commit()

    for c_t in Case_Galaxy_Tags.query.filter_by(case_id=case.id).all():
        case_cluster = Case_Template_Galaxy_Tags(
            template_id=new_template.id,
            cluster_id=c_t.cluster_id
        )
        db.session.add(case_cluster)
        db.session.commit()

    for task in case.tasks:
        task_exist = Task_Template.query.filter_by(title=task.title).first()
        if not task_exist:
            task_template = Task_Template(
                uuid=str(uuid.uuid4()),
                title=task.title,
                description=task.description,
                url=task.url
            )
            db.session.add(task_template)
            db.session.commit()

            ## Tags
            for t_t in Task_Tags.query.filter_by(task_id=task.id).all():
                task_tag = Task_Template_Tags(
                    task_id=task_template.id,
                    tag_id=t_t.tag_id
                )
                db.session.add(task_tag)
                db.session.commit()

            ## Clusters
            for t_t in Task_Galaxy_Tags.query.filter_by(task_id=task.id).all():
                task_cluster = Task_Template_Galaxy_Tags(
                    template_id=task_template.id,
                    cluster_id=t_t.cluster_id
                )
                db.session.add(task_cluster)
                db.session.commit()

            ## Task Connectors
            for t_c in Task_Connector_Instance.query.filter_by(task_id=task.id).all():
                task_connector = Task_Template_Connector_Instance(
                    template_id=task_template.id,
                    instance_id=t_c.instance_id
                )
                db.session.add(task_connector)
                db.session.commit()

            case_task_template = Case_Task_Template(
                    case_id=new_template.id,
                    task_id=task_template.id
                )
            db.session.add(case_task_template)
            db.session.commit()
        else:
            case_task_template = Case_Task_Template(
                    case_id=new_template.id,
                    task_id=task_exist.id
                )
            db.session.add(case_task_template)
            db.session.commit()

    return new_template


def change_recurring(form_dict, cid, current_user):
    case = CommonModel.get_case(cid)
    recurring_status = Status.query.filter_by(name="Recurring").first()
    created_status = Status.query.filter_by(name="Created").first()

    if "once" in form_dict and form_dict["once"]:
        case.recurring_type = "once"
        case.recurring_date = form_dict["once"]
        case.status_id = recurring_status.id
    elif "daily" in form_dict and form_dict["daily"]:
        case.recurring_type = "daily"
        case.recurring_date = datetime.datetime.today() + datetime.timedelta(days=1)
        case.status_id = recurring_status.id
    elif "weekly" in form_dict and form_dict["weekly"]:
        case.recurring_type = "weekly"
        if form_dict["weekly"]<datetime.datetime.today().date():
            case.recurring_date = datetime.datetime.today() + datetime.timedelta(
                days=(form_dict["weekly"].weekday() - datetime.datetime.today().weekday() + 7)
                )
        else:
            case.recurring_date = form_dict["weekly"]
        case.status_id = recurring_status.id
    elif "monthly" in form_dict and form_dict["monthly"]:
        case.recurring_type = "monthly"
        if form_dict["monthly"]<datetime.datetime.today().date():
            case.recurring_date = form_dict["monthly"] + relativedelta.relativedelta(months=1)
        else:
            case.recurring_date = form_dict["monthly"]
        case.status_id = recurring_status.id
    elif "remove" in form_dict and form_dict["remove"]:
        case.recurring_type = None
        case.recurring_date = None
        case.status_id = created_status.id

        for notif in Recurring_Notification.query.filter_by(case_id=cid).all():
            db.session.delete(notif)
            db.session.commit()
    else:
        return False

    db.session.commit()
    CommonModel.save_history(case.uuid, current_user, "Recurring changed")
    return True


def notify_user(task, user_id):
    case = CommonModel.get_case(task.case_id)
    message = f"Notify for task '{task.id}-{task.title}' of case '{case.id}-{case.title}'"
    NotifModel.create_notification_user(message, task.case_id, user_id=user_id, html_icon="fa-solid fa-bell")
    return True


def notify_user_recurring(form_dict, case_id, orgs):
    for org in orgs:
        if f"check_{org.id}" in form_dict:
            for user in org.users:
                if not Recurring_Notification.query.filter_by(case_id=case_id, user_id=user.id).first():
                    rec_notif = Recurring_Notification(case_id=case_id, user_id=user.id)
                    db.session.add(rec_notif)
                    db.session.commit()
        else:
            for user in org.users:
                if f"check_{org.id}_user_{user.id}" in form_dict:
                    if not Recurring_Notification.query.filter_by(case_id=case_id, user_id=user.id).first():
                        rec_notif = Recurring_Notification(case_id=case_id, user_id=user.id)
                        db.session.add(rec_notif)
                        db.session.commit()
                else:
                    notif = Recurring_Notification.query.filter_by(case_id=case_id, user_id=user.id).first()
                    if notif:
                        db.session.delete(notif)
                        db.session.commit()


def get_modules():
    return MODULES_CONFIG

def get_instance_module_core(module, user_id):
    connector = CommonModel.get_connector_by_name(MODULES_CONFIG[module]["config"]["connector"])
    instance_list = list()
    for instance in connector.instances:
        if CommonModel.get_user_instance_both(user_id=user_id, instance_id=instance.id):
            instance_list.append(instance.to_json())
    return  instance_list
