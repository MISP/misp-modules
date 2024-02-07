import os
import ast
import uuid
import shutil
import datetime
import subprocess
from .. import db
from ..db_class.db import *
from ..utils.utils import create_specific_dir

from sqlalchemy import desc, and_
from flask import request, send_file
from werkzeug.utils import secure_filename
from ..notification import notification_core as NotifModel

from . import common_core as CommonModel


UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
FILE_FOLDER = os.path.join(UPLOAD_FOLDER, "files")
TEMP_FOLDER = os.path.join(os.getcwd(), "temp")


def delete_task(tid, current_user):
    """Delete a task by is id"""
    task = CommonModel.get_task(tid)
    if task is not None:
        for file in task.files:
            try:
                os.remove(os.path.join(FILE_FOLDER, file.uuid))
            except:
                return False
            db.session.delete(file)
            db.session.commit()

        case = CommonModel.get_case(task.case_id)
        task_users = Task_User.query.where(Task_User.task_id==task.id).all()
        for task_user in task_users:
            user = User.query.get(task_user.user_id)
            NotifModel.create_notification_user(f"Task '{task.id}-{task.title}' of case '{case.id}-{case.title}' was deleted", task.case_id, user_id=user.id, html_icon="fa-solid fa-trash")

        Task_Tags.query.filter_by(task_id=task.id).delete()
        Task_Galaxy_Tags.query.filter_by(task_id=task.id).delete()
        Task_User.query.filter_by(task_id=task.id).delete()
        Task_Connector_Instance.query.filter_by(task_id=task.id).delete()
        db.session.delete(task)
        CommonModel.update_last_modif(task.case_id)
        db.session.commit()

        CommonModel.save_history(case.uuid, current_user, f"Task '{task.title}' deleted")
        return True
    return False


def complete_task(tid, current_user):
    """Complete task by is id"""
    task = CommonModel.get_task(tid)
    if task is not None:
        task.completed = not task.completed

        case = CommonModel.get_case(task.case_id)
        task_users = Task_User.query.where(Task_User.task_id==task.id).all()
        if task.completed:
            task.status_id = Status.query.filter_by(name="Finished").first().id
            message = f"Task '{task.id}-{task.title}' of case '{case.id}-{case.title}' completed"
        else:
            task.status_id = Status.query.filter_by(name="Created").first().id
            message = f"Task '{task.id}-{task.title}' of case '{case.id}-{case.title}' revived"
        for task_user in task_users:
            user = User.query.get(task_user.user_id)
            if task.completed:
                message = f"Task '{task.id}-{task.title}' of case '{case.id}-{case.title}' completed"
                NotifModel.create_notification_user(message, task.case_id, user_id=user.id, html_icon="fa-solid fa-check")
            else:
                message = f"Task '{task.id}-{task.title}' of case '{case.id}-{case.title}' revived"
                NotifModel.create_notification_user(message, task.case_id, user_id=user.id, html_icon="fa-solid fa-heart-circle-bolt")

        CommonModel.update_last_modif(task.case_id)
        CommonModel.update_last_modif_task(task.id)
        db.session.commit()
        CommonModel.save_history(case.uuid, current_user, f"Task '{task.title}' completed")
        return True
    return False


def create_task(form_dict, cid, current_user):
    """Add a task to the DB"""
    if "template_select" in form_dict and not 0 in form_dict["template_select"]:
        template = Task_Template.query.get(form_dict["template_select"])
        task = Task(
            uuid=str(uuid.uuid4()),
            title=template.title,
            description=template.description,
            url=template.url,
            creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
            last_modif=datetime.datetime.now(tz=datetime.timezone.utc),
            case_id=cid,
            status_id=1
        )
        db.session.add(task)
        db.session.commit()

        for t_t in Task_Template_Tags.query.filter_by(task_id=task.id).all():
            task_tag = Task_Tags(
                task_id=task.id,
                tag_id=t_t.tag_id
            )
            db.session.add(task_tag)
            db.session.commit()

        for t_t in Task_Template_Galaxy_Tags.query.filter_by(task_id=task.id).all():
            task_tag = Task_Galaxy_Tags(
                task_id=task.id,
                cluster_id=t_t.cluster_id
            )
            db.session.add(task_tag)
            db.session.commit()

        for t_t in Task_Template_Connector_Instance.query.filter_by(template_id=task.id).all():
            task_instance = Task_Connector_Instance(
                task_id=task.id,
                instance_id=t_t.instance_id
            )
            db.session.add(task_instance)
            db.session.commit()
    else:
        deadline = CommonModel.deadline_check(form_dict["deadline_date"], form_dict["deadline_time"])

        ## Check if instance is from current user
        for instance in form_dict["connectors"]:
            instance = CommonModel.get_instance_by_name(instance)
            if not CommonModel.get_user_instance_by_instance(instance.id):
                return False

        task = Task(
            uuid=str(uuid.uuid4()),
            title=form_dict["title"],
            description=form_dict["description"],
            url=form_dict["url"],
            creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
            last_modif=datetime.datetime.now(tz=datetime.timezone.utc),
            deadline=deadline,
            case_id=cid,
            status_id=1
        )
        db.session.add(task)
        db.session.commit()

        for tags in form_dict["tags"]:
            tag = CommonModel.get_tag(tags)
            
            task_tag = Task_Tags(
                tag_id=tag.id,
                task_id=task.id
            )
            db.session.add(task_tag)
            db.session.commit()

        for clusters in form_dict["clusters"]:
            cluster = CommonModel.get_cluster_by_name(clusters)
            
            task_galaxy_tag = Task_Galaxy_Tags(
                cluster_id=cluster.id,
                task_id=task.id
            )
            db.session.add(task_galaxy_tag)
            db.session.commit()

        for instance in form_dict["connectors"]:
            instance = CommonModel.get_instance_by_name(instance)
            task_instance = Task_Connector_Instance(
                task_id=task.id,
                instance_id=instance.id
            )
            db.session.add(task_instance)
            db.session.commit()

    CommonModel.update_last_modif(cid)

    case = CommonModel.get_case(cid)
    CommonModel.save_history(case.uuid, current_user, f"Task '{task.title}' Created")

    return task


def edit_task_core(form_dict, tid, current_user):
    """Edit a task to the DB"""
    task = CommonModel.get_task(tid)
    deadline = CommonModel.deadline_check(form_dict["deadline_date"], form_dict["deadline_time"])

    ## Check if instance is from current user
    for instance in form_dict["connectors"]:
        instance = CommonModel.get_instance_by_name(instance)
        if not CommonModel.get_user_instance_by_instance(instance.id):
            return False

    task.title = form_dict["title"]
    task.description=form_dict["description"]
    task.url=form_dict["url"]
    task.deadline=deadline

    ## Tags
    task_tag_db = Task_Tags.query.filter_by(task_id=task.id).all()
    for tags in form_dict["tags"]:
        tag = CommonModel.get_tag(tags)

        if not tags in task_tag_db:
            task_tag = Task_Tags(
                tag_id=tag.id,
                task_id=task.id
            )
            db.session.add(task_tag)
            db.session.commit()
    
    for c_t_db in task_tag_db:
        if not c_t_db in form_dict["tags"]:
            Task_Tags.query.filter_by(id=c_t_db.id).delete()
            db.session.commit()

    ## Clusters
    task_tag_db = Task_Galaxy_Tags.query.filter_by(task_id=task.id).all()
    for clusters in form_dict["clusters"]:
        cluster = CommonModel.get_cluster_by_name(clusters)

        if not clusters in task_tag_db:
            task_tag = Task_Galaxy_Tags(
                cluster_id=cluster.id,
                task_id=task.id
            )
            db.session.add(task_tag)
            db.session.commit()
    
    for c_t_db in task_tag_db:
        if not c_t_db in form_dict["clusters"]:
            Task_Galaxy_Tags.query.filter_by(id=c_t_db.id).delete()
            db.session.commit()
    
    ## Connectors
    task_connector_db = Task_Connector_Instance.query.filter_by(task_id=task.id).all()
    for connectors in form_dict["connectors"]:
        instance = CommonModel.get_instance_by_name(connectors)

        if not connectors in task_connector_db:
            task_tag = Task_Connector_Instance(
                instance_id=instance.id,
                task_id=task.id
            )
            db.session.add(task_tag)
            db.session.commit()
    
    for c_t_db in task_connector_db:
        if not c_t_db in form_dict["connectors"]:
            Task_Connector_Instance.query.filter_by(id=c_t_db.id).delete()
            db.session.commit()

    CommonModel.update_last_modif(task.case_id)
    CommonModel.update_last_modif_task(task.id)
    db.session.commit()

    case = CommonModel.get_case(task.case_id)
    CommonModel.save_history(case.uuid, current_user, f"Task '{task.title}' edited")


def add_file_core(task, files_list, current_user):
    create_specific_dir(UPLOAD_FOLDER)
    create_specific_dir(FILE_FOLDER)
    for file in files_list:
        if files_list[file].filename:
            uuid_loc = str(uuid.uuid4())
            filename = secure_filename(files_list[file].filename)
            try:
                file_data = request.files[file].read()
                with open(os.path.join(FILE_FOLDER, uuid_loc), "wb") as write_file:
                    write_file.write(file_data)
            except Exception as e:
                print(e)
                return False

            f = File(
                name=filename,
                task_id=task.id,
                uuid = uuid_loc
            )
            db.session.add(f)
            CommonModel.update_last_modif(task.case_id)
            CommonModel.update_last_modif_task(task.id)
            db.session.commit()
    case = CommonModel.get_case(task.case_id)
    CommonModel.save_history(case.uuid, current_user, f"File added for task '{task.title}'")
    return True

def modif_note_core(tid, current_user, notes):
    """Modify a noe of a task to the DB"""
    task = CommonModel.get_task(tid)
    if task:
        task.notes = notes
        CommonModel.update_last_modif(task.case_id)
        CommonModel.update_last_modif_task(task.id)
        db.session.commit()
        case = CommonModel.get_case(task.case_id)
        CommonModel.save_history(case.uuid, current_user, f"Notes for '{task.title}' modified")
        return True
    return False


def assign_task(tid, user, current_user, flag_current_user):
    """Assign current user to a task"""
    task = CommonModel.get_task(tid)
    case = CommonModel.get_case(task.case_id)
    if task:
        if type(user) == str or type(user) == int:
            user = User.query.get(user)

        task_user = Task_User(task_id=task.id, user_id=user.id)
        if not flag_current_user:
            NotifModel.create_notification_user(f"You have been assign to: '{task.id}-{task.title}' of case '{case.id}-{case.title}'", task.case_id, user_id=user.id, html_icon="fa-solid fa-hand")
   
        if not Task_User.query.filter_by(task_id=task.id, user_id=user.id).first():
            db.session.add(task_user)
            CommonModel.update_last_modif(task.case_id)
            CommonModel.update_last_modif_task(task.id)
            db.session.commit()
            CommonModel.save_history(case.uuid, current_user, f"Task '{task.id}-{task.title}' assigned to {user.first_name} {user.last_name}")
            return True
        return False
    return False

def get_users_assign_task(task_id, user):
    """Return users assigned to a task"""
    task_users = Task_User.query.filter_by(task_id=task_id).all()
    users = list()
    flag = False
    for task_user in task_users:
        u = User.query.get(task_user.user_id)
        # if current user is assigned to the task
        if u.id == user.id:
            flag = True
        users.append(u.to_json())
    return users, flag


def remove_assign_task(tid, user, current_user, flag_current_user):
    """Remove current user to the assignement to a task"""
    task = CommonModel.get_task(tid)
    case = CommonModel.get_case(task.case_id)
    if task:
        if type(user) == int or type(user) == str:
            user = User.query.get(user)
        task_users = Task_User.query.filter_by(task_id=task.id, user_id=user.id).all()
        if not flag_current_user:
            NotifModel.create_notification_user(f"Your assignment have been removed: '{task.id}-{task.title}' of case '{case.id}-{case.title}'", task.case_id, user_id=user.id, html_icon="fa-solid fa-handshake-slash")
        
        for task_user in task_users:
            db.session.delete(task_user)

        CommonModel.update_last_modif(task.case_id)
        CommonModel.update_last_modif_task(task.id)
        db.session.commit()
        CommonModel.save_history(case.uuid, current_user, f"Assignment '{task.title}' removed to {user.first_name} {user.last_name}")
        return True
    return False


def change_task_status(status, task, current_user):
    task.status_id = status
    CommonModel.update_last_modif(task.case_id)
    CommonModel.update_last_modif_task(task.id)
    db.session.commit()

    case = CommonModel.get_case(task.case_id)
    CommonModel.save_history(case.uuid, current_user, f"Status changed for task '{task.title}'")

    return True


def download_file(file):
    return send_file(os.path.join(FILE_FOLDER, file.uuid), as_attachment=True, download_name=file.name)


def delete_file(file, task, current_user):
    try:
        os.remove(os.path.join(FILE_FOLDER, file.uuid))
    except:
        return False

    db.session.delete(file)
    db.session.commit()
    case = CommonModel.get_case(task.case_id)
    CommonModel.save_history(case.uuid, current_user, f"File deleted for task '{task.title}'")
    return True


def get_task_info(tasks_list, user):
    tasks = list()
    for task in tasks_list:
        case = CommonModel.get_case(task.case_id)
        users, is_current_user_assigned = get_users_assign_task(task.id, user)
        file_list = list()
        for file in task.files:
            file_list.append(file.to_json())
        finalTask = task.to_json()
        finalTask["users"] = users
        finalTask["is_current_user_assigned"] = is_current_user_assigned
        finalTask["files"] = file_list
        finalTask["case_title"] = case.title

        finalTask["instances"] = list()
        for task_connector in CommonModel.get_task_connectors(task.id):
            loc_instance = CommonModel.get_instance(task_connector.instance_id).to_json()
            loc_instance["icon"] = Icon_File.query.join(Connector_Icon, Connector_Icon.file_icon_id==Icon_File.id)\
                                            .join(Connector, Connector.icon_id==Connector_Icon.id)\
                                            .join(Connector_Instance, Connector_Instance.connector_id==Connector.id)\
                                            .where(Connector_Instance.id==task_connector.instance_id)\
                                            .first().uuid
            finalTask["instances"].append(loc_instance)

        tasks.append(finalTask)
    return tasks


def build_task_query(completed, tags=None, taxonomies=None, galaxies=None, clusters=None, filter=None):
    query = Task.query
    conditions = [Task.completed == completed]

    if tags or taxonomies:
        query = query.join(Task_Tags, Task_Tags.task_id == Task.id)
        query = query.join(Tags, Task_Tags.tag_id == Tags.id)
        if tags:
            tags = ast.literal_eval(tags)
            conditions.append(Tags.name.in_(list(tags)))

        if taxonomies:
            taxonomies = ast.literal_eval(taxonomies)
            query = query.join(Taxonomy, Taxonomy.id == Tags.taxonomy_id)
            conditions.append(Taxonomy.name.in_(list(taxonomies)))

    if clusters or galaxies:
        query = query.join(Task_Galaxy_Tags, Task_Galaxy_Tags.task_id == Task.id)
        query = query.join(Cluster, Task_Galaxy_Tags.cluster_id == Cluster.id)
        if clusters:
            clusters = ast.literal_eval(clusters)
            conditions.append(Cluster.name.in_(list(clusters)))

        if galaxies:
            galaxies = ast.literal_eval(galaxies)
            query = query.join(Galaxy, Galaxy.id == Cluster.galaxy_id)
            conditions.append(Galaxy.name.in_(list(galaxies)))

    if filter:
        query.order_by(desc(filter))
    
    return query.filter(and_(*conditions)).all()

def sort_by_status_task_core(case, user, taxonomies=[], galaxies=[], tags=[], clusters=[], or_and_taxo="true", or_and_galaxies="true", completed=False, no_info=False, filter=False):
    tasks = build_task_query(completed, tags, taxonomies, galaxies, clusters, filter)

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

            for task in tasks:
                tags_db = task.to_json()["tags"]
                loc_tag = [tag["name"] for tag in tags_db]
                taxo_list = [Taxonomy.query.get(tag["taxonomy_id"]).name for tag in tags_db]

                if (not tags or all(item in loc_tag for item in tags)) and \
                (not taxonomies or all(item in taxo_list for item in taxonomies)):
                    glob_list.append(task)

            tasks = glob_list
        if or_and_galaxies == "false":
            glob_list = []

            for task in tasks:
                clusters_db = task.to_json()["clusters"]
                loc_cluster = [cluster["name"] for cluster in clusters_db]
                galaxies_list = [Galaxy.query.get(cluster["galaxy_id"]).name for cluster in clusters_db]

                if (not clusters or all(item in loc_cluster for item in clusters)) and \
                (not galaxies or all(item in galaxies_list for item in galaxies)):
                    glob_list.append(task)

            tasks = glob_list
    else:
        tasks = Task.query.filter_by(case_id=case.id, completed=completed).all()

    if no_info:
        return tasks
    return get_task_info(tasks, user)


def sort_tasks_by_filter(case, user, filter, taxonomies=[], galaxies=[], tags=[], clusters=[], or_and_taxo="true", or_and_galaxies="true", completed=False):
    tasks_list = sort_by_status_task_core(case, user, taxonomies, galaxies, tags, clusters, or_and_taxo, or_and_galaxies, completed, no_info=True, filter=filter)

    loc_list = list()
    if filter == "assigned_tasks":
        for task in tasks_list:
            if Task_User.query.filter_by(task_id=task.id).first():
                loc_list.append(task)
        tasks_list = loc_list

    elif filter == "my_assignment":
        for task in tasks_list:
            if Task_User.query.filter_by(task_id=task.id, user_id=user.id).first():
                task.is_current_user_assigned = True
                loc_list.append(task)
        tasks_list = loc_list

    elif filter == "deadline":
        # for deadline filter, only task with a deadline defined is required
        loc = list()
        for task in tasks_list:
            if getattr(task, filter):
                loc.append(task)
        tasks_list = loc
    else:
        # status, last_modif, title
        tasks_list.sort(key=lambda x: getattr(x, filter))

    return get_task_info(tasks_list, user)


def export_notes(task, type_req):
    if not os.path.isdir(TEMP_FOLDER):
        os.mkdir(TEMP_FOLDER)

    download_filename = f"export_note_task_{task.id}.{type_req}"
    temp_md = os.path.join(TEMP_FOLDER, "index.md")
    temp_export = os.path.join(TEMP_FOLDER, f"output.{type_req}")

    with open(temp_md, "w")as write_file:
        write_file.write(task.notes)
    if type_req == "pdf":
        process = subprocess.Popen(["pandoc", temp_md, "--pdf-engine=xelatex", "-V", "colorlinks=true", "-V", "linkcolor=blue", "-V", "urlcolor=red", "-V", "tocolor=gray"\
                                    "--number-sections", "--toc", "--template", "eisvogel", "-o", temp_export, "--filter=pandoc-mermaid"], stdout=subprocess.PIPE)
    elif type_req == "docx":
        process = subprocess.Popen(["pandoc", temp_md, "-o", temp_export, "--filter=mermaid-filter"], stdout=subprocess.PIPE)
    process.wait()

    try:
        shutil.rmtree(os.path.join(os.getcwd(), "mermaid-images"))
    except:
        pass
    
    return send_file(temp_export, as_attachment=True, download_name=download_filename)