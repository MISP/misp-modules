import {display_toast} from '../toaster.js'
const { ref, nextTick, computed } = Vue
export default {
	delimiters: ['[[', ']]'],
	props: {
		cases_info: Object,
		status_info: Object,
		users_in_case: Object,
		edit_mode: Boolean,
		task: Object,
		key_loop: Number
	},
	emits: ['edit_mode', 'task'],
	setup(props, {emit}) {
		Vue.onMounted(async () => {
			select2_change(props.task.id)
			
			const targetElement = document.getElementById('editor_' + props.task.id)
			editor = new Editor.EditorView({
				doc: "\n\n",
				extensions: [Editor.basicSetup, Editor.markdown(),Editor.EditorView.updateListener.of((v) => {
					if (v.docChanged) {
						note_editor_render.value = editor.state.doc.toString()
					}
				})],
				parent: targetElement
			})

			const allCollapses = document.getElementById('collapse' + props.task.id)
			allCollapses.addEventListener('shown.bs.collapse', event => {
				md.mermaid.init()
			})
			is_mounted.value = true
		})
		Vue.onUpdated(async () => {
			select2_change(props.task.id)
			// do not initialize mermaid before the page is mounted
			if(is_mounted)
				md.mermaid.init()
		})

		const is_mounted = ref(false)
		const is_exporting = ref(false)

		const notes = ref(props.task.notes)
		const note_editor_render = ref("")
		let editor
		const md = window.markdownit()
		md.use(mermaidMarkdown.default)

		if(props.task.notes)
			note_editor_render.value = props.task.notes
		

		async function change_status(status, task){
			const res = await fetch(
				'/case/' + task.case_id + '/change_task_status/'+task.id,{
					headers: { "X-CSRFToken": $("#csrf_token").val(), "Content-Type": "application/json" },
					method: "POST",
					body: JSON.stringify({"status": status})
				}
			)
			if(await res.status==200){
				task.last_modif = Date.now()
				task.status_id=status
					
				if(props.status_info.status[status-1].name == 'Finished'){
					task.last_modif = Date.now()
					task.completed = true
					fetch('/case/complete_task/'+task.id)
				}else{
					task.completed = false
				}
			}
			await display_toast(res)
		}

		async function take_task(task, current_user){
			const res = await fetch('/case/' + task.case_id + '/take_task/' + task.id)

			if( await res.status == 200){
				task.last_modif = Date.now()
				task.is_current_user_assigned = true
				task.users.push(current_user)
			}
			await display_toast(res)
		}

		async function remove_assign_task(task, current_user){
			const res = await fetch('/case/' + task.case_id + '/remove_assignment/' + task.id)

			if( await res.status == 200){
				task.last_modif = Date.now()
				task.is_current_user_assigned = false
	
				let index = -1
	
				for(let i=0;i<task.users.length;i++){
					if (task.users[i].id==current_user.id)
						index = i
				}
	
				if(index > -1)
					task.users.splice(index, 1)
			}
			await display_toast(res)
		}


		async function assign_user_task(){
			let users_select = $('#selectUser'+props.task.id).val()
			if(users_select.length){
				const res_msg = await fetch(
					'/case/' + props.task.case_id + '/assign_users/' + props.task.id,{
						headers: { "X-CSRFToken": $("#csrf_token").val(), "Content-Type": "application/json" },
						method: "POST",
						body: JSON.stringify({"users_id": users_select})
					}
				)
				if( await res_msg.status == 200){
					if(users_select.includes(props.cases_info.current_user.id.toString())){
						props.task.is_current_user_assigned = true
					}
					const res = await fetch('/case/' + props.task.case_id + '/get_assigned_users/' +props.task.id)
					if(await res.status == 404){
						display_toast(res)
					}else{
						let loc = await res.json()
						props.task.users = loc
						props.task.last_modif = Date.now()
						emit('task', props.task)
					}
				}
				await display_toast(res_msg)
			}
		}


		async function remove_assigned_user(user_id){
			const res = await fetch(
				'/case/' + props.task.case_id + '/remove_assigned_user/' + props.task.id,{
					headers: { "X-CSRFToken": $("#csrf_token").val(), "Content-Type": "application/json" },
					method: "POST",
					body: JSON.stringify({"user_id": user_id})
				}
			)

			if( await res.status == 200){
				props.task.last_modif = Date.now()

				let index = -1
				for(let i=0;i<props.task.users.length;i++){
					if (props.task.users[i].id==user_id){
						if(user_id == props.cases_info.current_user.id.toString()){
							props.task.is_current_user_assigned = true
						}
						props.task.is_current_user_assigned = false
						index = i
					}
				}

				if(index > -1)
					props.task.users.splice(index, 1)
			}
			await display_toast(res)
		}


		async function delete_task(task, task_array){
			const res = await fetch('/case/' + task.case_id + '/delete_task/' + task.id)

			if( await res.status == 200){
				let index = task_array.indexOf(task)
				if(index > -1)
					task_array.splice(index, 1)
			}
			await display_toast(res)
		}

		async function edit_note(task){
			task.last_modif = Date.now()
			emit('edit_mode', true)

			const res = await fetch('/case/' + task.case_id + '/get_note/' + task.id)
			let loc = await res.json()
			task.notes = loc["note"]

			const targetElement = document.getElementById('editor1_' + props.task.id)
			editor = new Editor.EditorView({
				doc: task.notes,
				extensions: [Editor.basicSetup, Editor.markdown(),Editor.EditorView.updateListener.of((v) => {
					if (v.docChanged) {
						note_editor_render.value = editor.state.doc.toString()
					}
				})],
				parent: targetElement
			})
			
		}

		async function modif_note(task){
			let notes_loc = editor.state.doc.toString()
			if(notes_loc.trim().length == 0){
				notes_loc = notes_loc.trim()
			}
			const res_msg = await fetch(
				'/case/' + task.case_id + '/modif_note/' + task.id,{
					headers: { "X-CSRFToken": $("#csrf_token").val(), "Content-Type": "application/json" },
					method: "POST",
					body: JSON.stringify({"task_id": task.id.toString(), "notes": notes_loc})
				}
			)

			if(await res_msg.status == 200){
				emit('edit_mode', false)
				task.last_modif = Date.now()
				task.notes = notes_loc
				notes.value = notes_loc
				await nextTick()
				
				if(!notes_loc){
					const targetElement = document.getElementById('editor_' + props.task.id)
					if(targetElement.innerHTML === ""){
						editor = new Editor.EditorView({
							doc: "\n\n",
							extensions: [Editor.basicSetup, Editor.markdown(),Editor.EditorView.updateListener.of((v) => {
								if (v.docChanged) {
									note_editor_render.value = editor.state.doc.toString()
								}
							})],
							parent: targetElement
						})
					}
				}
			}
			await display_toast(res_msg)
		}


		async function add_file(task){
			let files = document.getElementById('formFileMultiple'+task.id).files

			let formData = new FormData();
			for(let i=0;i<files.length;i++){
				formData.append("files"+i, files[i]);
			}

			const res = await fetch(
				'/case/' + task.case_id + '/add_files/' + task.id,{
					headers: { "X-CSRFToken": $("#csrf_token").val() },
					method: "POST",
					files: files,
					body: formData
				}
			)
			if(await res.status == 200){
				const res_files = await fetch('/case/' + task.case_id + '/get_files/'+task.id)

				if(await res_files.status == 200){
					task.last_modif = Date.now()
					let loc = await res_files.json()
					task.files = []
					for(let file in loc['files']){
						task.files.push(loc['files'][file])
					}
				}else{
					await display_toast(res_files)
				}
			}

			await display_toast(res)
		}

		async function delete_file(file, task){
			const res = await fetch('/case/task/' + task.id + '/delete_file/' + file.id)
			if(await res.status == 200){
				task.last_modif = Date.now()

				let index = task.files.indexOf(file)
				if(index > -1)
					task.files.splice(index, 1)
			}
			await display_toast(res)
		}

		async function complete_task(task){
			const res = await fetch('/case/complete_task/'+task.id)
			if (await res.status == 200){
				task.last_modif = Date.now()
				task.completed = !task.completed
				let status = task.status_id
				if(props.status_info.status[task.status_id -1].name == 'Finished'){
					for(let i in props.status_info.status){
						if(props.status_info.status[i].name == 'Created')
							task.status_id = props.status_info.status[i].id
					}
					if(task.status_id == status)
						task.status_id = 1

				}else{
					for(let i in props.status_info.status){
						if(props.status_info.status[i].name == 'Finished'){
							task.status_id = props.status_info.status[i].id
							break
						}
					}
				}
				let index = props.cases_info.tasks.indexOf(task)
				if(index > -1)
					props.cases_info.tasks.splice(index, 1)
			}
			await display_toast(res)
		}

		async function notify_user(user_id){
			const res = await fetch(
				'/case/' + props.task.case_id + '/task/' + props.task.id + '/notify_user',{
					headers: { "X-CSRFToken": $("#csrf_token").val(), "Content-Type": "application/json" },
					method: "POST",
					body: JSON.stringify({"task_id": props.task.id, "user_id": user_id})
				}
			)
			await display_toast(res)
		}

		function formatNow(dt) {
			return moment.utc(dt).from(moment.utc())
		}

		function endOf(dt){
			return moment.utc(dt).endOf().from(moment.utc())
		}


		function present_user_in_task(task_user_list, user){
			let index = -1

			for(let i=0;i<task_user_list.length;i++){
				if (task_user_list[i].id==user.id)
					index = i
			}

			return index
		}

		async function export_notes(task, type){
			is_exporting.value = true
			let filename = ""
			await fetch('/case/'+task.case_id+'/task/'+task.id+'/export_notes?type=' + type)
			.then(res =>{
				filename = res.headers.get("content-disposition").split("=")
				filename = filename[filename.length - 1]
				return res.blob() 
			})
			.then(data =>{
				var a = document.createElement("a")
				a.href = window.URL.createObjectURL(data);
				a.download = filename;
				a.click();
			})
			is_exporting.value = false
		}

		function select2_change(tid){
			$('.select2-selectUser'+tid).select2({width: 'element'})
			$('.select2-container').css("min-width", "200px")
		}
		

		return {
			notes,
			note_editor_render,
			md,
			is_exporting,
			getTextColor,
			mapIcon,
			change_status,
			take_task,
			remove_assign_task,
			assign_user_task,
			remove_assigned_user,
			delete_task,
			edit_note,
			modif_note,
			add_file,
			delete_file,
			complete_task,
			notify_user,
			formatNow,
			endOf,
			export_notes,
			present_user_in_task
		}
	},
	template: `
	<div style="display: flex;">                          
		<a :href="'#collapse'+task.id" class="list-group-item list-group-item-action" data-bs-toggle="collapse" role="button" aria-expanded="false" :aria-controls="'collapse'+task.id">
			<div class="d-flex w-100 justify-content-between">
				<h5 class="mb-1">[[ key_loop ]]- [[task.title]]</h5>
				<small><i>Changed [[ formatNow(task.last_modif) ]] </i></small>
			</div>

			<div class="d-flex w-100 justify-content-between">
				<p v-if="task.description" class="card-text">[[ task.description ]]</p>
				<p v-else class="card-text"><i style="font-size: 12px;">No description</i></p>

				<small v-if="status_info">
					<span :class="'badge rounded-pill text-bg-'+status_info.status[task.status_id -1].bootstrap_style">
						[[ status_info.status[task.status_id -1].name ]]
					</span>
				</small>
			</div>
			
			<div class="d-flex w-100 justify-content-between">
				<div style="display: flex;" v-if="task.tags">
					<template v-for="tag in task.tags">
						<div class="tag" :title="tag.description" :style="{'background-color': tag.color, 'color': getTextColor(tag.color)}">
							<i class="fa-solid fa-tag" style="margin-right: 3px; margin-left: 3px;"></i>
							[[tag.name]]
						</div>
					</template>
				</div>
				<div v-else></div>
			</div>

			<div class="d-flex w-100 justify-content-between">
                <div v-if="task.users.length">
                    Users: 
                    <template v-for="user in task.users">
                        [[user.first_name]] [[user.last_name]],
                    </template>
                </div>

                <div v-else>
                    <i>No user assigned</i>
                </div>
                <small v-if="task.deadline" :title="task.deadline"><i>Deadline [[endOf(task.deadline)]]</i></small>
                <small v-else><i>No deadline</i></small>
            </div>
			<div class="d-flex w-100 justify-content-between">
				<div style="display: flex;" v-if="task.clusters">
					<template v-for="cluster in task.clusters">
						<div :title="'Description:\\n' + cluster.description + '\\n\\nMetadata:\\n' + JSON.stringify(JSON.parse(cluster.meta), null, 4)">
							<span v-html="mapIcon(cluster.icon)"></span>
							[[cluster.tag]]
						</div>
					</template>
				</div>
				<div v-else></div>
			</div>
		</a>
		<div v-if="!cases_info.permission.read_only && cases_info.present_in_case || cases_info.permission.admin" style="display: grid;">
			<button v-if="task.completed" class="btn btn-secondary btn-sm"  @click="complete_task(task)" title="Revive the task">
				<i class="fa-solid fa-backward"></i>
			</button>
			<button v-else class="btn btn-success btn-sm" @click="complete_task(task)" title="Complete the task">
				<i class="fa-solid fa-check"></i>
			</button>
			<button v-if="!task.is_current_user_assigned" class="btn btn-secondary btn-sm" @click="take_task(task, cases_info.current_user)" title="Be assigned to the task">
				<i class="fa-solid fa-hand"></i>
			</button>
			<button v-else class="btn btn-secondary btn-sm" @click="remove_assign_task(task, cases_info.current_user)" title="Remove the assignment">
				<i class="fa-solid fa-handshake-slash"></i>
			</button>
			<a class="btn btn-primary btn-sm" :href="'/case/'+cases_info.case.id+'/edit_task/'+task.id" type="button" title="Edit the task">
				<i class="fa-solid fa-pen-to-square"></i>
			</a>
			<button class="btn btn-danger btn-sm" @click="delete_task(task, cases_info.tasks)" title="Delete the task">
				<i class="fa-solid fa-trash"></i>
			</button>
		</div>
	</div>

	
	<!-- Collapse Part -->
	<div class="collapse collapsetest" :id="'collapse'+task.id">
		<div class="card card-body" style="background-color: whitesmoke;">
			<div class="d-flex w-100 justify-content-between">
				<div v-if="!cases_info.permission.read_only && cases_info.present_in_case || cases_info.permission.admin">
					<div v-if="users_in_case">
						<h5>Assign</h5>
						<select data-placeholder="Users" multiple :class="'select2-selectUser'+task.id" :name="'selectUser'+task.id" :id="'selectUser'+task.id" style="min-width:200px">
							<template v-for="user in users_in_case.users_list">
								<option :value="user.id" v-if="present_user_in_task(task.users, user) == -1">[[user.first_name]] [[user.last_name]]</option>
							</template>
						</select>
						<button class="btn btn-primary" @click="assign_user_task()">Assign</button>
					</div>

					<div v-if="task.users.length">
						<h5>Remove assign</h5>
						<div v-for="user in task.users">
							<span style="margin-right: 5px">[[user.first_name]] [[user.last_name]]</span>
							<button v-if="cases_info.current_user.id != user.id" class="btn btn-primary btn-sm" @click="notify_user(user.id)"><i class="fa-solid fa-bell"></i></button>
							<button class="btn btn-danger btn-sm" @click="remove_assigned_user(user.id)"><i class="fa-solid fa-trash"></i></button>
						</div>
					</div>
				</div>
				<div v-if="!cases_info.permission.read_only && cases_info.present_in_case || cases_info.permission.admin">
					<div>
						<h5>Change Status</h5>
					</div>
					<div>
						<div class="dropdown" :id="'dropdown_status_'+task.id">
							<template v-if="status_info">
								<button class="btn btn-secondary dropdown-toggle" :id="'button_'+task.id" type="button" data-bs-toggle="dropdown" aria-expanded="false">
									[[ status_info.status[task.status_id -1].name ]]
								</button>
								<ul class="dropdown-menu" :id="'dropdown_ul_status_'+task.id">
									<template v-for="status_list in status_info.status">
										<li v-if="status_list.id != task.status_id">
											<button class="dropdown-item" @click="change_status(status_list.id, task)">[[ status_list.name ]]</button>
										</li>
									</template>
								</ul>
							</template>
						</div>
					</div>
				</div>
			</div>
			<hr>
			<div class="d-flex w-100 justify-content-between">
				<div v-if="task.url">
					<div>
						<h5>Tool/Url</h5>
					</div>
					<div>
						[[task.url]]
					</div>
				</div>
				<div v-if="task.instances.length">
					<div>
						<h5>Connectors</h5>
					</div>
					<div v-for="instance in task.instances" :title="instance.description">
						<img :src="'/static/icons/'+instance.icon" style="max-width: 30px;">
						<a style="margin-left: 5px" :href="instance.url">[[instance.url]]</a>
					</div>
				</div>
			</div>
			<hr>
			<div class="d-flex w-100 justify-content-between">
				<div>
					<div>
						<h5>Files</h5>
					</div>
					<div>
						<input class="form-control" type="file" :id="'formFileMultiple'+task.id" multiple/>
						<button class="btn btn-primary" @click="add_file(task)">Add</button>
					</div>
					<br/>
					<template v-if="task.files.length">
						<template v-for="file in task.files">
							<div>
								<a class="btn btn-link" :href="'/case/task/'+task.id+'/download_file/'+file.id">
									[[ file.name ]]
								</a>
								<button class="btn btn-danger" @click="delete_file(file, task)"><i class="fa-solid fa-trash"></i></button>
							</div>
						</template>
					</template>
				</div>
			</div>
			<hr>
			<div class="d-flex w-100 justify-content-between">
				<div class="w-100">
					<div>
						<h5>Notes</h5>
					</div>
					<div v-if="task.notes">
						<template v-if="edit_mode">
							<div>
								<button class="btn btn-primary" @click="modif_note(task)" type="button" :id="'note_'+task.id">
									<div hidden>[[task.title]]</div>
									Save
								</button>
							</div>
							<div style="display: flex;">
								<div style="background-color: white; border-width: 1px; border-style: solid; width: 50%" :id="'editor1_'+task.id"></div>
								<div style="background-color: white; border: 1px #515151 solid; padding: 5px; width: 50%" v-html="md.render(note_editor_render)"></div>
							</div>
						</template>
						<template v-else>
							<template v-if="!cases_info.permission.read_only && cases_info.present_in_case || cases_info.permission.admin">
								<button class="btn btn-primary" @click="edit_note(task)" type="button" :id="'note_'+task.id">
									<div hidden>[[task.title]]</div>
									Edit
								</button>
								<div class="btn-group">
									<button class="btn btn-primary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
										Export
									</button>
									<ul class="dropdown-menu">
										<li>
											<button v-if="!is_exporting" class="btn btn-link" @click="export_notes(task, 'pdf')" title="Export markdown as pdf">PDF</button>
											<button v-else class="btn btn-link" disabled>
												<span class="spinner-border spinner-border-sm" aria-hidden="true"></span>
												<span role="status">Loading...</span>
											</button>
										</li>
										<li>
											<button v-if="!is_exporting" class="btn btn-link" @click="export_notes(task, 'docx')" title="Export markdown as docx">DOCX</button>
											<button v-else class="btn btn-link" disabled>
												<span class="spinner-border spinner-border-sm" aria-hidden="true"></span>
												<span role="status">Loading...</span>
											</button>
										</li>
									</ul>
								</div>

							</template> 
							<p style="background-color: white; border: 1px #515151 solid; padding: 5px;" v-html="md.render(notes)"></p>
						</template>
					</div>
					<div v-else>
						<template v-if="!cases_info.permission.read_only && cases_info.present_in_case || cases_info.permission.admin">
							<div>
								<button class="btn btn-primary" @click="modif_note(task)" type="button" :id="'note_'+task.id">
									<div hidden>[[task.title]]</div>
									Create
								</button>
							</div>
							<div style="display: flex;">
								<div style="background-color: white; border-width: 1px; border-style: solid; width: 50%" :id="'editor_'+task.id"></div>
								<div style="background-color: white; border: 1px #515151 solid; padding: 5px; width: 50%" v-html="md.render(note_editor_render)"></div>
							</div>
						</template>
					</div>
				</div>
			</div>
		</div>
	</div>
	`
}