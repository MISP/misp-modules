
export default {
	name: "History_view",
	delimiters: ['[[', ']]'],
	props: {
		history: Object,
		key_loop: Number
	},

	template: `
	<div style="display: flex;">
		<div style="list-style-type: none; padding: 10px; font-size: large; margin-left: 13px" >
			<a v-if="'children' in history && history['children'].length" data-bs-toggle="collapse" style="color: black;" :href="'#collapseChild-'+history.uuid" role="button" aria-expanded="true" :aria-controls="'collapseChild-'+history.uuid">
				<i class="fa-solid fa-caret-down"></i>
			</a>
		</div>
		<a style="text-decoration: none; color: black;" data-bs-toggle="collapse" :href="'#collapse'+history.uuid" role="button" aria-expanded="false" :aria-controls="'collapse'+history.uuid">
			<ul class="list-group list-group-horizontal" style="padding-top: 5px;">
				<li class="list-group-item">
					<h5>[[history.query]]</h5>
				</li>
				<li class="list-group-item">
					<h5 style="color: brown"><u>Input Attributes</u></h5>
					[[history.input]]
				</li>
				<li class="list-group-item">
					<h5 style="color: brown"><u>Modules</u></h5>
					<template v-for="module in history.modules">[[module]],</template>
				</li>
			</ul
		</a>
	</div>
	<div>
		<div class="collapse" :id="'collapse'+history.uuid" style="width: 70%; margin-left: 30px">
			<div class="card card-body">
				<div class="d-flex w-100 justify-content-between">
					<h5 class="mb-1">[[history.query]]</h5>
					<small><i>[[history.uuid]]</i></small>
				</div>
				<p class="mb-1" style="color: green;"><u>Input Attribute</u>:</p>
				<div>[[history.input]]</div>
				<br>
				<p class="mb-1" style="color: #2000ff;"><u>Modules</u>:</p>
				<div>
					<template v-for="module in history.modules">[[module]],</template>
				</div>
				<div></div>
				<div class="d-flex w-100 justify-content-between">
					<div><a :href="'/query/'+history.uuid">See results</a></div>
					<small><i>[[history.query_date]]</i></small>
				</div>
			</div>
		</div>

		<div class="collapse show" :id="'collapseChild-'+history.uuid">
			<ul style="list-style-type: none;">
				<li>
					<div class="card-body">
						<template v-for="h, key in history['children']">
							<history_view :history="h" :key_loop="key" />
						</template>
					</div>
				</li>
			</ul>
		</div>
	</div>
	`
}