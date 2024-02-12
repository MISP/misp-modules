
const { ref, nextTick } = Vue
export default {
	name: "History_view",
	delimiters: ['[[', ']]'],
	props: {
		history: Object,
		key_loop: Number
	},
	setup(props) {
		
		

		return {

		}
	},
	template: `
	<div class="list-group" style="margin-bottom: 20px;">
		<a :href="'/query/'+history.uuid" class="list-group-item list-group-item-action">
			<div class="d-flex w-100 justify-content-between">
				<h5 class="mb-1">[[key_loop+1]]- [[history.query]]</h5>
				<small><i>[[history.uuid]]</i></small>
			</div>
			<p class="mb-1" style="color: green;"><u>Input Attribute</u>:</p>
			<div>[[history.input]]</div>
			<br>
			<p class="mb-1" style="color: #2000ff;"><u>Modules</u>:</p>
			<div>
				<template v-for="module in history.modules">[[module]],</template>
			</div>

			
			<div class="d-flex w-100 justify-content-between">
				<div></div>
				<small><i>[[history.query_date]]</i></small>
			</div>
		</a>
	</div>	

	`
}