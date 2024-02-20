export default {
	name: "History_view",
	delimiters: ['[[', ']]'],
	props: {
		history: Object,
	},

	template: `
        <li><a :href="'/query/'+history.uuid" :title="'Attribute: \\n' +history.input+ '\\n\\nModules: \\n' + history.modules">[[history.query]]</a></li>
        <ul>
            <template v-for="child in history.children">
                <history_view :history="child"></history_view>
            </template>
        </ul>
	`
}