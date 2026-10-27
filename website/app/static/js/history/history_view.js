const {computed} = Vue
export default {
    name: 'InvestigationNode',
    delimiters: ['[[', ']]'],
    props: {
        node: {type: Object, required: true}, scope: {type: String, required: true},
        depth: {type: Number, default: 0}, parentQuery: {type: String, default: ''}, parentId: {type: String, default: ''},
        collapsed: {type: Set, required: true}, searching: Boolean, busy: Boolean, pendingRemoval: String,
    },
    emits: ['toggle', 'remove-request', 'remove-cancel', 'remove-confirm'],
    setup(props) {
        const nodeId = computed(() => 'path-' + encodeURIComponent(props.scope) + '-' + encodeURIComponent(props.node.uuid))
        const expanded = computed(() => props.searching || !props.collapsed.has(props.node.uuid))
        const branchSize = computed(() => props.node.totalQueries)
        return {nodeId, expanded, branchSize}
    },
    template: `
    <li class="investigation-node" :class="{'depth-limit': depth >= 2}" :data-depth="depth">
        <article class="path-query-card" :class="{'search-match': searching && node.match}" :id="nodeId">
            <div class="path-query-topline"><span class="path-query-step"><i :class="depth === 0 ? 'fa-solid fa-circle-dot' : 'fa-solid fa-code-branch'" aria-hidden="true"></i>[[depth === 0 ? 'Starting query' : 'Pivot · Step '+(depth+1)]]</span><span v-if="searching" class="path-match-label">[[node.match ? 'Match' : 'Parent path']]</span><time v-if="node.query_date" :datetime="node.query_date.replace(' ', 'T')">[[node.query_date]]</time></div>
            <h3><a :href="'/query/'+encodeURIComponent(node.uuid)">[[node.query.join(', ')]]</a></h3>
            <a v-if="parentQuery" :href="'#'+parentId" class="path-parent"><i class="fa-solid fa-arrow-turn-up" aria-hidden="true"></i>From [[parentQuery]]</a>
            <div class="path-query-metadata"><span class="path-attribute"><i class="fa-solid fa-fingerprint" aria-hidden="true"></i>[[node.input]]</span><span v-for="module in node.modules" :key="module" class="path-module">[[module]]</span></div>
            <div class="path-query-actions"><button v-if="node.children.length" type="button" class="path-branch-toggle" @click="$emit('toggle', node.uuid)" :aria-expanded="expanded" :aria-controls="nodeId+'-children'" :disabled="searching"><i :class="expanded ? 'fa-solid fa-chevron-down' : 'fa-solid fa-chevron-right'" aria-hidden="true"></i>[[node.children.length]] [[node.children.length === 1 ? 'branch' : 'branches']]</button><span v-else class="path-leaf"><i class="fa-solid fa-check" aria-hidden="true"></i>End of path</span><a :href="'/query/'+encodeURIComponent(node.uuid)" class="path-results-link">View results <i class="fa-solid fa-arrow-right" aria-hidden="true"></i></a><button type="button" class="path-remove" :id="nodeId+'-remove'" :aria-label="'Remove query '+node.query.join(', ')" @click="$emit('remove-request', node.uuid)" :disabled="busy"><i class="fa-solid fa-trash-can" aria-hidden="true"></i></button></div>
            <div v-if="pendingRemoval === node.uuid" class="path-removal-confirmation" role="group" aria-label="Confirm branch removal" tabindex="-1" data-removal-confirmation><p><strong>Remove [[branchSize === 1 ? 'this query' : 'this branch of '+branchSize+' queries']] from this investigation?</strong><span>Enrichment results remain available. Other branches are kept.</span></p><div><button type="button" class="btn btn-sm btn-outline-secondary" @click="$emit('remove-cancel', node.uuid)" :disabled="busy">Cancel</button><button type="button" class="btn btn-sm btn-danger" @click="$emit('remove-confirm', node.uuid)" :disabled="busy">[[busy ? 'Removing…' : 'Remove branch']]</button></div></div>
        </article>
        <ol v-if="node.children.length" v-show="expanded" :id="nodeId+'-children'" class="path-children"><investigation-node v-for="child in node.children" :key="child.uuid" :node="child" :scope="scope" :depth="depth+1" :parent-query="node.query.join(', ')" :parent-id="nodeId" :collapsed="collapsed" :searching="searching" :busy="busy" :pending-removal="pendingRemoval" @toggle="$emit('toggle', $event)" @remove-request="$emit('remove-request', $event)" @remove-cancel="$emit('remove-cancel', $event)" @remove-confirm="$emit('remove-confirm', $event)" /></ol>
    </li>`,
}
