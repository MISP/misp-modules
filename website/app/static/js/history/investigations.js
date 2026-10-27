import {message_list} from '../toaster.js'
import InvestigationNode from './history_view.js'
import {normalizeNode, summarize, filterPath, matchingQueries, visit} from './tree_utils.js'
const {createApp, ref, computed, watch, nextTick} = Vue
const saved = document.getElementById('investigation-workspace').dataset.saved === 'true'
createApp({
    delimiters: ['[[', ']]'], components: {InvestigationNode},
    setup() {
        const roots = ref([]), selectedId = ref(''), search = ref(''), collapsed = ref(new Set())
        const loading = ref(false), error = ref(''), feedback = ref(''), busy = ref(''), pendingRemoval = ref('')
        const savedIds = ref(new Set()), errorBox = ref(null), feedbackBox = ref(null)
        const overview = computed(() => roots.value.reduce((total, root) => {
            const stats = summarize(root)
            return {queries: total.queries + stats.queries, depth: Math.max(total.depth, stats.depth)}
        }, {queries: 0, depth: 0}))
        const filteredRoots = computed(() => {
            const term = search.value.trim().toLowerCase()
            return term ? roots.value.map(root => filterPath(root, term)).filter(Boolean) : roots.value
        })
        const selectedRoot = computed(() => filteredRoots.value.find(root => root.uuid === selectedId.value))
        const matchCount = computed(() => filteredRoots.value.reduce((total, root) => total + matchingQueries(root), 0))
        watch(filteredRoots, list => { if (!list.some(root => root.uuid === selectedId.value)) selectedId.value = list[0]?.uuid || '' }, {flush: 'sync'})
        watch(search, () => { pendingRemoval.value = '' })
        async function readJSON(url) {
            const response = await fetch(url)
            let data
            try { data = await response.json() } catch { throw new Error('The server returned an unreadable response. Please try again.') }
            if (!response.ok || String(data?.toast_class || '').startsWith('danger')) throw new Error(data?.message || `Request failed (${response.status}).`)
            return data
        }
        async function loadHistory() {
            if (loading.value || busy.value) return
            loading.value = true; error.value = ''
            try {
                const data = await readJSON(saved ? '/get_history_tree' : '/get_history_session')
                if (!Array.isArray(data) && (!data || typeof data !== 'object' || Object.keys(data).length)) throw new Error('The server returned an unreadable investigation list.')
                roots.value = Array.isArray(data) ? data.map((root, index) => normalizeNode(root, index + 1)) : []
                return true
            } catch (failure) { error.value = failure.message; return false }
            finally { loading.value = false }
        }
        function selectRoot(id) { selectedId.value = id; pendingRemoval.value = ''; feedback.value = '' }
        function toggleBranch(id) { if (collapsed.value.has(id)) collapsed.value.delete(id); else collapsed.value.add(id) }
        function expandAll() { collapsed.value.clear() }
        function collapseAll() {
            if (selectedRoot.value) visit(selectedRoot.value, node => { if (node.children.length) collapsed.value.add(node.uuid) })
            pendingRemoval.value = ''
        }
        async function requestRemoval(id) { pendingRemoval.value = id; await nextTick(); document.querySelector('[data-removal-confirmation]')?.focus() }
        async function cancelRemoval(id) {
            pendingRemoval.value = ''; await nextTick()
            document.getElementById('path-' + encodeURIComponent(selectedId.value) + '-' + encodeURIComponent(id) + '-remove')?.focus()
        }
        async function showError(message) { error.value = message; await nextTick(); errorBox.value?.focus() }
        async function saveTree() {
            if (busy.value || !selectedId.value) return
            busy.value = 'save'; error.value = ''; feedback.value = ''
            try {
                await readJSON('/save_history/' + encodeURIComponent(selectedId.value))
                savedIds.value.add(selectedId.value)
                feedback.value = 'Investigation saved. Find it in Investigation trees.'
            } catch (failure) { await showError(failure.message) }
            finally { busy.value = '' }
        }
        async function removeNode(id) {
            if (busy.value) return
            busy.value = id; error.value = ''; feedback.value = ''
            try {
                await readJSON('/history/remove_node_' + (saved ? 'tree/' : 'session/') + encodeURIComponent(id) + '?root_id=' + encodeURIComponent(selectedId.value))
                pendingRemoval.value = ''; busy.value = ''
                // Reload server state; never splice a neighboring filtered root.
                if (!await loadHistory()) return
                feedback.value = 'Branch removed from this investigation. Enrichment results are kept.'
                await nextTick(); feedbackBox.value?.focus()
            } catch (failure) { await showError(failure.message) }
            finally { busy.value = '' }
        }
        loadHistory()
        return {message_list, roots, selectedId, search, collapsed, loading, error, feedback, busy, pendingRemoval, savedIds, errorBox, feedbackBox, overview, filteredRoots, selectedRoot, matchCount, summarize, loadHistory, selectRoot, toggleBranch, expandAll, collapseAll, requestRemoval, cancelRemoval, saveTree, removeNode}
    },
}).mount('.container-fluid')
