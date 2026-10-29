import {message_list} from './toaster.js'

const {createApp, ref, computed, watch, nextTick} = Vue

createApp({
    delimiters: ['[[', ']]'],
    setup() {
        const modules = ref([])
        const moduleName = ref('')
        const source = ref('file')
        const file = ref(null)
        const feeds = ref([])
        const feed = ref('')
        const events = ref([])
        const event = ref('')
        const search = ref('')
        const page = ref(1)
        const total = ref(0)
        const feedLoading = ref(false)
        const feedError = ref('')
        const selectedEvent = computed(() => events.value.find(item => item.uuid === event.value))
        let feedRequest = 0
        const options = ref({})
        const config = ref({})
        const overrideConfig = ref(false)
        const loading = ref(true)
        const submitting = ref(false)
        const loadError = ref('')
        const error = ref('')
        const errorBox = ref(null)
        const activeModule = computed(() => modules.value.find(module => module.name === moduleName.value))
        const userFields = computed(() => activeModule.value?.mispattributes.userConfig || {})
        const serverFields = computed(() => (overrideConfig.value || activeModule.value?.request_on_query)
            ? (activeModule.value?.meta.config || []).filter(key => !Object.hasOwn(userFields.value, key)) : [])
        watch(moduleName, () => {
            config.value = {}
            error.value = ''
            overrideConfig.value = false
            options.value = Object.fromEntries(Object.entries(userFields.value).map(([key, field]) =>
                [key, field.type === 'Boolean' ? String(field.checked).toLowerCase() === 'true' : '']))
        }, {flush: 'sync'})
        watch(source, () => { file.value = null; error.value = '' })
        watch(feed, () => { search.value = ''; loadEvents(1) })
        async function loadEvents(targetPage = 1) {
            const currentRequest = ++feedRequest
            events.value = []
            event.value = ''
            feedError.value = ''
            page.value = targetPage
            total.value = 0
            if (!feed.value) { feedLoading.value = false; return }
            feedLoading.value = true
            try {
                const params = new URLSearchParams({feed: feed.value, search: search.value, page: String(targetPage)})
                const result = await readJSON('/export_feed_events?' + params)
                if (currentRequest !== feedRequest) return
                events.value = result.events
                total.value = result.total
            } catch (failure) { if (currentRequest === feedRequest) feedError.value = failure.message }
            finally { if (currentRequest === feedRequest) feedLoading.value = false }
        }
        async function loadFeeds() {
            try { feeds.value = await readJSON('/export_feeds') }
            catch (failure) { error.value = failure.message }
        }
        function isSecret(key) { return /key|token|secret|password/i.test(key) }
        async function readJSON(url, settings) {
            const response = await fetch(url, settings)
            let result
            try { result = await response.json() } catch { throw new Error('The server returned an unreadable response. Please try again.') }
            if (!response.ok) throw new Error(result.message || `Request failed (${response.status}).`)
            return result
        }
        async function loadModules() {
            loading.value = true
            loadError.value = ''
            try {
                const result = await readJSON('/get_export_modules')
                if (!Array.isArray(result)) throw new Error('The module service is unavailable. Check that misp-modules is running.')
                modules.value = result
            } catch (failure) { loadError.value = failure.message }
            finally { loading.value = false }
        }
        async function runExport() {
            if (submitting.value || !activeModule.value) return
            error.value = ''
            try {
                if (source.value === 'file' && !file.value) throw new Error('Choose a MISP JSON file to export.')
                if (source.value === 'file' && file.value.size > 20 * 1024 * 1024) throw new Error('MISP JSON must be at most 20 MiB.')
                if (source.value === 'feed' && (!feed.value || !event.value || feedLoading.value || feedError.value)) throw new Error('Select an event from an OSINT feed.')
                const queryConfig = Object.fromEntries(Object.entries(options.value).map(([key, value]) =>
                    [key, typeof value === 'boolean' ? (value ? '1' : '0') : String(value ?? '')]))
                for (const key of serverFields.value) {
                    if (config.value[key]?.trim()) queryConfig[key] = config.value[key]
                }
                const body = new FormData()
                body.set('module', moduleName.value)
                body.set('source', source.value)
                body.set('config', JSON.stringify(queryConfig))
                if (source.value === 'file') body.set('file', file.value)
                if (source.value === 'feed') { body.set('feed', feed.value); body.set('event', event.value) }
                submitting.value = true
                const result = await readJSON('/run_export', {method: 'POST', headers: {'X-CSRFToken': document.getElementById('csrf_token').value}, body})
                if (!result.id) throw new Error('The server did not return a query ID. Please try again.')
                window.location.assign(`/query/${encodeURIComponent(result.id)}`)
            } catch (failure) {
                error.value = failure.message
                submitting.value = false
                await nextTick()
                errorBox.value?.focus()
            }
        }
        loadModules()
        loadFeeds()
        return {message_list, modules, moduleName, source, file, feeds, feed, events, event, search, page, total, feedLoading, feedError, selectedEvent, loadEvents, options, config, overrideConfig, loading, submitting, loadError, error, errorBox, activeModule, userFields, serverFields, isSecret, loadModules, runExport}
    }
}).mount('.container-fluid')
