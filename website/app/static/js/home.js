import {message_list} from './toaster.js'

const {createApp, ref, computed, watch, nextTick} = Vue

createApp({
    delimiters: ['[[', ']]'],
    setup() {
        let nextId = 1
        const entries = ref([{id: nextId++, value: ''}])
        const modules = ref([])
        const attributes = ref([])
        const attribute = ref('')
        const selected = ref([])
        const search = ref('')
        const customConfig = ref(false)
        const config = ref({})
        const configErrors = ref({})
        const loading = ref(true)
        const load_error = ref('')
        const submitting = ref(false)
        const attempted = ref(false)
        const status = ref('')
        const errorBox = ref(null)
        const indicatorCount = computed(() => entries.value.filter(entry => entry.value.trim()).length)
        const hasIndicators = computed(() => indicatorCount.value > 0)
        const commonAttributes = computed(() => ['domain', 'ip-dst', 'url', 'sha256', 'email-src'].filter(type => attributes.value.includes(type)))
        const compatibleModules = computed(() => modules.value.filter(module => {
            const inputs = module.mispattributes?.input || []
            return inputs.includes(attribute.value) || (attribute.value === 'ip' && (inputs.includes('ip-src') || inputs.includes('ip-dst')))
        }))
        const filteredModules = computed(() => {
            const term = search.value.trim().toLowerCase()
            return compatibleModules.value.filter(module => `${module.name} ${module.meta.description || ''}`.toLowerCase().includes(term))
        })
        const configModules = computed(() => modules.value.filter(module => selected.value.includes(module.name) && module.meta.config?.length && (customConfig.value || module.request_on_query)))
        watch(attribute, () => {
            selected.value = []
            search.value = ''
            configErrors.value = {}
            status.value = ''
        })
        watch(configModules, list => {
            for (const module of list) {
                if (!config.value[module.name]) config.value[module.name] = {}
            }
        }, {flush: 'sync'})

        async function readJSON(url, options) {
            const response = await fetch(url, options)
            let data
            try { data = await response.json() } catch { throw new Error('The server returned an unreadable response. Please try again.') }
            if (!response.ok) throw new Error(data.message || `Request failed (${response.status}).`)
            return data
        }

        async function loadModules() {
            loading.value = true
            load_error.value = ''
            try {
                const [moduleData, attributeData] = await Promise.all([readJSON('/get_modules'), readJSON('/get_list_misp_attributes')])
                if (!Array.isArray(moduleData) || !Array.isArray(attributeData)) throw new Error('The module service is unavailable. Check that misp-modules is running.')
                modules.value = moduleData.sort((a, b) => a.name.localeCompare(b.name))
                attributes.value = [...new Set(attributeData)].sort()
                if (!moduleData.length) load_error.value = 'No active enrichment modules were found. Check the module service and configuration.'
            } catch (error) {
                load_error.value = error.message
            } finally {
                loading.value = false
            }
        }

        async function restoreQuery() {
            try {
                const data = await readJSON('/get_query')
                if (Array.isArray(data.query) && data.query.length) entries.value = data.query.map(value => ({id: nextId++, value: String(value)}))
            } catch {
                // A previous query is optional; the new query form remains usable.
            }
        }

        async function addEntry() {
            entries.value.push({id: nextId++, value: ''})
            await nextTick()
            document.getElementById(`indicator-${entries.value.at(-1).id}`)?.focus()
        }
        function removeEntry(index) {
            if (entries.value.length > 1) entries.value.splice(index, 1)
        }
        function selectVisible() {
            selected.value = [...new Set([...selected.value, ...filteredModules.value.map(module => module.name)])]
        }
        function isSecret(key) { return /key|token|secret|password/i.test(key) }
        async function showError(message) {
            status.value = message
            await nextTick()
            errorBox.value?.focus()
        }
        async function runQuery() {
            if (submitting.value || loading.value || load_error.value) return
            attempted.value = true
            status.value = ''
            configErrors.value = {}
            const query = entries.value.map(entry => entry.value.trim()).filter(Boolean)
            if (!query.length) return showError('Add at least one indicator to start an enrichment.')
            if (!attribute.value) return showError('Choose a MISP attribute type for your indicators.')
            if (!selected.value.length) return showError('Select at least one enrichment module.')
            const queryConfig = {}
            for (const module of configModules.value) {
                queryConfig[module.name] = {}
                for (const key of module.meta.config) {
                    const value = config.value[module.name]?.[key] || ''
                    if (!value.trim()) configErrors.value[`${module.name} / ${key}`] = true
                    else queryConfig[module.name][key] = value
                }
            }
            if (Object.keys(configErrors.value).length) return showError('Complete the required module configuration below the module list.')
            submitting.value = true
            try {
                const data = await readJSON('/run_modules', {
                    method: 'POST',
                    headers: {'X-CSRFToken': document.getElementById('csrf_token').value, 'Content-Type': 'application/json'},
                    body: JSON.stringify({query, input: attribute.value, modules: selected.value, config: queryConfig, parent_id: document.getElementById('parent_id').value})
                })
                if (!data.id) throw new Error('The server did not return a query ID. Please try again.')
                window.location.assign(`/query/${encodeURIComponent(data.id)}`)
            } catch (error) {
                await showError(error.message)
                submitting.value = false
            }
        }
        loadModules()
        restoreQuery()
        return {message_list, entries, modules, attributes, attribute, selected, search, customConfig, config, configErrors, loading, load_error, submitting, attempted, status, errorBox, indicatorCount, hasIndicators, commonAttributes, compatibleModules, filteredModules, configModules, loadModules, addEntry, removeEntry, selectVisible, isSecret, runQuery}
    }
}).mount('.container-fluid')
