import {message_list} from './toaster.js'

const {createApp, ref, computed, watch, nextTick} = Vue

createApp({
    delimiters: ['[[', ']]'],
    setup() {
        const modules = ref([])
        const moduleName = ref('')
        const source = ref('config')
        const file = ref(null)
        const data = ref('')
        const options = ref({})
        const config = ref({})
        const overrideConfig = ref(false)
        const loading = ref(true)
        const submitting = ref(false)
        const loadError = ref('')
        const error = ref('')
        const errorBox = ref(null)
        const activeModule = computed(() => modules.value.find(module => module.name === moduleName.value))
        const sources = computed(() => activeModule.value?.mispattributes.inputSource || [])
        const userFields = computed(() => activeModule.value?.mispattributes.userConfig || {})
        const serverFields = computed(() => (overrideConfig.value || activeModule.value?.request_on_query)
            ? (activeModule.value?.meta.config || []).filter(key => !Object.hasOwn(userFields.value, key)) : [])
        watch(moduleName, () => {
            source.value = sources.value[0] || 'config'
            file.value = null
            data.value = ''
            config.value = {}
            error.value = ''
            overrideConfig.value = false
            options.value = Object.fromEntries(Object.entries(userFields.value).map(([key, field]) =>
                [key, field.type === 'Boolean' ? String(field.checked).toLowerCase() === 'true' : '']))
        }, {flush: 'sync'})
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
                const result = await readJSON('/get_import_modules')
                if (!Array.isArray(result)) throw new Error('The module service is unavailable. Check that misp-modules is running.')
                modules.value = result
            } catch (failure) { loadError.value = failure.message }
            finally { loading.value = false }
        }
        async function runImport() {
            if (submitting.value || !activeModule.value) return
            error.value = ''
            try {
                if (source.value === 'file' && !file.value) throw new Error('Choose a file to import.')
                if (source.value === 'file' && file.value.size > 20 * 1024 * 1024) throw new Error('Import data must be at most 20 MiB.')
                if (source.value === 'paste' && !data.value.trim()) throw new Error('Paste data to import.')
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
                if (source.value === 'paste') body.set('data', data.value)
                submitting.value = true
                const result = await readJSON('/run_import', {method: 'POST', headers: {'X-CSRFToken': document.getElementById('csrf_token').value}, body})
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
        return {message_list, modules, moduleName, source, file, data, options, config, overrideConfig, loading, submitting, loadError, error, errorBox, activeModule, sources, userFields, serverFields, isSecret, loadModules, runImport}
    }
}).mount('.container-fluid')
