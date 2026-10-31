import {message_list, display_toast} from './toaster.js'
const {createApp, ref, computed, nextTick} = Vue
createApp({
    delimiters: ['[[', ']]'],
    setup() {
        const modules = ref([]), search = ref(''), filter = ref('all'), current = ref(null)
        const loading = ref(true), error = ref(''), pending = ref([]), values = ref({})
        const requestConfig = ref(false), saving = ref(false), saved = ref(false), saveError = ref('')
        const filteredModules = computed(() => {
            const term = search.value.trim().toLowerCase()
            return modules.value.filter(module => {
                const active = module.is_active !== false
                return (filter.value === 'all' || (filter.value === 'enabled' ? active : !active)) && `${module.name} ${module.description || ''} ${(module.input_attr || []).join(' ')}`.toLowerCase().includes(term)
            })
        })
        async function readJSON(response) {
            const data = await response.json()
            if (!response.ok) throw new Error(data.message || `Request failed (${response.status}).`)
            return data
        }
        async function loadModules() {
            loading.value = true
            error.value = ''
            try {
                const data = await readJSON(await fetch('/modules_config_data'))
                if (!Array.isArray(data)) throw new Error('Unable to read the module configuration.')
                modules.value = data
            } catch (failure) { error.value = failure.message }
            finally { loading.value = false }
        }
        async function openModule(module) {
            if (saving.value) return
            current.value = module
            values.value = Object.assign({}, ...module.config)
            requestConfig.value = !!module.request_on_query
            saved.value = false
            saveError.value = ''
            await nextTick()
            if (window.matchMedia('(max-width: 767px)').matches) document.getElementById('config-title')?.focus()
        }
        async function closeModule() {
            const id = current.value?.id
            current.value = null
            await nextTick()
            document.getElementById('module-' + id)?.focus()
        }
        async function toggleModule(module, event) {
            const checkbox = event.target
            pending.value.push(module.id)
            try {
                const response = await fetch(`/change_status?module_id=${encodeURIComponent(module.id)}`)
                if (!response.ok) {
                    const data = await response.json()
                    throw new Error(data.message || 'Unable to change module status.')
                }
                module.is_active = module.is_active === false
                await display_toast(response)
            } catch (failure) {
                checkbox.checked = module.is_active !== false
                error.value = failure.message
            } finally { pending.value = pending.value.filter(id => id !== module.id) }
        }
        async function saveConfig() {
            if (saving.value || !current.value) return
            const module = current.value
            saving.value = true
            saved.value = false
            saveError.value = ''
            try {
                await readJSON(await fetch('/change_config', {
                    method: 'POST',
                    headers: {'X-CSRFToken': document.getElementById('csrf_token').value, 'Content-Type': 'application/json'},
                    body: JSON.stringify({result_dict: {...values.value, module_name: module.name, request_on_query: requestConfig.value}})
                }))
                module.config = Object.entries(values.value).map(([key, value]) => ({[key]: value}))
                module.request_on_query = requestConfig.value
                saved.value = true
            } catch (failure) { saveError.value = failure.message }
            finally { saving.value = false }
        }
        function isSecret(key) { return /key|token|secret|password/i.test(key) }
        loadModules()
        return {message_list, modules, search, filter, current, loading, error, pending, values, requestConfig, saving, saved, saveError, filteredModules, loadModules, openModule, closeModule, toggleModule, saveConfig, isSecret}
    }
}).mount('.container-fluid')
