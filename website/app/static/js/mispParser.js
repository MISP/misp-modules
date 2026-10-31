// These renderers return a jQuery element because the result view inserts its
// outerHTML with Vue's v-html. Values always enter the DOM as text or attributes.
function mispDisplayValue(value) {
    if (value === null) return 'null'
    if (typeof value === 'object') return JSON.stringify(value, null, 2)
    return String(value ?? '')
}

function mispDisplayLabel(value) {
    const names = {'ip-dst': 'Destination IP', 'ip-src': 'Source IP', sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5', datetime: 'Date and time', counter: 'Count'}
    if (Object.hasOwn(names, value)) return names[value]
    const label = String(value || 'Attribute').replace(/[_-]/g, ' ')
    if (['url', 'ip', 'dns', 'http', 'tls'].includes(label.toLowerCase())) return label.toUpperCase()
    return label.charAt(0).toUpperCase() + label.slice(1)
}

function mispResultIcon(name) {
    return $('<i>').addClass('fa-solid ' + name).attr('aria-hidden', 'true')
}

function mispResultActions(value, types, queryUrl, callback) {
    const text = mispDisplayValue(value)
    const $actions = $('<div>').addClass('enrichment-field-actions')
    const $copy = $('<button>').attr({type: 'button', 'data-enrichment-action': 'copy', 'data-value': text})
        .addClass('enrichment-action').append(mispResultIcon('fa-copy'), $('<span>').text('Copy value'))
    $actions.append($copy)
    if (!types.some(type => ['counter', 'datetime'].includes(type))) {
        if (queryUrl) {
            $actions.append($('<a>').attr({href: queryUrl + encodeURIComponent(text), title: 'Start a related enrichment with a different attribute or modules'})
                .addClass('enrichment-action').append(mispResultIcon('fa-magnifying-glass-plus'), $('<span>').text('Choose modules')))
        }
        if (callback) {
            $actions.append($('<button>').attr({type: 'button', 'data-enrichment-action': 'query', 'data-value': text, 'data-callback': '_' + callback.name,
                title: 'Enrich this value using the original query’s attribute type and modules'})
                .addClass('enrichment-action').append(mispResultIcon('fa-arrow-rotate-right'), $('<span>').text('Run same modules')))
        }
    }
    return $actions
}

function mispResultTypes(types) {
    const $badges = $('<span>').addClass('enrichment-type-list')
    for (const type of types) $badges.append($('<span>').addClass('enrichment-type').text(type))
    return $badges
}

function mispResultField(attribute, queryUrl, callback) {
    const types = Array.isArray(attribute.types) ? attribute.types : [attribute.type || 'Unknown type']
    const $field = $('<div>').addClass('enrichment-field')
    const $label = $('<dt>').append($('<span>').addClass('enrichment-field-label').text(mispDisplayLabel(attribute.object_relation || types[0])), mispResultTypes(types))
    const $value = $('<dd>').append($('<div>').addClass('enrichment-value').text(mispDisplayValue(attribute.value)))
    if (attribute.comment) $value.append($('<p>').addClass('enrichment-field-comment').text(attribute.comment))
    $value.append(mispResultActions(attribute.value, types, queryUrl, callback))
    $value.append($('<span>').addClass('enrichment-action-status').attr({role: 'status', 'aria-live': 'polite'}))
    return $field.append($label, $value)
}

function parseMispObject(mispObject, queryUrl, callback) {
    const attributes = Array.isArray(mispObject.Attribute) ? mispObject.Attribute : []
    const $card = $('<article>').addClass('enrichment-object-card')
    const $title = $('<div>').addClass('enrichment-card-title').append(
        $('<span>').addClass('enrichment-card-icon').append(mispResultIcon('fa-cube')),
        $('<div>').append($('<p>').addClass('enrichment-card-kind').text('MISP object'), $('<h3>').text(mispDisplayLabel(mispObject.name || 'Object'))))
    const $header = $('<header>').addClass('enrichment-card-header').append($title,
        $('<span>').addClass('enrichment-count').text(`${attributes.length} ${attributes.length === 1 ? 'attribute' : 'attributes'}`))
    $card.append($header)
    if (mispObject.description) $card.append($('<p>').addClass('enrichment-card-description').text(mispObject.description))
    if (mispObject.comment) $card.append($('<p>').addClass('enrichment-card-description').text(mispObject.comment))
    if (attributes.length) {
        const $fields = $('<dl>').addClass('enrichment-fields')
        for (const attribute of attributes) $fields.append(mispResultField(attribute, queryUrl, callback))
        $card.append($fields)
    } else {
        $card.append($('<p>').addClass('enrichment-card-description').text('This object has no attributes.'))
    }
    return $card
}

function parseMispAttr(value, types, key, queryUrl, callback) {
    const normalizedTypes = Array.isArray(types) ? (types.length ? types : ['Unknown type']) : [types || 'Unknown type']
    const $card = $('<article>').addClass('enrichment-attribute-card')
    const $title = $('<div>').addClass('enrichment-card-title').append(
        $('<span>').addClass('enrichment-card-icon').append(mispResultIcon('fa-fingerprint')),
        $('<div>').append($('<p>').addClass('enrichment-card-kind').text('MISP attribute'), $('<h3>').text(mispDisplayLabel(normalizedTypes[0]))))
    $card.append($('<header>').addClass('enrichment-card-header').append($title, mispResultTypes(normalizedTypes)))
    // Keep the same definition-list structure as object properties, without
    // repeating the type label already visible in the card header.
    const $field = mispResultField({types: normalizedTypes, value}, queryUrl, callback)
    $field.find('dt').empty().append($('<span>').addClass('visually-hidden').text('Value'))
    return $card.append($('<dl>').addClass('enrichment-fields enrichment-standalone-value').append($field))
}

async function mispCopyValue(value) {
    if (window.isSecureContext && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value)
        return
    }
    // Support installations served over plain HTTP, where Clipboard API is absent.
    const focused = document.activeElement
    const input = document.createElement('textarea')
    input.value = value
    input.className = 'enrichment-copy-fallback'
    input.setAttribute('aria-label', 'Value to copy')
    document.body.append(input)
    input.select()
    try {
        if (!document.execCommand('copy')) throw new Error('Clipboard unavailable')
    } finally {
        input.remove()
        focused?.focus()
    }
}

// Delegate actions so copied outerHTML keeps working after Vue renders a result
// or switches format. Indicator values never become executable inline JavaScript.
document.addEventListener('click', async event => {
    const button = event.target.closest('[data-enrichment-action]')
    if (!button || button.disabled) return
    const status = button.closest('.enrichment-field')?.querySelector('.enrichment-action-status')
    if (!status) return
    const value = button.dataset.value
    button.disabled = true
    status.textContent = ''
    try {
        if (button.dataset.enrichmentAction === 'copy') {
            await mispCopyValue(value)
            status.textContent = 'Value copied.'
        } else {
            const callback = window[button.dataset.callback]
            if (typeof callback !== 'function') throw new Error('Unable to start a related enrichment. Reload the page and try again.')
            status.textContent = 'Starting enrichment…'
            await callback(value)
        }
    } catch (error) {
        status.textContent = button.dataset.enrichmentAction === 'copy' ? 'Unable to copy. Select the value and copy it manually.' : error.message
    } finally {
        button.disabled = false
    }
})
