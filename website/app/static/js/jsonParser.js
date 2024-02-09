function generateCoreFormatUI(event) {
    var indent_size = 'calc(1.25em)'
    var color_key = '#005cd5'
    var color_index = '#727272'
    var color_string = '#cf5900'
    var color_null = '#747474'
    var color_bool = '#004bad'
    var color_brace = '#727272'
    var color_column = '#727272'
    var color_collapse = '#727272'
    var defaultCollapseList = ['Org', 'Orgc']

    function generate(item, depth, path, forceObjectCollaspe) {
        if (Array.isArray(item)) {
            var $container = $('<span>').append(
                depth == 1 ? '' : braceOpen(true),
                depth == 1 ? '' : childrenCount(item),
                genArray(item, depth, path),
                depth == 1 ? '' : braceClose(true),
            )
            if (depth > 2) {
                $container.children("div").toggleClass("hidden")
            }
        } else if (typeof item === 'object' && item !== null) {
            var $container = $('<span>').append(
                depth == 1 ? '' : braceOpen(),
                depth == 1 ? '' : childrenCount(item),
                genObject(item, depth, path),
                depth == 1 ? '' : braceClose(),
            )
            if (forceObjectCollaspe === true) {
                $container.children("div").toggleClass("hidden")
            }
        } else {
            var $container = genValue(item)
        }
        return $container
    }

    function genArray(arr, depth, path) {
        var $container = $('<div>')
        arr.forEach(function (v, i) {
            var nextPath = path + '.{n}'
            var $index = genIndex(i)
            var $value = generate(v, depth + 1, nextPath)
            var $div = $('<div>')
            $div.append($index, column(), $value)
            $container.append($div)
        })
        setDepth($container, depth, path)
        return $container
    }

    function genObject(obj, depth, path) {
        var $container = $('<div>')
        Object.keys(obj).forEach(function (k) {
            var nextPath = path + '.' + k
            var v = obj[k]
            var forceCollaspe = defaultCollapseList.includes(k)
            var $key = genKey(k)
            var $value = generate(v, depth+1, nextPath, forceCollaspe)
            var $div = $('<div>')
            var $collase = ''
            if (isIterable(v)) {
                $collase = collapseIcon()
                if (depth > 1 && (Array.isArray(v) || forceCollaspe)) {
                    $collase.addClass('fa-rotate-270')
                }
            }
            $div.append($collase, $key, column(), $value)
            $container.append($div)
        })
        setDepth($container, depth)
        return $container
    }

    function genValue(val, path) {
        var $value
        if (val === null) {
            $value = $('<span>').text('null').css({'color': color_null })
        } else if (typeof val === 'boolean') {
            $value = $('<span>').text(val).css({'color': color_bool })
        } else {
            $value = $('<span>').text(val).css({'color': color_string })
        }
        $value
            .addClass('selectable-value')
        return $value
    }

    function genKey(key) {
        return $('<span>')
            .text(key)
            .css({ 'color': color_key })
            .addClass('selectable-key')
    }

    function genIndex(i) {
        return $('<span>')
            .text(i)
            .addClass('selectable-key')
            .css({ 'color': color_index })
    }

    function header() {
        return $('<div>').append(braceOpen())
    }

    function footer() {
        return $('<div>').append(braceClose())
    }

    function collapseIcon() {
        return $('<i>')
            .addClass(['fas fa-caret-down', 'collaspe-button'])
            .css({ 'color': color_collapse, 'margin-right': '0.25rem', 'font-size': '1.25em' })
            .attr('onclick', '$(this).toggleClass("fa-rotate-270").parent().children().last().children("div").toggleClass("d-none")')
    }

    function childrenCount(iterable) {
        var count = getChildrenCount(iterable)
        var $span = $('<span>').text(count).addClass('children-counter')
        if (count === 0) {
            $span.css('background-color', '#a3a3a3')
        }
        return $span
    }

    function braceOpen(isArray) {
        return $('<span>').text(isArray ? '[' : '{').css({ 'color': color_brace, margin: '0 0.25em' })
    }
    function braceClose(isArray) {
        return $('<span>').text(isArray ? ']' : '}').css({ 'color': color_brace, margin: '0 0.25em' })
    }
    function column() {
        return $('<span>').text(':').css({ 'color': color_column, margin: '0 0.25em' })
    }

    function setDepth($obj) {
        $obj.css('margin-left', 'calc( ' + indent_size + ' )')
    }

    function isIterable(obj) {
        return typeof obj === 'object' && obj !== null
    }
    
    function getChildrenCount(iterable) {
        var count = 0
        if (Array.isArray(iterable)) {
            count = iterable.length
        } else if (typeof iterable === 'object') {
            count = Object.keys(iterable).length
        }
        return count
    }

    var $mainContainer = $('<div id="core-format-picker">')
    $mainContainer.append(header(), generate(event, 1, ''), footer())
    return $mainContainer
}