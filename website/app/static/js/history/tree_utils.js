export function normalizeNode(node, ordinal) {
    if (!node || typeof node.uuid !== 'string') throw new Error('The server returned an unreadable investigation path.')
    const normalized = {
        uuid: node.uuid, ordinal,
        query: Array.isArray(node.query) ? (node.query.length ? node.query.map(String) : ['Untitled query']) : [String(node.query || 'Untitled query')],
        input: String(node.input || 'Unknown attribute'),
        modules: Array.isArray(node.modules) ? node.modules.map(String) : [],
        query_date: String(node.query_date || ''),
        children: Array.isArray(node.children) ? node.children.map(child => normalizeNode(child)) : [],
    }
    const stats = summarize(normalized)
    return {...normalized, totalQueries: stats.queries, maxDepth: stats.depth}
}
export function summarize(node) {
    let queries = 0, depth = 0
    const pending = [[node, 1]]
    while (pending.length) {
        const [current, level] = pending.pop()
        queries++
        depth = Math.max(depth, level)
        for (const child of current.children) pending.push([child, level + 1])
    }
    return {queries, depth}
}
export function filterPath(node, term) {
    const match = [node.query.join(' '), node.input, node.modules.join(' ')].join(' ').toLowerCase().includes(term)
    const children = node.children.map(child => filterPath(child, term)).filter(Boolean)
    return match || children.length ? {...node, match, children} : null
}
export function matchingQueries(node) { return Number(!!node.match) + node.children.reduce((total, child) => total + matchingQueries(child), 0) }
export function visit(node, callback) { callback(node); node.children.forEach(child => visit(child, callback)) }
