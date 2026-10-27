// Keep navigation independent of the Vue application used by each page.
document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.querySelector('.menu-toggle')
    const sidebar = document.getElementById('sidebar')
    if (!toggle || !sidebar) return
    function closeNavigation() {
        document.body.classList.remove('navigation-open')
        toggle.setAttribute('aria-expanded', 'false')
        toggle.setAttribute('aria-label', 'Open navigation')
    }
    toggle.addEventListener('click', () => {
        const opened = document.body.classList.toggle('navigation-open')
        toggle.setAttribute('aria-expanded', String(opened))
        toggle.setAttribute('aria-label', opened ? 'Close navigation' : 'Open navigation')
    })
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && document.body.classList.contains('navigation-open')) {
            closeNavigation()
            toggle.focus()
        }
    })
    document.addEventListener('click', event => {
        if (!sidebar.contains(event.target) && !toggle.contains(event.target)) closeNavigation()
    })
    window.matchMedia('(min-width: 992px)').addEventListener('change', closeNavigation)
})
