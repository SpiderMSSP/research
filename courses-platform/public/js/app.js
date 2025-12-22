// Courses Platform - Client-side JavaScript

document.addEventListener('DOMContentLoaded', () => {
    // Initialize syntax highlighting
    if (typeof hljs !== 'undefined') {
        document.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
        });
    }

    // Auto-dismiss flash messages
    document.querySelectorAll('[role="alert"]').forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.5s ease';
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 500);
        }, 5000);
    });

    // Confirm dialogs for delete actions
    document.querySelectorAll('[data-confirm]').forEach(el => {
        el.addEventListener('click', (e) => {
            if (!confirm(el.dataset.confirm)) {
                e.preventDefault();
            }
        });
    });

    // Live markdown preview (if preview element exists)
    const markdownInput = document.querySelector('[data-markdown-input]');
    const markdownPreview = document.querySelector('[data-markdown-preview]');

    if (markdownInput && markdownPreview && typeof marked !== 'undefined') {
        let timeout;
        markdownInput.addEventListener('input', () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                markdownPreview.innerHTML = marked.parse(markdownInput.value);
                if (typeof hljs !== 'undefined') {
                    markdownPreview.querySelectorAll('pre code').forEach(block => {
                        hljs.highlightElement(block);
                    });
                }
            }, 300);
        });
    }

    // Progress tracking - update time spent
    let startTime = Date.now();

    window.addEventListener('beforeunload', () => {
        const timeSpent = Math.round((Date.now() - startTime) / 60000); // minutes
        if (timeSpent > 0) {
            // Could send to server to track time
            navigator.sendBeacon('/progress/time', JSON.stringify({ timeSpent }));
        }
    });

    // Mobile menu toggle
    const mobileMenuBtn = document.querySelector('[data-mobile-menu-btn]');
    const mobileMenu = document.querySelector('[data-mobile-menu]');

    if (mobileMenuBtn && mobileMenu) {
        mobileMenuBtn.addEventListener('click', () => {
            mobileMenu.classList.toggle('hidden');
        });
    }

    // Collapsible sections
    document.querySelectorAll('[data-collapse-toggle]').forEach(toggle => {
        toggle.addEventListener('click', () => {
            const target = document.querySelector(toggle.dataset.collapseToggle);
            if (target) {
                target.classList.toggle('hidden');
                toggle.classList.toggle('rotate-180');
            }
        });
    });

    // Copy code button
    document.querySelectorAll('pre').forEach(pre => {
        const copyBtn = document.createElement('button');
        copyBtn.className = 'absolute top-2 right-2 px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity';
        copyBtn.textContent = 'Copy';
        copyBtn.addEventListener('click', () => {
            const code = pre.querySelector('code')?.textContent || pre.textContent;
            navigator.clipboard.writeText(code).then(() => {
                copyBtn.textContent = 'Copied!';
                setTimeout(() => copyBtn.textContent = 'Copy', 2000);
            });
        });

        pre.style.position = 'relative';
        pre.classList.add('group');
        pre.appendChild(copyBtn);
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl+K for search (if implemented)
        if (e.ctrlKey && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.querySelector('[data-search-input]');
            if (searchInput) searchInput.focus();
        }

        // Arrow keys for navigation
        if (e.key === 'ArrowRight' && e.altKey) {
            const nextLink = document.querySelector('[data-next-link]');
            if (nextLink) nextLink.click();
        }
        if (e.key === 'ArrowLeft' && e.altKey) {
            const prevLink = document.querySelector('[data-prev-link]');
            if (prevLink) prevLink.click();
        }
    });
});

// Utility function to mark items complete via API
async function markComplete(type, id) {
    try {
        const response = await fetch(`/${type}/${id}/complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        if (data.success) {
            location.reload();
        }
        return data;
    } catch (error) {
        console.error('Error marking complete:', error);
        return { success: false, error };
    }
}

// Utility function to get hint
async function getHint(labId) {
    try {
        const response = await fetch(`/labs/${labId}/hint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        return await response.json();
    } catch (error) {
        console.error('Error getting hint:', error);
        return { success: false, error };
    }
}
