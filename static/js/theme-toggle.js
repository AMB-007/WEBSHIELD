/**
 * WebShield — Core UI Runtime
 * Handles: theme, sidebar, menus, search, tabs, dialogs, panels, toasts, file uploads
 */
(function () {
  'use strict';

  const THEME_KEY   = 'ws-theme';
  const SIDEBAR_KEY = 'ws-sidebar-collapsed';

  /* ── Helpers ─────────────────────────────────────────────── */
  function prefersDark() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function getStoredTheme() {
    try {
      const v = localStorage.getItem(THEME_KEY);
      return v === 'dark' || v === 'light' ? v : null;
    } catch { return null; }
  }

  function storeTheme(theme) {
    try { localStorage.setItem(THEME_KEY, theme); } catch {}
  }

  function escapeHTML(value) {
    return String(value == null ? '' : value)
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;')
      .replace(/'/g,  '&#039;');
  }

  /* ── Theme ───────────────────────────────────────────────── */
  function setTheme(theme) {
    const previous = document.documentElement.getAttribute('data-theme');
    document.documentElement.setAttribute('data-theme', theme);
    syncThemeButtons(theme);
    if (previous && previous !== theme) {
      window.dispatchEvent(new CustomEvent('themechange', { detail: { theme } }));
    }
  }

  function syncThemeButtons(theme) {
    const isDark = theme === 'dark';
    document.querySelectorAll('[data-theme-toggle]').forEach(btn => {
      btn.innerHTML = isDark
        ? '<i class="fas fa-sun"></i>'
        : '<i class="fas fa-moon"></i>';
      btn.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
      btn.dataset.tooltip = isDark ? 'Light mode' : 'Dark mode';
    });
  }

  function initTheme() {
    const theme = getStoredTheme() || (prefersDark() ? 'dark' : 'light');
    setTheme(theme);

    document.querySelectorAll('[data-theme-toggle]').forEach(btn => {
      btn.addEventListener('click', () => {
        const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        storeTheme(next);
        setTheme(next);
      });
    });

    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
        if (!getStoredTheme()) setTheme(e.matches ? 'dark' : 'light');
      });
    }
  }

  /* ── Sidebar ─────────────────────────────────────────────── */
  function initSidebar() {
    const sidebar  = document.querySelector('.sidebar');
    const backdrop = document.querySelector('.sidebar-backdrop');
    const openBtns = document.querySelectorAll('[data-sidebar-open]');
    const closeBtns = document.querySelectorAll('[data-sidebar-close]');
    const collapseBtn = document.querySelector('[data-sidebar-collapse]');

    /* Restore collapsed state */
    try {
      if (localStorage.getItem(SIDEBAR_KEY) === 'true') {
        document.body.dataset.sidebarCollapsed = 'true';
      }
    } catch {}

    function openSidebar() {
      if (!sidebar || !backdrop) return;
      sidebar.classList.add('open');
      backdrop.classList.add('open');
      document.body.style.overflow = 'hidden';
    }

    function closeSidebar() {
      if (!sidebar || !backdrop) return;
      sidebar.classList.remove('open');
      backdrop.classList.remove('open');
      document.body.style.overflow = '';
    }

    openBtns.forEach(btn => btn.addEventListener('click', openSidebar));
    closeBtns.forEach(btn => btn.addEventListener('click', closeSidebar));

    /* Close on nav link click (mobile) */
    document.querySelectorAll('.sidebar .nav-link').forEach(link => {
      link.addEventListener('click', () => {
        if (window.innerWidth <= 900) closeSidebar();
      });
    });

    /* Collapse toggle (desktop) */
    if (collapseBtn) {
      collapseBtn.addEventListener('click', () => {
        const collapsed = document.body.dataset.sidebarCollapsed !== 'true';
        document.body.dataset.sidebarCollapsed = String(collapsed);
        try { localStorage.setItem(SIDEBAR_KEY, String(collapsed)); } catch {}
      });
    }

    /* Close on resize */
    window.addEventListener('resize', () => {
      if (window.innerWidth > 900) closeSidebar();
    });
  }

  /* ── Dropdown Menus ──────────────────────────────────────── */
  function initMenus() {
    const toggles = document.querySelectorAll('[data-menu-toggle]');

    function closeMenus(exceptId) {
      document.querySelectorAll('.menu-panel').forEach(p => {
        if (p.id !== exceptId) p.hidden = true;
      });
    }

    toggles.forEach(toggle => {
      toggle.addEventListener('click', e => {
        e.stopPropagation();
        const id    = toggle.getAttribute('data-menu-toggle');
        const panel = document.getElementById(id);
        if (!panel) return;
        const willOpen = panel.hidden;
        closeMenus(id);
        panel.hidden = !willOpen;
        if (!panel.hidden) {
          /* Focus first focusable item */
          const first = panel.querySelector('a, button');
          if (first) requestAnimationFrame(() => first.focus());
        }
      });
    });

    document.addEventListener('click', () => closeMenus());

    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') closeMenus();
      /* Arrow key nav within open menu */
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        const openMenu = document.querySelector('.menu-panel:not([hidden])');
        if (!openMenu) return;
        const items = [...openMenu.querySelectorAll('a, button')];
        const idx   = items.indexOf(document.activeElement);
        const next  = e.key === 'ArrowDown'
          ? items[(idx + 1) % items.length]
          : items[(idx - 1 + items.length) % items.length];
        if (next) { e.preventDefault(); next.focus(); }
      }
    });
  }

  /* ── Global Search ───────────────────────────────────────── */
  function initGlobalSearch() {
    const input = document.querySelector('[data-global-search]');
    if (!input) return;

    let debounce;
    input.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        const query = input.value.trim().toLowerCase();
        document.querySelectorAll('[data-searchable]').forEach(item => {
          const text = (item.getAttribute('data-searchable') || item.textContent || '').toLowerCase();
          item.hidden = query.length > 0 && !text.includes(query);
        });
        window.dispatchEvent(new CustomEvent('webshield:search', { detail: { query } }));
      }, 120);
    });

    /* Keyboard shortcut: "/" to focus search */
    document.addEventListener('keydown', e => {
      if (e.key === '/' && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
        e.preventDefault();
        input.focus();
        input.select();
      }
    });
  }

  /* ── Tabs ────────────────────────────────────────────────── */
  function initTabs() {
    document.querySelectorAll('[data-tabs]').forEach(tabset => {
      const buttons = tabset.querySelectorAll('[data-tab-target]');

      buttons.forEach(btn => {
        btn.addEventListener('click', () => {
          const target = btn.getAttribute('data-tab-target');

          buttons.forEach(candidate => {
            const active = candidate === btn;
            candidate.classList.toggle('active', active);
            candidate.setAttribute('aria-selected', String(active));
          });

          document.querySelectorAll('[data-tab-panel]').forEach(panel => {
            panel.hidden = panel.getAttribute('data-tab-panel') !== target;
          });
        });

        /* Arrow key navigation between tabs */
        btn.addEventListener('keydown', e => {
          const btns = [...buttons];
          const idx  = btns.indexOf(btn);
          if (e.key === 'ArrowRight') { e.preventDefault(); btns[(idx + 1) % btns.length]?.click(); }
          if (e.key === 'ArrowLeft')  { e.preventDefault(); btns[(idx - 1 + btns.length) % btns.length]?.click(); }
        });
      });
    });
  }

  /* ── File Uploads ────────────────────────────────────────── */
  function initFileUploads() {
    document.querySelectorAll('[data-file-input]').forEach(input => {
      input.addEventListener('change', () => {
        const label = document.querySelector(`[data-file-label="${input.id}"]`);
        if (!label) return;
        if (input.files && input.files.length) {
          label.textContent = input.files[0].name;
          if (window.WebShield) {
            WebShield.toast('File staged', `${input.files[0].name} is ready for review.`, 'info');
          }
        } else {
          label.textContent = 'Choose JSON or CSV file';
        }
      });

      /* Drag-over visual feedback */
      const zone = input.closest('.file-upload');
      if (zone) {
        zone.addEventListener('dragover', e => { e.preventDefault(); zone.style.borderColor = 'var(--blue)'; });
        zone.addEventListener('dragleave', () => { zone.style.borderColor = ''; });
        zone.addEventListener('drop', () => { zone.style.borderColor = ''; });
      }
    });
  }

  /* ── Toast Notifications ─────────────────────────────────── */
  function toast(title, message, type) {
    const region = document.querySelector('.toast-region');
    if (!region) return;

    const tone = type || 'info';
    const icons = { success: 'fa-circle-check', warning: 'fa-triangle-exclamation', danger: 'fa-circle-xmark', info: 'fa-circle-info' };
    const icon  = icons[tone] || 'fa-circle-info';

    const node = document.createElement('div');
    node.className = `toast ${tone}`;
    node.setAttribute('role', 'status');
    node.innerHTML = `
      <i class="fas ${icon}" aria-hidden="true"></i>
      <div>
        <strong>${escapeHTML(title)}</strong>
        <span>${escapeHTML(message || '')}</span>
      </div>`;

    region.appendChild(node);

    /* Auto-dismiss */
    const DURATION = 4200;
    setTimeout(() => {
      node.style.opacity = '0';
      node.style.transform = 'translateY(8px)';
      setTimeout(() => node.remove(), 200);
    }, DURATION);
  }

  /* ── Dialogs ─────────────────────────────────────────────── */
  function openDialog(id) {
    const dialog   = document.getElementById(id);
    const backdrop = document.querySelector(`[data-dialog-backdrop="${id}"]`);
    if (!dialog || !backdrop) return;
    dialog.classList.add('open');
    backdrop.classList.add('open');
    dialog.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    const focusable = dialog.querySelector('button:not([disabled]), [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    if (focusable) requestAnimationFrame(() => focusable.focus());
  }

  function closeDialog(id) {
    const dialog   = document.getElementById(id);
    const backdrop = document.querySelector(`[data-dialog-backdrop="${id}"]`);
    if (!dialog || !backdrop) return;
    dialog.classList.remove('open');
    backdrop.classList.remove('open');
    dialog.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  }

  /* ── Side Panels ─────────────────────────────────────────── */
  function openPanel(id) {
    const panel    = document.getElementById(id);
    const backdrop = document.querySelector(`[data-panel-backdrop="${id}"]`);
    if (!panel || !backdrop) return;
    panel.classList.add('open');
    backdrop.classList.add('open');
    panel.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    const focusable = panel.querySelector('button:not([disabled]), [href], input');
    if (focusable) requestAnimationFrame(() => focusable.focus());
  }

  function closePanel(id) {
    const panel    = document.getElementById(id);
    const backdrop = document.querySelector(`[data-panel-backdrop="${id}"]`);
    if (!panel || !backdrop) return;
    panel.classList.remove('open');
    backdrop.classList.remove('open');
    panel.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  }

  /* ── Dismissable Wiring ──────────────────────────────────── */
  function initDismissables() {
    document.querySelectorAll('[data-dialog-close]').forEach(btn => {
      btn.addEventListener('click', () => closeDialog(btn.getAttribute('data-dialog-close')));
    });
    document.querySelectorAll('[data-dialog-open]').forEach(btn => {
      btn.addEventListener('click', () => openDialog(btn.getAttribute('data-dialog-open')));
    });
    document.querySelectorAll('[data-dialog-backdrop]').forEach(bd => {
      bd.addEventListener('click', () => closeDialog(bd.getAttribute('data-dialog-backdrop')));
    });
    document.querySelectorAll('[data-panel-close]').forEach(btn => {
      btn.addEventListener('click', () => closePanel(btn.getAttribute('data-panel-close')));
    });
    document.querySelectorAll('[data-panel-backdrop]').forEach(bd => {
      bd.addEventListener('click', () => closePanel(bd.getAttribute('data-panel-backdrop')));
    });

    document.addEventListener('keydown', e => {
      if (e.key !== 'Escape') return;
      document.querySelectorAll('.dialog.open').forEach(d => closeDialog(d.id));
      document.querySelectorAll('.side-panel.open').forEach(p => closePanel(p.id));
    });
  }

  /* ── Public API ──────────────────────────────────────────── */
  window.WebShield = {
    escapeHTML,
    toast,
    openDialog,
    closeDialog,
    openPanel,
    closePanel
  };

  /* ── Boot ────────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initSidebar();
    initMenus();
    initGlobalSearch();
    initTabs();
    initFileUploads();
    initDismissables();
  });
})();
