(function () {
  const THEME_KEY = "ws-theme";
  const SIDEBAR_KEY = "ws-sidebar-collapsed";

  function prefersDark() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  }

  function getStoredTheme() {
    try {
      const value = localStorage.getItem(THEME_KEY);
      return value === "dark" || value === "light" ? value : null;
    } catch (error) {
      return null;
    }
  }

  function storeTheme(theme) {
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch (error) {}
  }

  function setTheme(theme) {
    const previous = document.documentElement.getAttribute("data-theme");
    document.documentElement.setAttribute("data-theme", theme);
    syncThemeButtons(theme);
    if (previous && previous !== theme) {
      window.dispatchEvent(new CustomEvent("themechange", { detail: { theme } }));
    }
  }

  function syncThemeButtons(theme) {
    const dark = theme === "dark";
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      button.innerHTML = dark ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
      button.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
      button.dataset.tooltip = dark ? "Light mode" : "Dark mode";
    });
  }

  function initTheme() {
    const theme = getStoredTheme() || (prefersDark() ? "dark" : "light");
    setTheme(theme);
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      button.addEventListener("click", () => {
        const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
        storeTheme(next);
        setTheme(next);
      });
    });

    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (event) => {
        if (!getStoredTheme()) setTheme(event.matches ? "dark" : "light");
      });
    }
  }

  function initSidebar() {
    const sidebar = document.querySelector(".sidebar");
    const backdrop = document.querySelector(".sidebar-backdrop");
    const openButtons = document.querySelectorAll("[data-sidebar-open]");
    const closeButtons = document.querySelectorAll("[data-sidebar-close]");
    const collapseButton = document.querySelector("[data-sidebar-collapse]");

    try {
      if (localStorage.getItem(SIDEBAR_KEY) === "true") {
        document.body.dataset.sidebarCollapsed = "true";
      }
    } catch (error) {}

    function openSidebar() {
      if (!sidebar || !backdrop) return;
      sidebar.classList.add("open");
      backdrop.classList.add("open");
      document.body.style.overflow = "hidden";
    }

    function closeSidebar() {
      if (!sidebar || !backdrop) return;
      sidebar.classList.remove("open");
      backdrop.classList.remove("open");
      document.body.style.overflow = "";
    }

    openButtons.forEach((button) => button.addEventListener("click", openSidebar));
    closeButtons.forEach((button) => button.addEventListener("click", closeSidebar));
    document.querySelectorAll(".sidebar .nav-link").forEach((link) => {
      link.addEventListener("click", () => {
        if (window.innerWidth <= 900) closeSidebar();
      });
    });

    if (collapseButton) {
      collapseButton.addEventListener("click", () => {
        const collapsed = document.body.dataset.sidebarCollapsed !== "true";
        document.body.dataset.sidebarCollapsed = collapsed ? "true" : "false";
        try {
          localStorage.setItem(SIDEBAR_KEY, collapsed ? "true" : "false");
        } catch (error) {}
      });
    }

    window.addEventListener("resize", () => {
      if (window.innerWidth > 900) closeSidebar();
    });
  }

  function initMenus() {
    const toggles = document.querySelectorAll("[data-menu-toggle]");

    function closeMenus(exceptId) {
      document.querySelectorAll(".menu-panel").forEach((panel) => {
        if (panel.id !== exceptId) panel.hidden = true;
      });
    }

    toggles.forEach((toggle) => {
      toggle.addEventListener("click", (event) => {
        event.stopPropagation();
        const id = toggle.getAttribute("data-menu-toggle");
        const panel = document.getElementById(id);
        if (!panel) return;
        const willOpen = panel.hidden;
        closeMenus(id);
        panel.hidden = !willOpen;
      });
    });

    document.addEventListener("click", () => closeMenus());
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeMenus();
    });
  }

  function initGlobalSearch() {
    const input = document.querySelector("[data-global-search]");
    if (!input) return;

    input.addEventListener("input", () => {
      const query = input.value.trim().toLowerCase();
      const items = document.querySelectorAll("[data-searchable]");
      items.forEach((item) => {
        const text = (item.getAttribute("data-searchable") || item.textContent || "").toLowerCase();
        item.hidden = query.length > 0 && !text.includes(query);
      });
      window.dispatchEvent(new CustomEvent("webshield:search", { detail: { query } }));
    });
  }

  function initTabs() {
    document.querySelectorAll("[data-tabs]").forEach((tabset) => {
      const buttons = tabset.querySelectorAll("[data-tab-target]");
      buttons.forEach((button) => {
        button.addEventListener("click", () => {
          const target = button.getAttribute("data-tab-target");
          buttons.forEach((candidate) => {
            const active = candidate === button;
            candidate.classList.toggle("active", active);
            candidate.setAttribute("aria-selected", active ? "true" : "false");
          });

          document.querySelectorAll("[data-tab-panel]").forEach((panel) => {
            panel.hidden = panel.getAttribute("data-tab-panel") !== target;
          });
        });
      });
    });
  }

  function initFileUploads() {
    document.querySelectorAll("[data-file-input]").forEach((input) => {
      input.addEventListener("change", () => {
        const label = document.querySelector(`[data-file-label="${input.id}"]`);
        if (!label) return;
        label.textContent = input.files && input.files.length ? input.files[0].name : "Choose JSON or CSV file";
        if (input.files && input.files.length && window.WebShield) {
          window.WebShield.toast("File staged", `${input.files[0].name} is ready for upload review.`, "info");
        }
      });
    });
  }

  function escapeHTML(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function toast(title, message, type) {
    const region = document.querySelector(".toast-region");
    if (!region) return;
    const tone = type || "info";
    const icon = tone === "success" ? "fa-circle-check" : tone === "warning" ? "fa-triangle-exclamation" : tone === "danger" ? "fa-circle-xmark" : "fa-circle-info";
    const node = document.createElement("div");
    node.className = `toast ${tone}`;
    node.setAttribute("role", "status");
    node.innerHTML = `
      <i class="fas ${icon}" aria-hidden="true"></i>
      <div>
        <strong>${escapeHTML(title)}</strong>
        <span>${escapeHTML(message || "")}</span>
      </div>`;
    region.appendChild(node);
    setTimeout(() => {
      node.style.opacity = "0";
      node.style.transform = "translateY(8px)";
      setTimeout(() => node.remove(), 180);
    }, 4200);
  }

  function openDialog(id) {
    const dialog = document.getElementById(id);
    const backdrop = document.querySelector(`[data-dialog-backdrop="${id}"]`);
    if (!dialog || !backdrop) return;
    dialog.classList.add("open");
    backdrop.classList.add("open");
    dialog.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
    const focusable = dialog.querySelector("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
    if (focusable) focusable.focus();
  }

  function closeDialog(id) {
    const dialog = document.getElementById(id);
    const backdrop = document.querySelector(`[data-dialog-backdrop="${id}"]`);
    if (!dialog || !backdrop) return;
    dialog.classList.remove("open");
    backdrop.classList.remove("open");
    dialog.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
  }

  function openPanel(id) {
    const panel = document.getElementById(id);
    const backdrop = document.querySelector(`[data-panel-backdrop="${id}"]`);
    if (!panel || !backdrop) return;
    panel.classList.add("open");
    backdrop.classList.add("open");
    panel.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
  }

  function closePanel(id) {
    const panel = document.getElementById(id);
    const backdrop = document.querySelector(`[data-panel-backdrop="${id}"]`);
    if (!panel || !backdrop) return;
    panel.classList.remove("open");
    backdrop.classList.remove("open");
    panel.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
  }

  function initDismissables() {
    document.querySelectorAll("[data-dialog-close]").forEach((button) => {
      button.addEventListener("click", () => closeDialog(button.getAttribute("data-dialog-close")));
    });
    document.querySelectorAll("[data-dialog-open]").forEach((button) => {
      button.addEventListener("click", () => openDialog(button.getAttribute("data-dialog-open")));
    });
    document.querySelectorAll("[data-dialog-backdrop]").forEach((backdrop) => {
      backdrop.addEventListener("click", () => closeDialog(backdrop.getAttribute("data-dialog-backdrop")));
    });
    document.querySelectorAll("[data-panel-close]").forEach((button) => {
      button.addEventListener("click", () => closePanel(button.getAttribute("data-panel-close")));
    });
    document.querySelectorAll("[data-panel-backdrop]").forEach((backdrop) => {
      backdrop.addEventListener("click", () => closePanel(backdrop.getAttribute("data-panel-backdrop")));
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      document.querySelectorAll(".dialog.open").forEach((dialog) => closeDialog(dialog.id));
      document.querySelectorAll(".side-panel.open").forEach((panel) => closePanel(panel.id));
    });
  }

  window.WebShield = {
    escapeHTML,
    toast,
    openDialog,
    closeDialog,
    openPanel,
    closePanel
  };

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initSidebar();
    initMenus();
    initGlobalSearch();
    initTabs();
    initFileUploads();
    initDismissables();
  });
})();
