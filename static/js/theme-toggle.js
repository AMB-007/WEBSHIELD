// ─── Theme Toggle ───────────────────────────────────────────────
(function () {
  const KEY = "ws-theme";

  function sys()    { return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"; }
  function stored() { try { const v = localStorage.getItem(KEY); return v === "dark" || v === "light" ? v : null; } catch { return null; } }
  function save(t)  { try { localStorage.setItem(KEY, t); } catch {} }
  function current(){ return document.documentElement.getAttribute("data-theme") || "light"; }

  function apply(theme) {
    const prev = current();
    document.documentElement.setAttribute("data-theme", theme);
    if (prev !== theme) window.dispatchEvent(new CustomEvent("themechange", { detail: { theme } }));
  }

  function syncButtons(theme) {
    const dark = theme === "dark";
    document.querySelectorAll("[data-theme-toggle]").forEach(btn => {
      btn.innerHTML = dark
        ? `<i class="fas fa-sun"></i> Light Mode`
        : `<i class="fas fa-moon"></i> Dark Mode`;
      btn.setAttribute("aria-label", `Switch to ${dark ? "light" : "dark"} mode`);
    });
  }

  function bindButtons() {
    document.querySelectorAll("[data-theme-toggle]").forEach(btn => {
      if (btn.dataset.bound) return;
      btn.dataset.bound = "1";
      btn.addEventListener("click", () => {
        const next = current() === "dark" ? "light" : "dark";
        apply(next); save(next); syncButtons(next);
      });
    });
  }

  function init() {
    const t = stored() || sys();
    apply(t);
    bindButtons();
    syncButtons(t);
    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", e => {
        if (stored()) return;
        apply(e.matches ? "dark" : "light");
        syncButtons(e.matches ? "dark" : "light");
      });
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();

// ─── Mobile Sidebar ─────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", function () {
  const sidebar  = document.querySelector(".app-sidebar");
  const overlay  = document.querySelector(".sidebar-overlay");
  const hamburger= document.querySelector(".hamburger-btn");
  if (!sidebar || !overlay || !hamburger) return;

  function openSidebar() {
    sidebar.classList.add("open");
    overlay.classList.add("active");
    document.body.style.overflow = "hidden";
  }

  function closeSidebar() {
    sidebar.classList.remove("open");
    overlay.classList.remove("active");
    document.body.style.overflow = "";
  }

  hamburger.addEventListener("click", () => sidebar.classList.contains("open") ? closeSidebar() : openSidebar());
  overlay.addEventListener("click", closeSidebar);

  // Close on nav link click (mobile)
  sidebar.querySelectorAll(".nav-link").forEach(link => {
    link.addEventListener("click", () => { if (window.innerWidth < 992) closeSidebar(); });
  });

  // Close on resize past breakpoint
  window.addEventListener("resize", () => { if (window.innerWidth >= 992) closeSidebar(); });
});
