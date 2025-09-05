// public/app.js
(() => {
  function onReady(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn, { once: true });
    } else {
      fn();
    }
  }

  onReady(() => {
    const btn = document.querySelector('.nav-toggle');
    const nav = document.getElementById('site-nav');
    if (!btn || !nav) return;

    const setExpanded = (open) => btn.setAttribute('aria-expanded', String(open));

    btn.addEventListener('click', () => {
      const open = nav.classList.toggle('open');
      setExpanded(open);
    });

    nav.addEventListener('click', (e) => {
      if (e.target && e.target.closest('a')) {
        nav.classList.remove('open');
        setExpanded(false);
      }
    });

    window.addEventListener('resize', () => {
      if (window.innerWidth > 640 && nav.classList.contains('open')) {
        nav.classList.remove('open');
        setExpanded(false);
      }
    });
  });
})();