/* Collapsible sidebar for mdBook 0.4.5x: the sidebar is JS-rendered from
   toc.html and renders all chapters expanded. mdBook-toc injects per-page
   headings as a section list stored in a sibling <li><ol class="section">,
   so re-parent that list under the chapter's <li>, add a caret, and fold on
   click. The chapter title itself still navigates. */
(function () {
  function restructure() {
    document
      .querySelectorAll('.sidebar ol.chapter > li')
      .forEach(function (li) {
        var next = li.nextElementSibling;
        if (
          !next ||
          next.tagName !== 'LI' ||
          !next.querySelector(':scope > ol.section') ||
          li.dataset.foldReady
        )
          return;
        var link = li.querySelector(':scope > a');
        if (!link) return;
        var sub = next.querySelector(':scope > ol.section');
        next.remove();
        sub.classList.add('fold-hidden');
        li.appendChild(sub);
        li.dataset.foldReady = '1';
        var caret = document.createElement('span');
        caret.className = 'sidebar-fold-caret';
        caret.textContent = '▸';
        caret.title = 'fold/unfold';
        caret.addEventListener('click', function (e) {
          e.preventDefault();
          e.stopPropagation();
          var open = sub.classList.toggle('fold-hidden') === false;
          caret.textContent = open ? '▾' : '▸';
        });
        li.insertBefore(caret, link);
      });
    // Keep the active page's ancestors unfolded so the current location
    // stays visible after navigation.
    var active = document.querySelector('.sidebar li > a.active');
    if (active) {
      var li = active.closest('li');
      while (li) {
        var sub = li.querySelector(':scope > ol.section');
        if (sub) {
          sub.classList.remove('fold-hidden');
          var c = li.querySelector(':scope > .sidebar-fold-caret');
          if (c && c.textContent !== '▾') c.textContent = '▾';
        }
        li = li.parentElement ? li.parentElement.closest('li') : null;
      }
    }
  }
  function start() {
    var sidebar = document.querySelector('.sidebar');
    if (!sidebar) return;
    restructure();
    new MutationObserver(restructure).observe(sidebar, {
      childList: true,
      subtree: true,
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();