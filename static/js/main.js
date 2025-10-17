(function () {
  const navToggle = document.getElementById('navToggle');
  const siteNav = document.getElementById('siteNav');

  if (navToggle && siteNav) {
    navToggle.addEventListener('click', () => {
      siteNav.classList.toggle('open');
    });
  }

  // Lightweight tilt effect for project cards
  const cards = document.querySelectorAll('[data-tilt]');
  cards.forEach((card) => {
    card.addEventListener('mousemove', (event) => {
      const bounds = card.getBoundingClientRect();
      const centerX = bounds.x + bounds.width / 2;
      const centerY = bounds.y + bounds.height / 2;
      const percentX = (event.clientX - centerX) / (bounds.width / 2);
      const percentY = (event.clientY - centerY) / (bounds.height / 2);
      card.style.transform = `rotateX(${percentY * -3}deg) rotateY(${percentX * 3}deg)`;
    });

    card.addEventListener('mouseleave', () => {
      card.style.transform = 'rotateX(0) rotateY(0)';
    });
  });

  // Auto-hide flash messages
  const flashes = document.querySelectorAll('.flash');
  if (flashes.length) {
    setTimeout(() => {
      flashes.forEach((flash) => {
        flash.style.opacity = '0';
        flash.style.transform = 'translateY(-12px)';
      });
    }, 4500);
  }
})();
