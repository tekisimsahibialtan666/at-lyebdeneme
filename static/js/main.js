(function () {
  const prefersReducedMotion = window.matchMedia
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
    : false;

  const header = document.querySelector('.site-header');
  const navToggle = document.getElementById('navToggle');
  const siteNav = document.getElementById('siteNav');
  const navOverlay = document.getElementById('navOverlay');

  const setHeaderState = () => {
    if (!header) {
      return;
    }
    header.classList.toggle('is-scrolled', window.scrollY > 12);
  };

  setHeaderState();
  window.addEventListener('scroll', setHeaderState, { passive: true });

  if (navToggle && siteNav) {
    const setNavState = (open) => {
      siteNav.classList.toggle('open', open);
      document.body.classList.toggle('nav-open', open);
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    };

    navToggle.addEventListener('click', () => {
      setNavState(!siteNav.classList.contains('open'));
    });

    if (navOverlay) {
      navOverlay.addEventListener('click', () => setNavState(false));
    }

    siteNav.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => setNavState(false));
    });

    window.addEventListener(
      'resize',
      () => {
        if (window.innerWidth > 960) {
          setNavState(false);
        }
      },
      { passive: true },
    );

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        setNavState(false);
      }
    });
  }

  if (!prefersReducedMotion) {
    const cards = document.querySelectorAll('[data-tilt]');
    cards.forEach((card) => {
      const updateTilt = (event) => {
        const bounds = card.getBoundingClientRect();
        const centerX = bounds.x + bounds.width / 2;
        const centerY = bounds.y + bounds.height / 2;
        const percentX = (event.clientX - centerX) / (bounds.width / 2);
        const percentY = (event.clientY - centerY) / (bounds.height / 2);
        const tiltX = Math.max(Math.min(percentY * -4, 6), -6);
        const tiltY = Math.max(Math.min(percentX * 4, 6), -6);
        card.style.setProperty('--tiltX', `${tiltX}deg`);
        card.style.setProperty('--tiltY', `${tiltY}deg`);
      };

      card.addEventListener('mousemove', updateTilt);
      card.addEventListener('mouseleave', () => {
        card.style.setProperty('--tiltX', '0deg');
        card.style.setProperty('--tiltY', '0deg');
      });
    });
  }

  const animatedElements = document.querySelectorAll('[data-animate], [data-animate-stagger]');
  if (prefersReducedMotion || !('IntersectionObserver' in window)) {
    animatedElements.forEach((element) => element.classList.add('is-visible'));
  } else {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            observer.unobserve(entry.target);
          }
        });
      },
      {
        threshold: 0.15,
        rootMargin: '0px 0px -80px',
      },
    );

    animatedElements.forEach((element) => observer.observe(element));
  }

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
