// ========== THROTTLE HELPER FOR PERFORMANCE ==========
function throttle(func, delay) {
  let timeout = null;
  return function (...args) {
    if (!timeout) {
      timeout = setTimeout(() => {
        func.apply(this, args);
        timeout = null;
      }, delay);
    }
  };
}

// ========== CUSTOM CURSOR ==========
const cursor = document.createElement('div');
cursor.className = 'custom-cursor';
document.body.appendChild(cursor);

const cursorDot = document.createElement('div');
cursorDot.className = 'custom-cursor-dot';
document.body.appendChild(cursorDot);

let mouseX = 0, mouseY = 0;
let cursorX = 0, cursorY = 0;
let dotX = 0, dotY = 0;

// Throttled mousemove for better performance
document.addEventListener('mousemove', throttle((e) => {
  mouseX = e.clientX;
  mouseY = e.clientY;
  dotX = e.clientX;
  dotY = e.clientY;
}, 16)); // ~60fps


function animateCursor() {
  cursorX += (mouseX - cursorX) * 0.15;
  cursorY += (mouseY - cursorY) * 0.15;
  cursor.style.left = cursorX + 'px';
  cursor.style.top = cursorY + 'px';

  cursorDot.style.left = dotX + 'px';
  cursorDot.style.top = dotY + 'px';

  requestAnimationFrame(animateCursor);
}
animateCursor();

// Cursor hover effects
const hoverElements = document.querySelectorAll('a, button, .card, .btn, .nav-link, .price-card');
hoverElements.forEach(el => {
  el.addEventListener('mouseenter', () => cursor.classList.add('hover'));
  el.addEventListener('mouseleave', () => cursor.classList.remove('hover'));
});

// ========== PARTICLE SYSTEM WITH MOUSE INTERACTION ==========
const canvas = document.createElement('canvas');
canvas.id = 'particleCanvas';
document.body.prepend(canvas);
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

window.addEventListener('resize', () => {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
});

// Mouse tracking for antigravity effect
let mouseParticleX = -1000;
let mouseParticleY = -1000;

document.addEventListener('mousemove', throttle((e) => {
  mouseParticleX = e.clientX;
  mouseParticleY = e.clientY;
}, 16));

class Particle {
  constructor() {
    this.x = Math.random() * canvas.width;
    this.y = Math.random() * canvas.height;
    this.baseVx = (Math.random() - 0.5) * 0.3;
    this.baseVy = (Math.random() - 0.5) * 0.3;
    this.vx = this.baseVx;
    this.vy = this.baseVy;
    this.radius = Math.random() * 2 + 1;
    this.opacity = Math.random() * 0.4 + 0.1;
  }

  update() {
    // Antigravity effect - particles move away from mouse
    const dx = this.x - mouseParticleX;
    const dy = this.y - mouseParticleY;
    const distance = Math.sqrt(dx * dx + dy * dy);
    const maxDistance = 150;

    if (distance < maxDistance && distance > 0) {
      // Push particles away from mouse
      const force = (maxDistance - distance) / maxDistance;
      const angle = Math.atan2(dy, dx);
      this.vx += Math.cos(angle) * force * 0.5;
      this.vy += Math.sin(angle) * force * 0.5;
    }

    // Gradually return to base velocity
    this.vx += (this.baseVx - this.vx) * 0.02;
    this.vy += (this.baseVy - this.vy) * 0.02;

    // Apply velocity
    this.x += this.vx;
    this.y += this.vy;

    // Bounce off edges
    if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
    if (this.y < 0 || this.y > canvas.height) this.vy *= -1;

    // Keep in bounds
    this.x = Math.max(0, Math.min(canvas.width, this.x));
    this.y = Math.max(0, Math.min(canvas.height, this.y));
  }

  draw() {
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(0, 212, 255, ${this.opacity})`;
    ctx.fill();
  }
}

const particles = [];
for (let i = 0; i < 80; i++) {
  particles.push(new Particle());
}

function connectParticles() {
  for (let i = 0; i < particles.length; i++) {
    for (let j = i + 1; j < particles.length; j++) {
      const dx = particles[i].x - particles[j].x;
      const dy = particles[i].y - particles[j].y;
      const distance = Math.sqrt(dx * dx + dy * dy);

      if (distance < 100) {
        ctx.beginPath();
        ctx.moveTo(particles[i].x, particles[i].y);
        ctx.lineTo(particles[j].x, particles[j].y);
        ctx.strokeStyle = `rgba(0, 212, 255, ${0.15 * (1 - distance / 100)})`;
        ctx.lineWidth = 0.5;
        ctx.stroke();
      }
    }
  }
}

function animateParticles() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  particles.forEach(particle => {
    particle.update();
    particle.draw();
  });

  connectParticles();
  requestAnimationFrame(animateParticles);
}
animateParticles();

// ========== NAVBAR SCROLL EFFECT ==========
const navbar = document.querySelector('.glass-nav');
window.addEventListener('scroll', () => {
  if (window.scrollY > 50) {
    navbar.classList.add('scrolled');
  } else {
    navbar.classList.remove('scrolled');
  }
});

// ========== YEAR IN FOOTER ==========
document.getElementById('year').textContent = new Date().getFullYear();

// ========== SMOOTH SCROLL ==========
const links = document.querySelectorAll('a[href^="#"]:not([data-bs-toggle])');
links.forEach(a => a.addEventListener('click', e => {
  const target = document.querySelector(a.getAttribute('href'));
  if (target) {
    e.preventDefault();
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}));

// ========== REVEAL ON SCROLL ==========
const revealables = document.querySelectorAll('.reveal, .reveal-fly');
const io = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('revealed');
      io.unobserve(entry.target);
    }
  });
}, { threshold: 0.1 });
revealables.forEach(el => io.observe(el));

// ========== STAGGER ANIMATION FOR FEATURE LISTS ==========
const featureLists = document.querySelectorAll('.feature-list');
featureLists.forEach(list => {
  const items = list.querySelectorAll('li');
  items.forEach((item, index) => {
    item.classList.add('stagger-item');
    item.style.transitionDelay = `${index * 0.1}s`;
  });

  const listObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        items.forEach(item => item.classList.add('revealed'));
        listObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.2 });

  listObserver.observe(list);
});

// ========== BACK TO TOP BUTTON ==========
const backBtn = document.getElementById('backToTop');
window.addEventListener('scroll', () => {
  backBtn.classList.toggle('show', window.scrollY > 600);
});
backBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));

// ========== SUBTLE 3D TILT EFFECT ON CARDS ==========
const tiltCards = document.querySelectorAll('.card.glass, .price-card');
tiltCards.forEach(card => {
  card.addEventListener('mousemove', (e) => {
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const centerX = rect.width / 2;
    const centerY = rect.height / 2;

    // Reduced rotation values for subtler effect
    const rotateX = (y - centerY) / 40;
    const rotateY = (centerX - x) / 40;

    card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-4px) scale(1.01)`;
  });

  card.addEventListener('mouseleave', () => {
    card.style.transform = '';
  });
});

// ========== MAGNETIC BUTTON EFFECT ==========
const magneticButtons = document.querySelectorAll('.btn-primary, .btn-outline-light');
magneticButtons.forEach(btn => {
  btn.addEventListener('mousemove', (e) => {
    const rect = btn.getBoundingClientRect();
    const x = e.clientX - rect.left - rect.width / 2;
    const y = e.clientY - rect.top - rect.height / 2;

    btn.style.transform = `translate(${x * 0.3}px, ${y * 0.3}px) scale(1.05)`;
  });

  btn.addEventListener('mouseleave', () => {
    btn.style.transform = '';
  });
});

// ========== SCROLL PROGRESS BAR ==========
const scrollProgress = document.getElementById('scrollProgress');
if (scrollProgress) {
  window.addEventListener('scroll', () => {
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    const scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    const progress = (scrollTop / scrollHeight) * 100;
    scrollProgress.style.width = progress + '%';
  });
}

// ========== TERMINAL TYPING ANIMATION ==========
const terminalText = document.getElementById('terminalText');
if (terminalText) {
  const commands = [
    'diag-agent --scan --full',
    'trivy fs / --severity HIGH,CRITICAL',
    'nmap -sV -sC localhost',
    'ssh-audit 127.0.0.1',
    'diag-agent --report --pdf',
    'systemctl status diag-agent',
    'cat /var/log/auth.log | grep Failed'
  ];

  let commandIndex = 0;
  let charIndex = 0;
  let isDeleting = false;
  let currentCommand = '';

  function typeTerminal() {
    currentCommand = commands[commandIndex];

    if (!isDeleting) {
      // Typing
      terminalText.textContent = currentCommand.substring(0, charIndex);
      charIndex++;

      if (charIndex > currentCommand.length) {
        // Pause before deleting
        isDeleting = true;
        setTimeout(typeTerminal, 2000);
        return;
      }
      setTimeout(typeTerminal, 80 + Math.random() * 40);
    } else {
      // Deleting
      terminalText.textContent = currentCommand.substring(0, charIndex);
      charIndex--;

      if (charIndex < 0) {
        isDeleting = false;
        charIndex = 0;
        commandIndex = (commandIndex + 1) % commands.length;
        setTimeout(typeTerminal, 500);
        return;
      }
      setTimeout(typeTerminal, 30);
    }
  }

  // Start after delay
  setTimeout(typeTerminal, 1500);
}

// ========== NUMBER COUNTER ANIMATION ==========
function animateCounter(element, target, duration = 2000) {
  let start = 0;
  const increment = target / (duration / 16);

  function updateCounter() {
    start += increment;
    if (start < target) {
      element.textContent = Math.floor(start);
      requestAnimationFrame(updateCounter);
    } else {
      element.textContent = target;
    }
  }

  updateCounter();
}

// Example: If you want to add counters, add elements with class 'counter' and data-target attribute
const counters = document.querySelectorAll('.counter');
const counterObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const target = parseInt(entry.target.getAttribute('data-target'));
      animateCounter(entry.target, target);
      counterObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.5 });

counters.forEach(counter => counterObserver.observe(counter));

// ========== TOAST NOTIFICATION ==========
function toast(msg, type = 'dark') {
  const t = document.createElement('div');
  t.className = 'position-fixed bottom-0 end-0 p-3';
  t.style.zIndex = '9999';
  t.innerHTML = `
    <div class="toast align-items-center text-bg-${type} border-0 show" role="alert" style="border: 1px solid rgba(0,212,255,0.5); box-shadow: 0 8px 30px rgba(0,0,0,0.6), 0 0 40px rgba(0,212,255,0.3);">
      <div class="d-flex">
        <div class="toast-body" style="font-weight: 500;">${msg}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Tanca"></button>
      </div>
    </div>
  `;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ========== FORM HANDLERS ==========
document.getElementById('contactForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const email = fd.get('email');

  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    toast('⚠️ Si us plau, introdueix un email vàlid', 'warning');
    return;
  }

  console.log('Contact form:', Object.fromEntries(fd.entries()));

  // Add loading state
  const submitBtn = e.target.querySelector('button[type="submit"]');
  const originalContent = submitBtn.innerHTML;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Enviant...';

  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 1500));

  // Success state
  submitBtn.innerHTML = '<i class="bi bi-check-circle"></i> Enviat!';
  submitBtn.classList.remove('btn-primary');
  submitBtn.classList.add('btn-success');

  toast('✨ Gràcies! Ens posarem en contacte ben aviat.', 'success');

  setTimeout(() => {
    e.target.reset();
    submitBtn.innerHTML = originalContent;
    submitBtn.classList.remove('btn-success');
    submitBtn.classList.add('btn-primary');
    submitBtn.disabled = false;
  }, 3000);
});

// ========== PARALLAX EFFECT ==========
window.addEventListener('scroll', () => {
  const scrolled = window.pageYOffset;
  const parallaxElements = document.querySelectorAll('.hero-device');

  parallaxElements.forEach(el => {
    const speed = 0.3;
    el.style.transform = `translateY(${scrolled * speed}px)`;
  });
});

// ========== ADD RIPPLE EFFECT ON CLICK ==========
document.querySelectorAll('.btn, .card').forEach(element => {
  element.addEventListener('click', function (e) {
    const ripple = document.createElement('span');
    const rect = this.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = e.clientX - rect.left - size / 2;
    const y = e.clientY - rect.top - size / 2;

    ripple.style.width = ripple.style.height = size + 'px';
    ripple.style.left = x + 'px';
    ripple.style.top = y + 'px';
    ripple.style.position = 'absolute';
    ripple.style.borderRadius = '50%';
    ripple.style.background = 'rgba(0, 212, 255, 0.5)';
    ripple.style.pointerEvents = 'none';
    ripple.style.animation = 'ripple 0.6s ease-out';

    this.style.position = 'relative';
    this.style.overflow = 'hidden';
    this.appendChild(ripple);

    setTimeout(() => ripple.remove(), 600);
  });
});

// Add ripple animation to CSS dynamically
const style = document.createElement('style');
style.textContent = `
  @keyframes ripple {
    to {
      transform: scale(2);
      opacity: 0;
    }
  }
`;
document.head.appendChild(style);

// ========== ENHANCE PRICE CARDS WITH SPOTLIGHT ==========
const priceCards = document.querySelectorAll('.price-card');
priceCards.forEach(card => {
  card.addEventListener('mousemove', (e) => {
    const rect = card.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100;
    const y = ((e.clientY - rect.top) / rect.height) * 100;

    card.style.background = `
      radial-gradient(circle at ${x}% ${y}%, rgba(0,212,255,0.15), transparent 50%),
      linear-gradient(135deg, rgba(13,20,38,.9), rgba(10,17,34,.9))
    `;
  });

  card.addEventListener('mouseleave', () => {
    card.style.background = '';
  });
});

// ========== APP SCREENSHOTS CAROUSEL ==========
class AppCarousel {
  constructor(container) {
    this.container = container;
    this.slides = container.querySelectorAll('.carousel-slide');
    this.indicators = container.querySelectorAll('.indicator');
    this.prevBtn = container.querySelector('.carousel-arrow-left');
    this.nextBtn = container.querySelector('.carousel-arrow-right');
    this.currentSlideSpan = container.querySelector('.current-slide');
    this.totalSlides = this.slides.length;
    this.currentIndex = 0;
    this.autoPlayInterval = null;
    this.autoPlayDelay = 4000; // 4 seconds

    this.init();
  }

  init() {
    // Navigation buttons
    this.prevBtn.addEventListener('click', () => this.prevSlide());
    this.nextBtn.addEventListener('click', () => this.nextSlide());

    // Indicators
    this.indicators.forEach((indicator, index) => {
      indicator.addEventListener('click', () => this.goToSlide(index));
    });

    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
      if (this.isInViewport()) {
        if (e.key === 'ArrowLeft') this.prevSlide();
        if (e.key === 'ArrowRight') this.nextSlide();
      }
    });

    // Touch swipe support
    let touchStartX = 0;
    let touchEndX = 0;

    this.container.addEventListener('touchstart', (e) => {
      touchStartX = e.changedTouches[0].screenX;
    });

    this.container.addEventListener('touchend', (e) => {
      touchEndX = e.changedTouches[0].screenX;
      this.handleSwipe();
    });

    const handleSwipe = () => {
      if (touchEndX < touchStartX - 50) this.nextSlide();
      if (touchEndX > touchStartX + 50) this.prevSlide();
    };

    this.handleSwipe = handleSwipe;

    // Start auto-play
    this.startAutoPlay();

    // Pause on hover
    this.container.addEventListener('mouseenter', () => this.pauseAutoPlay());
    this.container.addEventListener('mouseleave', () => this.startAutoPlay());
  }

  goToSlide(index) {
    // Remove active class from current slide and indicator
    this.slides[this.currentIndex].classList.remove('active');
    this.indicators[this.currentIndex].classList.remove('active');

    // Update index
    this.currentIndex = index;

    // Add active class to new slide and indicator
    this.slides[this.currentIndex].classList.add('active');
    this.indicators[this.currentIndex].classList.add('active');

    // Update counter
    this.currentSlideSpan.textContent = this.currentIndex + 1;

    // Reset auto-play
    this.resetAutoPlay();
  }

  nextSlide() {
    const nextIndex = (this.currentIndex + 1) % this.totalSlides;
    this.goToSlide(nextIndex);
  }

  prevSlide() {
    const prevIndex = (this.currentIndex - 1 + this.totalSlides) % this.totalSlides;
    this.goToSlide(prevIndex);
  }

  startAutoPlay() {
    this.pauseAutoPlay(); // Clear any existing interval
    this.autoPlayInterval = setInterval(() => {
      this.nextSlide();
    }, this.autoPlayDelay);
  }

  pauseAutoPlay() {
    if (this.autoPlayInterval) {
      clearInterval(this.autoPlayInterval);
      this.autoPlayInterval = null;
    }
  }

  resetAutoPlay() {
    this.startAutoPlay();
  }

  isInViewport() {
    const rect = this.container.getBoundingClientRect();
    return (
      rect.top >= 0 &&
      rect.left >= 0 &&
      rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
      rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
  }
}

// Initialize carousel when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  const carouselContainer = document.querySelector('.app-carousel');
  if (carouselContainer) {
    new AppCarousel(carouselContainer);
  }
});

console.log('🚀 Cybershield Solutions - Enhanced Edition Loaded!');

// ========== COOKIE CONSENT BANNER ==========
(function initCookieConsent() {
  const cookieBanner = document.getElementById('cookieBanner');
  const cookieEssentialBtn = document.getElementById('cookieEssential');
  const cookieAllBtn = document.getElementById('cookieAll');

  // Check if user has already made a choice
  const cookieChoice = localStorage.getItem('cookieConsent');

  if (!cookieChoice && cookieBanner) {
    // Show banner after a short delay for better UX
    setTimeout(() => {
      cookieBanner.classList.add('show');
    }, 1000);
  }

  // Handle "Essential only" button
  if (cookieEssentialBtn) {
    cookieEssentialBtn.addEventListener('click', () => {
      localStorage.setItem('cookieConsent', 'essential');
      localStorage.setItem('cookieConsentDate', new Date().toISOString());
      hideCookieBanner();
      toast('🍪 Cookies essencials acceptades', 'info');
      console.log('Cookie consent: essential only');
    });
  }

  // Handle "Accept all" button
  if (cookieAllBtn) {
    cookieAllBtn.addEventListener('click', () => {
      localStorage.setItem('cookieConsent', 'all');
      localStorage.setItem('cookieConsentDate', new Date().toISOString());
      hideCookieBanner();
      toast('🍪 Totes les cookies acceptades', 'success');
      console.log('Cookie consent: all cookies');
      // Here you would initialize analytics, marketing cookies, etc.
      initAnalytics();
    });
  }

  function hideCookieBanner() {
    if (cookieBanner) {
      cookieBanner.classList.remove('show');
      // Remove from DOM after animation
      setTimeout(() => {
        cookieBanner.style.display = 'none';
      }, 500);
    }
  }

  function initAnalytics() {
    // Placeholder for Google Analytics or other tracking
    console.log('Analytics initialized (placeholder)');
    // Example: would load GA4, Hotjar, etc.
  }

  // Check if all cookies were accepted previously and init analytics
  if (cookieChoice === 'all') {
    initAnalytics();
  }
})();
