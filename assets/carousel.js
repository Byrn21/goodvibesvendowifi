/**
 * Carousel — Tropical Bukuhan Portal
 * Self-contained image carousel with auto-advance, swipe, and dot indicators.
 * Can be instantiated multiple times if needed on other pages.
 *
 * Usage:
 *   const carousel = new Carousel('#my-carousel', {
 *     interval: 4500,   // ms between auto-advances (default 4500)
 *     autoplay: true,   // start auto-advancing immediately (default true)
 *   });
 *   carousel.start();   // start autoplay
 *   carousel.stop();    // stop autoplay
 *   carousel.goTo(2);   // jump to slide index
 */
(function (root, factory) {
  'use strict';
  if (typeof define === 'function' && define.amd) {
    define(factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Carousel = factory();
  }
}(this, function () {
  'use strict';

  function Carousel(selector, options) {
    var el = document.querySelector(selector);
    if (!el) throw new Error('[Carousel] Element not found: ' + selector);

    this.el       = el;
    this.track    = el.querySelector('.carousel__track');
    this.dots     = Array.from(el.querySelectorAll('.carousel__dot'));
    this.slides   = Array.from(el.querySelectorAll('.carousel__slide'));
    this.prevBtn  = el.querySelector('.carousel__arrow--prev');
    this.nextBtn  = el.querySelector('.carousel__arrow--next');

    this.current  = 0;
    this.count    = this.slides.length;
    this.autoplay = options && options.autoplay !== false;
    this.interval = (options && options.interval) || 4500;
    this._timer   = null;
    this._paused  = false;

    this._bind();
  }

  Carousel.prototype._bind = function () {
    var self = this;

    // Dot clicks
    this.dots.forEach(function (dot, i) {
      dot.addEventListener('click', function () { self.goTo(i); });
    });

    // Arrow buttons
    if (this.prevBtn) this.prevBtn.addEventListener('click', function () { self.prev(); });
    if (this.nextBtn) this.nextBtn.addEventListener('click', function () { self.next(); });

    // Touch / swipe
    var startX = 0;
    this.el.addEventListener('touchstart', function (e) {
      startX = e.touches[0].clientX;
      self._onTouchStart();
    }, { passive: true });

    this.el.addEventListener('touchend', function (e) {
      var dx = e.changedTouches[0].clientX - startX;
      if (Math.abs(dx) > 44) {
        if (dx < 0) self.next(); else self.prev();
      }
    }, { passive: true });

    // Pause on hover / focus-within
    this.el.addEventListener('mouseenter', function () { self._paused = true; });
    this.el.addEventListener('mouseleave', function () { self._paused = false; });
    this.el.addEventListener('focusin', function () { self._paused = true; });
    this.el.addEventListener('focusout', function () { self._paused = false; });
  };

  Carousel.prototype._onTouchStart = function () {
    // stop auto-play while swiping
    this._paused = true;
  };

  Carousel.prototype.goTo = function (index) {
    this.current = ((index % this.count) + this.count) % this.count;
    if (this.track) {
      this.track.style.transform = 'translateX(' + (-this.current * 100) + '%)';
    }
    this._updateDots();
  };

  Carousel.prototype.next = function () { this.goTo(this.current + 1); };
  Carousel.prototype.prev = function () { this.goTo(this.current - 1); };

  Carousel.prototype._updateDots = function () {
    this.dots.forEach(function (dot, i) {
      dot.classList.toggle('is-active', i === this.current);
    }, this);
  };

  Carousel.prototype.start = function () {
    var self = this;
    if (this._timer) clearInterval(this._timer);
    this._timer = setInterval(function () {
      if (!self._paused) self.next();
    }, this.interval);
  };

  Carousel.prototype.stop = function () {
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
  };

  Carousel.prototype.restart = function () { this.stop(); this.start(); };

  return Carousel;
}));
