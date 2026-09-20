/* Login page (spec §9.1): login + password, one POST /admin/login, and the
 * per-IP lockout spelled out so an administrator knows how many tries are
 * left before this IP is locked for fifteen minutes. */
(function () {
  'use strict';

  var strings = {
    lockout: 'After 5 failed attempts this IP is locked for 15 minutes.',
    attemptsLeft: function (n) { return n + (n === 1 ? ' attempt left' : ' attempts left') + ' · after 5 failed attempts this IP is locked for 15 minutes.'; }
  };

  mon.start({
    data: function () {
      var el = document.getElementById('app');
      return {
        strings: strings,
        username: '',
        password: '',
        busy: false,
        error: '',
        attempts: null,
        next: (el && el.dataset.next) || '/admin/requests'
      };
    },
    computed: {
      attemptsLine: function () {
        return this.attempts === null ? strings.lockout : strings.attemptsLeft(this.attempts);
      }
    },
    methods: {
      submit: async function () {
        if (this.busy) { return; }
        this.busy = true;
        this.error = '';
        var env = await mon.api('POST', '/admin/login', {
          username: this.username,
          password: this.password,
          next: this.next
        });
        this.busy = false;
        if (!env.success) {
          this.error = env.msg;
          if (env.obj && typeof env.obj.attemptsLeft === 'number') { this.attempts = env.obj.attemptsLeft; }
          return;
        }
        location.href = (env.obj && env.obj.next) || '/admin/requests';
      }
    }
  });
})();
