/* Settings page (spec §9.4): one Save at the top, the panel status line next
 * to it, and five tabs. Check and Send test use whatever is currently typed
 * into the form and save nothing; Save applies everything at once and, when
 * a probe parameter or realHost changed, rebuilds every mon-client's config
 * with a new revision. */
(function () {
  'use strict';

  var strings = {
    panelUrl: 'The panel on the real server: where /mon/v1/* answers. Polled every minute for state and probe configs. Include the webBasePath.',
    monToken: "The monToken from the panel's Monitoring settings tab. Check asks the panel for GET /state with what is typed here — nothing is saved.",
    realHost: "Host substituted into direct targets: the real server as clients reach it without the override. Defaults to the panel URL's host. Only mon-clients with the direct path ever see it.",
    proxyFront: "Read-only, as the panel reports it in GET /state. mon-server has no setting of its own: the front lives in the panel's host override, and /probe/configs already carries it.",
    telegram: 'Used when the panel is unreachable (PANEL_DOWN) and for config errors reported by mon-clients.',
    probe: 'Sent to every mon-client in its config; changing any of these bumps every config revision.',
    tls: 'From the bootstrap config, read-only here. In acme-ip mode the certificate is issued for this box\'s IP from the Let\'s Encrypt short-lived profile.',
    saved: 'Saved.'
  };

  var probeFields = [
    { key: 'intervalMs', label: 'Probe interval', hint: 'How often a mon-client runs a full probe cycle.' },
    { key: 'budgetMs', label: 'Cycle budget', hint: 'Wall-clock budget for one whole cycle.' },
    { key: 'connectMs', label: 'Connect timeout', hint: 'TCP connect timeout per target.' },
    { key: 'tlsMs', label: 'TLS timeout', hint: 'TLS handshake timeout per target.' },
    { key: 'headersMs', label: 'Headers timeout', hint: 'Time to first response headers.' },
    { key: 'startJitterMs', label: 'Start jitter', hint: 'Random delay before a cycle so boxes do not synchronise.' },
    { key: 'heartbeatTimeoutMs', label: 'Heartbeat timeout', hint: 'How long a mon-client waits for POST /v1/heartbeat.' }
  ];

  /* numericKeys are the fields the form edits as text (so that every input
   * carries its own data-testid) and the server takes as numbers. */
  var numericKeys = ['downAfter', 'upAfter', 'flapN', 'flapMin', 'flapHoldMin', 'clientOfflineAfter', 'panelDownAfter']
    .concat(probeFields.map(function (f) { return f.key; }));

  mon.start({
    data: function () {
      return {
        strings: strings,
        probeFields: probeFields,
        tab: 'real',
        form: {},
        status: { configured: false, reachable: false, polled: false, revision: '', inbounds: 0, override: { enabled: false, host: '' } },
        bootstrap: { listen: '', publicIp: '', dataDir: '', tlsMode: '', adminCommand: '', cert: null },
        busy: false,
        checking: false,
        sending: false,
        checkResult: ''
      };
    },
    computed: {
      statusLine: function () {
        if (!this.status.configured) { return 'Panel not configured yet — fill in the panel URL and the monitoring token, then Check.'; }
        if (!this.status.polled) { return 'Panel not polled yet.'; }
        var line = (this.status.reachable ? '✓ Panel reachable' : '✗ Panel unreachable (PANEL_DOWN)');
        line += ' · revision ' + (this.status.revision || '—');
        line += ' · ' + this.status.inbounds + ' inbounds';
        line += ' · override → ' + (this.status.override.enabled ? (this.status.override.host || '(on)') : 'off');
        return line;
      },
      panelHost: function () {
        try { return new URL(this.form.panelUrl).hostname; } catch (e) { return ''; }
      },
      proxyFrontLine: function () {
        if (!this.status.polled) { return 'not polled yet'; }
        return this.status.override.enabled ? ('override on → ' + (this.status.override.host || '(host not reported)')) : 'override off';
      },
      tlsLine: function () {
        var line = this.bootstrap.tlsMode || '—';
        var cert = this.bootstrap.cert;
        if (!cert) { return line + ' · no certificate yet'; }
        line += ' · ' + cert.subject + ' · expires in ' + mon.dur(cert.notAfter - this.now);
        if (cert.renewAt) { line += ' · renews in ' + mon.dur(cert.renewAt - this.now); }
        return line;
      }
    },
    mounted: function () { this.load(); },
    methods: {
      load: async function () {
        var env = await mon.api('GET', '/admin/api/settings');
        if (!env.success) { mon.notifyErr(env.msg); return; }
        this.apply(env.obj.settings);
        this.status = env.obj.panel;
        this.bootstrap = env.obj.bootstrap;
        this.now = env.obj.now;
      },
      /* apply turns the server's numbers into the strings the inputs edit;
       * payload() turns them back. Keeping the conversion in one pair of
       * methods is what lets every field be a plain <a-input> with its own
       * data-testid. */
      apply: function (s) {
        var form = {};
        Object.keys(s).forEach(function (k) {
          form[k] = numericKeys.indexOf(k) >= 0 ? String(s[k]) : s[k];
        });
        this.form = form;
      },
      payload: function () {
        var out = {};
        var form = this.form;
        Object.keys(form).forEach(function (k) {
          out[k] = numericKeys.indexOf(k) >= 0 ? Number(form[k]) : form[k];
        });
        return out;
      },
      save: async function () {
        var body = this.payload();
        var bad = Object.keys(body).filter(function (k) {
          return numericKeys.indexOf(k) >= 0 && (!Number.isFinite(body[k]) || body[k] < 0);
        });
        if (bad.length) { mon.notifyErr(bad[0] + ' must be a number, zero or more.'); return; }

        this.busy = true;
        var env = await mon.api('POST', '/admin/api/settings', body);
        this.busy = false;
        if (!env.success) { mon.notifyErr(env.msg); return; }
        mon.notifyOk(env.msg);
        this.load();
      },
      check: async function () {
        this.checking = true;
        this.checkResult = '';
        var env = await mon.api('POST', '/admin/api/settings/check', {
          panelUrl: this.form.panelUrl, monToken: this.form.monToken
        });
        this.checking = false;
        if (!env.success) { this.checkResult = env.msg; mon.notifyErr(env.msg); return; }
        this.checkResult = 'revision ' + env.obj.revision + ' · ' + env.obj.inbounds + ' inbounds · override → ' +
          (env.obj.override.enabled ? (env.obj.override.host || '(on)') : 'off') + ' · panel ' + (env.obj.panelVersion || '?');
        mon.notifyOk(env.msg);
      },
      sendTest: async function () {
        this.sending = true;
        var env = await mon.api('POST', '/admin/api/settings/telegram-test', {
          tgToken: this.form.tgToken, tgChatId: this.form.tgChatId
        });
        this.sending = false;
        if (!env.success) { mon.notifyErr(env.msg); return; }
        mon.notifyOk(env.msg);
      }
    }
  });
})();
