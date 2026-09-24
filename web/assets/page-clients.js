/* mon-clients page (spec §9.3): the registry as the panel's inbound table —
 * "⋯" for Edit / Revoke / Delete, a switch for Enabled, the full config
 * error, the targets the box rejected with their errors, and both revisions
 * in the Edit modal. Target state is deliberately
 * absent: the panel's Monitoring page owns it. */
(function () {
  'use strict';

  var strings = {
    pathsHint: 'For boxes in hostile regions leave only proxy: direct reveals the real server\'s address to that box.',
    revokeWarning: 'The box gets 401 on its next call, wipes its state and sends a new registration request. Approve that request as a replacement to give it this id back. The registry row, its history and its paths stay.',
    deleteWarning: 'The row and its targets are removed for good. The panel drops its own copy on the next snapshot. A box that comes back gets a brand-new id.',
    nameRequired: 'Name is required.',
    pickPath: 'Pick at least one path.'
  };

  mon.start({
    data: function () {
      return {
        strings: strings,
        clients: [],
        edit: { open: false, client: null, name: '', region: '', proxy: true, direct: true, busy: false },
        revoke: { open: false, client: null, busy: false },
        remove: { open: false, client: null, busy: false }
      };
    },
    mounted: function () { this.load(); },
    methods: {
      load: async function () {
        var env = await mon.api('GET', '/admin/api/clients');
        if (!env.success) { mon.notifyErr(env.msg); return; }
        this.clients = env.obj.clients || [];
        this.now = env.obj.now;
      },
      stateLabel: function (c) {
        if (!c.enabled) { return 'disabled'; }
        if (c.state === 'NEVER') { return 'never seen'; }
        return c.state;
      },
      stateClass: function (c) { return c.enabled ? c.state : 'DISABLED'; },
      rejectedTitle: function (c) {
        return (c.rejectedTargets || []).map(function (r) { return r.target + ': ' + r.error; }).join('\n');
      },
      openEdit: function (c) {
        this.edit = {
          open: true,
          client: c,
          name: c.name,
          region: c.region,
          proxy: c.paths.indexOf('proxy') >= 0,
          direct: c.paths.indexOf('direct') >= 0,
          busy: false
        };
      },
      save: async function () {
        var e = this.edit;
        if (!e.name) { mon.notifyErr(strings.nameRequired); return; }
        var paths = [];
        if (e.proxy) { paths.push('proxy'); }
        if (e.direct) { paths.push('direct'); }
        if (!paths.length) { mon.notifyErr(strings.pickPath); return; }

        e.busy = true;
        var env = await mon.api('POST', '/admin/api/clients/' + encodeURIComponent(e.client.id), {
          name: e.name, region: e.region, paths: paths
        });
        e.busy = false;
        if (!env.success) { mon.notifyErr(env.msg); return; }
        mon.notifyOk(env.msg);
        this.edit.open = false;
        this.load();
      },
      setEnabled: async function (c, enabled) {
        var env = await mon.api('POST', '/admin/api/clients/' + encodeURIComponent(c.id) + '/enabled', { enabled: enabled });
        if (!env.success) { mon.notifyErr(env.msg); this.load(); return; }
        mon.notifyOk(env.msg);
        this.load();
      },
      askRevoke: function (c) { this.revoke = { open: true, client: c, busy: false }; },
      doRevoke: async function () {
        this.revoke.busy = true;
        var env = await mon.api('POST', '/admin/api/clients/' + encodeURIComponent(this.revoke.client.id) + '/revoke');
        this.revoke.busy = false;
        if (!env.success) { mon.notifyErr(env.msg); return; }
        mon.notifyOk(env.msg);
        this.revoke.open = false;
        this.load();
      },
      askDelete: function (c) { this.remove = { open: true, client: c, busy: false }; },
      doDelete: async function () {
        this.remove.busy = true;
        var env = await mon.api('POST', '/admin/api/clients/' + encodeURIComponent(this.remove.client.id) + '/delete');
        this.remove.busy = false;
        if (!env.success) { mon.notifyErr(env.msg); return; }
        mon.notifyOk(env.msg);
        this.remove.open = false;
        this.load();
      }
    }
  });
})();
