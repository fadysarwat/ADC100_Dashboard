/* ============================================================
   Shared front-end helpers (loaded by every protected page).

   IMPORTANT: hiding a button here is only a convenience. The server
   enforces every permission independently (src/auth.js); nothing in
   this file is a security boundary.

   Provides:
     RBAC.ready            promise; resolves after /api/me was loaded
     RBAC.me               { username, role, orgId, orgName, permissions }
     RBAC.can('perm')      does the current user hold this permission?
     RBAC.afterWsClose(fn) reconnect helper: sends the user to the login
                           page when the session ended, otherwise retries
     esc(value)            HTML-escape text before putting it in innerHTML
   and, on load:
     [data-perm="x"]       hidden unless the user holds permission x
     [data-perm-any="a b"] hidden unless the user holds at least one of them
     [data-role="r"]       hidden unless the user's role is r
     .navbar-right         gets a "who am I" badge
   ============================================================ */
(function () {
    'use strict';

    /* ── HTML escaping: ALL server data goes through this before innerHTML ── */
    window.esc = function (value) {
        return String(value === undefined || value === null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };

    const RBAC = {
        me: null,
        perms: new Set(),
        can(perm) { return this.perms.has('*') || this.perms.has(perm); },
        canAny(list) { return list.some(p => this.can(p)); },

        /* Reconnect helper for WebSocket onclose handlers. */
        afterWsClose(reconnect) {
            fetch('/api/me', { cache: 'no-store' })
                .then(r => { if (r.status === 401) window.location = '/login.html'; else setTimeout(reconnect, 3000); })
                .catch(() => setTimeout(reconnect, 3000));
        },

        /* JSON fetch that sends the user to the login page on 401. */
        async api(url, options) {
            const res = await fetch(url, options);
            if (res.status === 401) { window.location = '/login.html'; return new Promise(() => {}); }
            let data = null;
            try { data = await res.json(); } catch (_) { /* no body */ }
            return { ok: res.ok, status: res.status, data };
        },

        applyPerms(root) {
            (root || document).querySelectorAll('[data-perm],[data-perm-any],[data-role]').forEach(el => {
                let allowed = true;
                if (el.dataset.perm)    allowed = allowed && this.can(el.dataset.perm);
                if (el.dataset.permAny) allowed = allowed && this.canAny(el.dataset.permAny.split(/\s+/));
                if (el.dataset.role)    allowed = allowed && this.me && this.me.role === el.dataset.role;
                if (!allowed) {
                    el.hidden = true;
                    el.style.setProperty('display', 'none', 'important');
                }
            });
        }
    };
    window.RBAC = RBAC;

    const ROLE_LABEL = {
        super_admin: 'Platform admin',
        org_admin:   'Customer admin',
        operator:    'Operator',
        viewer:      'Viewer'
    };

    function addBadge() {
        const bar = document.querySelector('.navbar-right');
        if (!bar || !RBAC.me || document.getElementById('rbacBadge')) return;
        const span = document.createElement('span');
        span.id = 'rbacBadge';
        span.style.cssText = 'font-size:12px;color:#8A9BB5;padding:5px 10px;border:1px solid #1e2d4a;border-radius:6px;white-space:nowrap;';
        const who = RBAC.me.fullName || RBAC.me.username;
        span.innerHTML = '👤 ' + esc(who) + ' · <span style="color:#00C2FF">' + esc(ROLE_LABEL[RBAC.me.role] || RBAC.me.role) + '</span>' +
            (RBAC.me.orgName ? ' · ' + esc(RBAC.me.orgName) : '');
        bar.insertBefore(span, bar.firstChild);
    }

    const domReady = new Promise(resolve => {
        if (document.readyState !== 'loading') resolve();
        else document.addEventListener('DOMContentLoaded', resolve);
    });

    RBAC.ready = Promise.all([
        fetch('/api/me', { cache: 'no-store' }).then(r => {
            if (r.status === 401) { window.location = '/login.html'; return new Promise(() => {}); }
            return r.json();
        }),
        domReady
    ]).then(([me]) => {
        RBAC.me = me;
        RBAC.perms = new Set(me.permissions || []);
        RBAC.applyPerms(document);
        addBadge();
        document.dispatchEvent(new CustomEvent('rbac-ready', { detail: me }));
        return me;
    });
})();
