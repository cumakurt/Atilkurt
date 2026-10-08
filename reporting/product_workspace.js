/* Offline work-item drafts; no remote delivery or directory modifications. */
document.addEventListener('DOMContentLoaded', function () {
    'use strict';
    var node = document.getElementById('product-workspace-data');
    if (!node) return;
    var config = JSON.parse(node.textContent);
    var tickets = new Map(config.tickets.map(function (ticket) { return [ticket.finding_id, ticket]; }));
    function el(id) { return document.getElementById(id); }
    function renderTask() {
        var ticket = tickets.get(el('task-finding').value);
        el('task-owner').value = ticket && ticket.owner !== 'unassigned' ? ticket.owner : '';
        el('task-status').value = ticket && ticket.status !== 'resolved' ? ticket.status : 'open';
        el('task-notes').value = ticket ? ticket.notes || '' : '';
        el('task-due').value = ticket && ticket.due_at ? new Date(ticket.due_at).toISOString().slice(0, 16) : '';
    }
    el('task-finding').addEventListener('change', renderTask);
    el('task-draft-form').addEventListener('submit', function (event) {
        event.preventDefault();
        var identifier = el('task-finding').value;
        var owner = el('task-owner').value.trim();
        var due = el('task-due').value ? new Date(el('task-due').value + ':00Z') : null;
        if (!identifier || !owner || (due && isNaN(due))) {
            el('task-message').textContent = config.labels.invalid; return;
        }
        tickets.set(identifier, {finding_id: identifier, external_id: 'AK-' + identifier, owner: owner,
            status: el('task-status').value, due_at: due ? due.toISOString() : null, notes: el('task-notes').value});
        el('task-message').textContent = config.labels.saved;
    });
    el('task-export').addEventListener('click', function () {
        var payload = {schema_version: 1, domain: config.domain, tickets: Array.from(tickets.values())};
        var url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], {type: 'application/json'}));
        var anchor = document.createElement('a'); anchor.href = url; anchor.download = 'atilkurt-tasks.json';
        document.body.appendChild(anchor); anchor.click(); anchor.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    });
    if (!el('task-finding').options.length) {
        el('task-draft-form').querySelectorAll('input,select,textarea,button[type=submit]').forEach(function (input) { input.disabled = true; });
    }
    renderTask();
    var fresh = config.history.filter(function (run) { return run.fresh; }).reverse();
    if (fresh.length && typeof Chart !== 'undefined' && el('history-score-chart')) {
        new Chart(el('history-score-chart'), {type: 'line', data: {
            labels: fresh.map(function (run) { return run.created_at; }),
            datasets: [{label: config.labels.score, data: fresh.map(function (run) { return run.score; }), borderColor: '#38bdf8', tension: 0.15}]
        }, options: {responsive: true, maintainAspectRatio: false, scales: {y: {min: 0, max: 100}}}});
    }
});
