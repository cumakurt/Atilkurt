/* Offline drafts and bounded what-if analysis. Directory data is always text. */
document.addEventListener('DOMContentLoaded', function () {
    'use strict';
    var configElement = document.getElementById('assessment-workspace-data');
    if (!configElement) return;
    var config = JSON.parse(configElement.textContent);
    var center = config.center;
    var labels = config.labels;
    var draft = JSON.parse(JSON.stringify(center.document));
    var findings = new Map(center.findings.map(function (finding) { return [finding.finding_id, finding]; }));
    var graph = config.simulation.graph;
    var nodeLabels = new Map(graph.nodes.map(function (node) { return [node.id, node.label || node.id]; }));
    var simulationSelection = new Set(config.simulation.removed_edge_ids || []);
    function el(id) { return document.getElementById(id); }
    function tell(id, message) { el(id).textContent = labels[message] || message; }
    function download(name, body, type) {
        var url = URL.createObjectURL(new Blob([body], {type: type || 'application/json'}));
        var anchor = document.createElement('a');
        anchor.href = url; anchor.download = name;
        document.body.appendChild(anchor); anchor.click(); anchor.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }
    function exportReview() { download('atilkurt-review.json', JSON.stringify(draft, null, 2)); }
    function isoInput(date) { return date.toISOString().slice(0, 16); }
    function inputDate(id) { return new Date(el(id).value + ':00Z'); }
    function recordBase(finding) {
        return {finding_id: finding.finding_id, evidence_fingerprint: finding.evidence_fingerprint,
            rule_version: finding.rule_version};
    }
    function replaceRecord(field, record) {
        draft[field] = (draft[field] || []).filter(function (item) { return item.finding_id !== record.finding_id; });
        draft[field].push(record);
    }
    function renderChecks() {
        var finding = findings.get(el('review-finding').value);
        var container = el('review-checks'); container.replaceChildren();
        if (!finding) return;
        var saved = (draft.reviews || []).find(function (record) { return record.finding_id === finding.finding_id; });
        finding.required_checks.forEach(function (name, index) {
            var row = document.createElement('div'); row.className = 'assessment-check';
            var label = document.createElement('label'); label.textContent = labels[name] || name; label.htmlFor = 'prerequisite-' + index;
            var select = document.createElement('select'); select.id = 'prerequisite-' + index; select.dataset.check = name;
            ['unknown', 'pass', 'fail'].forEach(function (value) {
                var option = document.createElement('option'); option.value = value; option.textContent = labels[value];
                select.appendChild(option);
            });
            if (saved) {
                var check = (saved.checks || []).find(function (item) { return item.name === name; });
                if (check) select.value = check.result;
            }
            row.append(label, select); container.appendChild(row);
        });
        el('review-status').value = saved ? saved.status : 'insufficient_evidence';
        el('review-owner').value = saved ? saved.reviewer || '' : '';
        el('review-reason').value = saved ? saved.reason || '' : '';
        el('review-source').value = saved && saved.checks && saved.checks[0] ? saved.checks[0].source || '' : '';
        if (saved && saved.expires_at && !isNaN(new Date(saved.expires_at))) el('review-expiration').value = isoInput(new Date(saved.expires_at));
        if (saved && saved.checks && saved.checks[0] && !isNaN(new Date(saved.checks[0].collected_at))) el('review-collected-at').value = isoInput(new Date(saved.checks[0].collected_at));
    }
    el('review-finding').addEventListener('change', renderChecks);
    el('finding-review-form').addEventListener('submit', function (event) {
        event.preventDefault();
        var finding = findings.get(el('review-finding').value); if (!finding) return;
        var now = new Date(); var expires = inputDate('review-expiration'); var collected = inputDate('review-collected-at');
        var status = el('review-status').value;
        var checks = Array.from(el('review-checks').querySelectorAll('select')).map(function (select) {
            return {name: select.dataset.check, result: select.value, source: el('review-source').value.trim(),
                target: finding.affected_object, collected_at: isNaN(collected) ? '' : collected.toISOString()};
        });
        var valid = expires > now && el('review-owner').value.trim() && el('review-reason').value.trim();
        if (status !== 'insufficient_evidence') {
            valid = valid && !isNaN(collected) && collected <= new Date(now.getTime() + 300000) &&
                collected >= new Date(now.getTime() - center.max_age_days * 86400000) && el('review-source').value.trim();
            if (status === 'confirmed') valid = valid && checks.every(function (check) { return check.result === 'pass'; });
            if (status === 'false_positive') valid = valid && checks.some(function (check) { return check.result === 'fail'; });
        }
        if (!valid) { tell('assessment-message', 'invalid'); return; }
        var record = Object.assign(recordBase(finding), {status: status, reason: el('review-reason').value.trim(),
            reviewer: el('review-owner').value.trim(), reviewed_at: now.toISOString(), expires_at: expires.toISOString(), checks: checks});
        replaceRecord('reviews', record); tell('assessment-message', 'saved');
    });
    el('review-remove').addEventListener('click', function () {
        var id = el('review-finding').value;
        draft.reviews = (draft.reviews || []).filter(function (record) { return record.finding_id !== id; });
        renderChecks(); tell('assessment-message', 'saved');
    });
    ['review-export', 'exception-export'].forEach(function (id) { el(id).addEventListener('click', exportReview); });
    el('validation-collector-download').addEventListener('click', function () {
        download('Collect-AtilKurtEvidence.ps1', config.collector, 'text/plain');
    });
    el('review-import').addEventListener('click', function () { el('review-file-input').click(); });
    el('review-file-input').addEventListener('change', function (event) {
        var file = event.target.files[0]; if (!file) return;
        if (file.size > 16 * 1024 * 1024) { tell('assessment-message', 'invalid_import'); return; }
        var reader = new FileReader();
        reader.onload = function () {
            try {
                var loaded = JSON.parse(reader.result);
                if (loaded.schema_version !== 1 || typeof loaded.domain !== 'string' ||
                    loaded.domain.toLowerCase().replace(/\.$/, '') !== center.domain.toLowerCase().replace(/\.$/, '')) throw new Error();
                ['reviews', 'exceptions', 'observations'].forEach(function (field) {
                    loaded[field] = loaded[field] || [];
                    if (!Array.isArray(loaded[field]) || loaded[field].length > 10000 ||
                        loaded[field].some(function (row) { return !row || typeof row !== 'object' || Array.isArray(row); })) throw new Error();
                });
                loaded.reviews.forEach(function (record) {
                    if (!['confirmed', 'false_positive', 'insufficient_evidence'].includes(record.status) ||
                        !Array.isArray(record.checks || []) || (record.checks || []).length > 100) throw new Error();
                });
                draft = loaded; renderChecks(); renderExceptions(); tell('assessment-message', 'imported');
            } catch (_) { tell('assessment-message', 'invalid_import'); }
        };
        reader.onerror = function () { tell('assessment-message', 'invalid_import'); };
        reader.readAsText(file);
    });
    function renderExceptions() {
        var container = el('exception-records'); container.replaceChildren();
        (draft.exceptions || []).forEach(function (record) {
            var finding = findings.get(record.finding_id);
            var paragraph = document.createElement('p');
            var status = new Date(record.expires_at) <= new Date() ? 'expired' : 'active';
            if (finding && record.evidence_fingerprint !== finding.evidence_fingerprint) status = 'configuration_changed';
            if (record.rule_version !== center.rule_version) status = 'rule_changed';
            paragraph.textContent = (finding ? finding.affected_object : record.finding_id) + ' — ' +
                (labels[status] || status) + ' — ' + (record.owner || '') + ' — ' + (record.expires_at || '') + ' — ' + (record.reason || '');
            container.appendChild(paragraph);
        });
        if (!(draft.exceptions || []).length) container.textContent = labels.no_exceptions;
    }
    el('risk-exception-form').addEventListener('submit', function (event) {
        event.preventDefault();
        var finding = findings.get(el('exception-finding').value); if (!finding) return;
        var expires = inputDate('exception-expiration');
        if (!(expires > new Date()) || !el('exception-owner').value.trim() || !el('exception-reason').value.trim()) {
            tell('exception-message', 'invalid'); return;
        }
        replaceRecord('exceptions', Object.assign(recordBase(finding), {
            reason: el('exception-reason').value.trim(), owner: el('exception-owner').value.trim(),
            created_at: new Date().toISOString(), expires_at: expires.toISOString()
        }));
        renderExceptions(); tell('exception-message', 'saved');
    });
    el('exception-remove').addEventListener('click', function () {
        draft.exceptions = (draft.exceptions || []).filter(function (record) { return record.finding_id !== el('exception-finding').value; });
        renderExceptions(); tell('exception-message', 'removed');
    });
    function reachability(removed) {
        var reverse = new Map();
        graph.edges.forEach(function (edge) {
            if (removed.has(edge.id)) return;
            if (!reverse.has(edge.target)) reverse.set(edge.target, new Set());
            reverse.get(edge.target).add(edge.source);
        });
        var targets = new Set(graph.nodes.filter(function (node) { return node.privileged; }).map(function (node) { return node.id; }));
        var sources = new Set(graph.nodes.filter(function (node) {
            return ['user', 'computer', 'principal'].includes(node.kind) && !targets.has(node.id);
        }).map(function (node) { return node.id; }));
        var reached = new Map();
        targets.forEach(function (target) {
            var queue = [[target, 0]]; var visited = new Set([target]);
            for (var index = 0; index < queue.length; index++) {
                var current = queue[index][0]; var depth = queue[index][1];
                if (sources.has(current)) {
                    if (!reached.has(current)) reached.set(current, new Set());
                    reached.get(current).add(target);
                }
                if (depth >= graph.max_depth) continue;
                (reverse.get(current) || []).forEach(function (previous) {
                    if (!visited.has(previous)) { visited.add(previous); queue.push([previous, depth + 1]); }
                });
            }
        });
        return reached;
    }
    var originalReach = reachability(new Set());
    function pairs(reached) { var total = 0; reached.forEach(function (targets) { total += targets.size; }); return total; }
    function runSimulation() {
        if (config.simulation.available === false) {
            ['simulation-before', 'simulation-after', 'simulation-before-pairs', 'simulation-after-pairs'].forEach(function (id) { el(id).textContent = labels.unknown; });
            tell('simulation-message', 'simulation_limit');
            return;
        }
        var result = reachability(simulationSelection);
        el('simulation-before').textContent = originalReach.size; el('simulation-after').textContent = result.size;
        el('simulation-before-pairs').textContent = pairs(originalReach); el('simulation-after-pairs').textContent = pairs(result);
        var list = el('simulation-closed'); list.replaceChildren();
        originalReach.forEach(function (_, source) {
            if (!result.has(source)) { var item = document.createElement('li'); item.textContent = nodeLabels.get(source) || source; list.appendChild(item); }
        });
        tell('simulation-message', graph.edges.length ? 'updated' : 'no_graph');
    }
    function renderSimulationEdges() {
        var query = el('simulation-filter').value.trim().toLowerCase();
        var matching = graph.edges.filter(function (edge) {
            return [nodeLabels.get(edge.source) || edge.source, nodeLabels.get(edge.target) || edge.target, edge.type, edge.permission || ''].join(' ').toLowerCase().includes(query);
        });
        el('simulation-edges').replaceChildren();
        el('simulation-edge-count').textContent = labels.edge_display + ': ' + Math.min(300, matching.length) + ' / ' + matching.length;
        matching.slice(0, 300).forEach(function (edge) {
            var label = document.createElement('label'); var checkbox = document.createElement('input');
            checkbox.type = 'checkbox'; checkbox.value = edge.id; checkbox.checked = simulationSelection.has(edge.id);
            checkbox.addEventListener('change', function () {
                if (checkbox.checked) simulationSelection.add(edge.id); else simulationSelection.delete(edge.id);
            });
            var name = document.createElement('span');
            name.textContent = (nodeLabels.get(edge.source) || edge.source) + ' → ' + (nodeLabels.get(edge.target) || edge.target) + ' (' + edge.type + (edge.permission ? ': ' + edge.permission : '') + ')';
            label.append(checkbox, name); el('simulation-edges').appendChild(label);
        });
    }
    var filterTimer;
    el('simulation-filter').addEventListener('input', function () {
        clearTimeout(filterTimer); filterTimer = setTimeout(renderSimulationEdges, 150);
    });
    renderSimulationEdges();
    el('simulation-run').addEventListener('click', runSimulation);
    el('simulation-reset').addEventListener('click', function () {
        simulationSelection.clear(); el('simulation-edges').querySelectorAll('input').forEach(function (input) { input.checked = false; }); runSimulation();
    });
    el('simulation-export').addEventListener('click', function () {
        download('atilkurt-scenario.json', JSON.stringify({schema_version: 1, removed_edge_ids: Array.from(simulationSelection).sort()}, null, 2));
    });
    var now = new Date(); var expiry = new Date(now.getTime() + center.max_age_days * 86400000);
    el('review-collected-at').value = isoInput(now);
    ['review-expiration', 'exception-expiration'].forEach(function (id) { el(id).value = isoInput(expiry); });
    if (!findings.size) {
        [el('finding-review-form'), el('risk-exception-form')].forEach(function (form) {
            form.querySelectorAll('input,select,textarea,button').forEach(function (input) { input.disabled = true; });
        });
        tell('assessment-message', 'no_findings');
    }
    renderChecks(); renderExceptions(); runSimulation();
});
