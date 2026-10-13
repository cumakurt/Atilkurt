"""Dedicated Domain Admin takeover map for the HTML report."""

from __future__ import annotations

import html as html_stdlib
from typing import Any


class DomainAdminSectionMixin:
    """Render pentest-oriented Domain Admin takeover paths."""

    def _generate_domain_admin_takeover_section(
        self,
        takeover: dict[str, Any] | None,
        domain: str | None = None,
        dc_ip: str | None = None,
    ) -> str:
        """Return HTML for the Domain Admin takeover map tab."""
        takeover = takeover or {}
        summary = takeover.get("summary") or {}
        open_paths = takeover.get("open_paths") or []
        pending_paths = takeover.get("pending_paths") or []
        unobserved = takeover.get("unobserved_paths") or []
        headline = html_stdlib.escape(str(summary.get("headline") or "Domain Admin takeover map."))
        domain_label = html_stdlib.escape(str(domain or "DOMAIN"))
        dc_label = html_stdlib.escape(str(dc_ip or "DC_IP"))

        open_count = int(summary.get("open_path_count") or 0)
        da_count = int(summary.get("da_equivalent_open_count") or 0)
        critical_count = int(summary.get("critical_open_count") or 0)
        high_count = int(summary.get("high_open_count") or 0)
        catalog_count = int(summary.get("catalog_count") or 0)
        option_count = int(summary.get("option_count") or 0)
        evidence_count = int(summary.get("evidence_finding_count") or 0)
        from_account = takeover.get("from_assessment_account") or {}
        starters = takeover.get("nonadmin_starters") or {}
        starter_count = int(summary.get("nonadmin_starter_count") or starters.get("principal_count") or 0)
        account_html = self._da_assessment_account_block(from_account)
        starters_html = self._da_nonadmin_starters_block(starters)
        existing_html = self._da_existing_access(takeover.get("existing_access") or [])

        categories = []
        for path in open_paths:
            category = str(path.get("category") or "other")
            if category not in categories:
                categories.append(category)

        filter_buttons = ['<button type="button" class="btn btn-sm btn-outline-light da-filter active" data-da-filter="all">All open paths</button>']
        for category in categories:
            label = html_stdlib.escape(category.replace("_", " ").title())
            filter_buttons.append(
                f'<button type="button" class="btn btn-sm btn-outline-light da-filter" data-da-filter="{html_stdlib.escape(category)}">{label}</button>'
            )

        open_html = (
            self._da_empty_state()
            if not open_paths
            else "".join(self._da_path_card(path, emphasized=True) for path in open_paths)
        )
        unobserved_html = "".join(self._da_path_card(path, emphasized=False) for path in unobserved)
        pending_html = ""
        if pending_paths:
            cards = "".join(self._da_path_card(path, emphasized=False) for path in pending_paths)
            pending_html = (
                '<h5 class="mt-4">Paths requiring validation</h5>'
                '<p>These indicators are excluded from open-path counts and risk scores. '
                'Verify the missing prerequisites before treating them as exploitable.</p>'
                f'<div id="da-pending-paths">{cards}</div>'
            )

        return f"""
        <style>
            .da-hero {{
                background: linear-gradient(135deg, rgba(255,107,0,.12), rgba(15,23,42,.9));
                border: 1px solid rgba(255,107,0,.35);
                border-radius: 16px;
                padding: 1.5rem;
                margin-bottom: 1.25rem;
            }}
            .da-kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: .75rem; margin-top: 1rem; }}
            .da-kpi {{ background: rgba(2,6,23,.55); border-radius: 12px; padding: .9rem; }}
            .da-kpi .n {{ font-size: 1.6rem; font-weight: 700; color: #ff9f66; }}
            .da-kpi .l {{ color: #94a3b8; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }}
            .da-path {{
                border: 1px solid rgba(148,163,184,.2);
                border-radius: 14px;
                padding: 1.1rem 1.25rem;
                margin-bottom: 1rem;
                background: rgba(15,23,42,.55);
            }}
            .da-path.is-critical {{ border-color: rgba(239,68,68,.55); }}
            .da-path.is-high {{ border-color: rgba(249,115,22,.45); }}
            .da-path.is-closed {{ opacity: .82; }}
            .da-path h4 {{ margin: 0 0 .35rem 0; }}
            .da-meta {{ display: flex; flex-wrap: wrap; gap: .4rem; margin-bottom: .75rem; }}
            .da-stage {{
                display: grid;
                grid-template-columns: auto 1fr;
                gap: .35rem 0.8rem;
                margin: .35rem 0;
            }}
            .da-num {{
                width: 1.6rem; height: 1.6rem; border-radius: 999px;
                background: #ff6b00; color: #111; font-weight: 700;
                display: flex; align-items: center; justify-content: center;
                font-size: .85rem;
            }}
            .da-why {{ color: #cbd5e1; font-size: .92rem; }}
            .da-break li {{ margin-bottom: .25rem; }}
            .da-poc {{
                border-left: 3px solid #ff6b00;
                padding-left: .9rem;
                margin: .5rem 0 1rem;
            }}
            .da-poc-step {{ margin-bottom: .85rem; }}
            .da-expected {{ color: #86efac; font-size: .86rem; }}
            .da-cmd {{
                background: rgba(2,6,23,.7);
                border-radius: 10px;
                padding: .75rem .9rem;
                margin-bottom: .65rem;
            }}
            .da-cmd pre {{
                margin: .35rem 0 0 0;
                white-space: pre-wrap;
                word-break: break-word;
            }}
            .da-evidence-list {{
                max-height: 16rem;
                overflow: auto;
                padding-right: .35rem;
            }}
            .da-route {{
                font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                font-size: .86rem;
                margin: .25rem 0;
            }}
        </style>
        <div class="da-hero">
            <h3 class="mb-2"><i class="fas fa-crown text-warning"></i> Domain Admin takeover map</h3>
            <p class="mb-0">{headline}</p>
            <p class="text-muted small mt-2 mb-0">
                This view is written the way an internal penetration test is scoped: every technique that
                can become Domain Admin (or a Domain Admin equivalent such as DCSync, KRBTGT, or a
                privileged certificate). Each open path is backed by findings from this scan. Every path
                includes a step-by-step procedure. Each step states what to do, the example command,
                and the evidence to record. Commands are templates for authorized engagements only.
            </p>
            <p class="text-muted small mt-2 mb-0">
                Domain: <code>{domain_label}</code> | DC: <code>{dc_label}</code>.
                Use only in authorized engagements.
            </p>
            <div class="da-kpis">
                <div class="da-kpi"><div class="n">{open_count}</div><div class="l">Open paths</div></div>
                <div class="da-kpi"><div class="n">{da_count}</div><div class="l">DA-equivalent</div></div>
                <div class="da-kpi"><div class="n">{critical_count}</div><div class="l">Critical</div></div>
                <div class="da-kpi"><div class="n">{high_count}</div><div class="l">High</div></div>
                <div class="da-kpi"><div class="n">{catalog_count}</div><div class="l">Techniques in catalog</div></div>
                <div class="da-kpi"><div class="n">{option_count}</div><div class="l">Object options</div></div>
                <div class="da-kpi"><div class="n">{evidence_count}</div><div class="l">Mapped findings</div></div>
                <div class="da-kpi"><div class="n">{starter_count}</div><div class="l">Non-admin footholds</div></div>
            </div>
        </div>
        <div class="alert alert-info" role="note">
            <strong>Evidence boundary:</strong> Observed conditions and graph reachability are not a completed takeover.
            Existing nested administrator membership is current access. Credential recovery, service reachability,
            conditional permissions and end-to-end exploitation require separate proof. PoC examples are not executed by this report.
        </div>
        {account_html}
        {existing_html}
        {starters_html}
        <div class="mb-3 d-flex flex-wrap gap-2">{''.join(filter_buttons)}</div>
        <h5 class="mb-3">Open paths evidenced in this domain</h5>
        <div id="da-open-paths">{open_html}</div>
        {pending_html}
        <div class="card mt-4">
            <div class="card-header" data-bs-toggle="collapse" data-bs-target="#da-unobserved" style="cursor:pointer">
                <i class="fas fa-clipboard-list"></i>
                Remaining pentest catalog ({len(unobserved)} techniques not evidenced in this scan)
            </div>
            <div id="da-unobserved" class="collapse">
                <div class="card-body">
                    <p class="text-muted small">
                        Absence of evidence is not evidence of absence. These techniques remain on a
                        Domain Admin assessment checklist even when this LDAP-only scan did not observe
                        the supporting attributes. Each catalog entry still includes the PoC roadmap
                        and command templates.
                    </p>
                    {unobserved_html}
                </div>
            </div>
        </div>
        <script>
        (function() {{
            document.querySelectorAll('.da-filter').forEach(function(btn) {{
                btn.addEventListener('click', function() {{
                    document.querySelectorAll('.da-filter').forEach(function(b) {{ b.classList.remove('active'); }});
                    btn.classList.add('active');
                    var key = btn.getAttribute('data-da-filter');
                    document.querySelectorAll('#da-open-paths .da-path').forEach(function(card) {{
                        card.style.display = (key === 'all' || card.getAttribute('data-da-category') === key) ? '' : 'none';
                    }});
                }});
            }});
        }})();
        </script>
        """

    def _da_existing_access(self, rows: list[dict[str, Any]]) -> str:
        if not rows:
            return ""
        items = []
        for row in rows:
            label = html_stdlib.escape(str(row.get("label") or ""))
            sid = html_stdlib.escape(str(row.get("sid") or ""))
            parents = html_stdlib.escape(", ".join(str(value) for value in row.get("memberships") or []))
            access = "Existing Tier-0 membership" if row.get("tier0") else "Sensitive delegated access; Tier-0 not established"
            items.append(f"<li><strong>{label}</strong> — <span>{access}</span><br><code>{sid}</code><br><code>{parents}</code></li>")
        return ('<details class="card p-3 mb-3 da-existing-access"><summary>Existing privileged and delegated access</summary>'
                '<p>These are current memberships, not newly acquired privileges. DNS and operator groups require additional evidence for a Tier-0 claim.</p>'
                '<ul>' + "".join(items) + '</ul></details>')

    def _da_assessment_account_block(self, account: dict[str, Any]) -> str:
        if not account:
            return ""
        sam = html_stdlib.escape(str(account.get("sam") or "unresolved"))
        headline = html_stdlib.escape(str(account.get("headline") or ""))
        token = html_stdlib.escape(str(account.get("token_status") or "skipped"))
        limitation = html_stdlib.escape(str(account.get("limitation") or ""))
        grouped = account.get("routes_by_target") or []
        routes = account.get("routes") or []
        route_html = ""
        if grouped:
            blocks = []
            for group in grouped:
                target = html_stdlib.escape(str(group.get("target_label") or group.get("target") or ""))
                count = int(group.get("route_count") or 0)
                shortest = group.get("shortest_hops")
                header = (
                    f"<h6 class='mt-2 mb-1'><code>{target}</code> — {count} route(s)"
                    f"{f', shortest {html_stdlib.escape(str(shortest))} hop(s)' if shortest is not None else ''}</h6>"
                )
                items = []
                for route in group.get("routes") or []:
                    labels = " → ".join(html_stdlib.escape(str(label)) for label in (route.get("labels") or []))
                    hops = int(route.get("hop_count") or 0)
                    types = ", ".join(
                        html_stdlib.escape(str(hop.get("type") or ""))
                        for hop in (route.get("hops") or [])
                        if hop.get("type")
                    )
                    extra = f" <span class='text-muted'>({html_stdlib.escape(types)})</span>" if types else ""
                    items.append(f"<div class='da-route'>{hops} hop: {labels}{extra}</div>")
                blocks.append(header + "".join(items))
            route_html = (
                f"<h6 class='mt-3'>Routes from this account ({len(routes)})</h6>" + "".join(blocks)
            )
        elif routes:
            items = []
            for route in routes:
                labels = " → ".join(html_stdlib.escape(str(label)) for label in (route.get("labels") or []))
                hops = int(route.get("hop_count") or 0)
                items.append(f"<div class='da-route'>{hops} hop: {labels}</div>")
            route_html = "<h6 class='mt-3'>Routes from this account</h6>" + "".join(items)
        templates = account.get("enrollable_templates") or []
        template_html = ""
        if templates:
            items = []
            for item in templates:
                name = html_stdlib.escape(str(item.get("template") or ""))
                trustees = ", ".join(html_stdlib.escape(str(value)) for value in (item.get("trustees") or [])[:6])
                cas = ", ".join(html_stdlib.escape(str(value)) for value in (item.get("published_cas") or [])[:4])
                items.append(
                    f"<li><code>{name}</code> via {trustees or 'enroll'}"
                    f"{f' on {cas}' if cas else ''}</li>"
                )
            template_html = (
                "<h6 class='mt-3'>ESC templates this token can enroll on</h6>"
                f"<ul class='mb-0'>{''.join(items)}</ul>"
            )
        findings = account.get("finding_options") or []
        finding_html = ""
        if findings:
            items = []
            for option in findings:
                obj = html_stdlib.escape(str(option.get("object") or ""))
                count = int(option.get("finding_count") or 0)
                types = ", ".join(html_stdlib.escape(str(item)) for item in (option.get("types") or [])[:8])
                items.append(
                    f"<li><code>{obj}</code> — {count} finding(s)"
                    f"{f' (<code>{types}</code>)' if types else ''}</li>"
                )
            finding_html = (
                "<h6 class='mt-3'>Findings that name this account or its token</h6>"
                f"<ul class='mb-0'>{''.join(items)}</ul>"
            )
        techniques = account.get("session_techniques") or []
        technique_html = ""
        if techniques:
            badges = " ".join(
                f'<span class="badge bg-danger">{html_stdlib.escape(str(item).replace("_", " "))}</span>'
                for item in techniques
            )
            technique_html = (
                "<h6 class='mt-3'>Domain Admin techniques this session can start</h6>"
                f"<p class='mb-0'>{badges}</p>"
            )
        return f"""
        <div class="da-path is-critical mb-4">
            <div class="da-meta">
                <span class="badge bg-warning text-dark">Assessment account</span>
                <span class="badge bg-dark">{sam}</span>
                <span class="badge bg-secondary">tokenGroups: {token}</span>
            </div>
            <h4>From the account used for this scan</h4>
            <p class="mb-2">{headline}</p>
            {technique_html}
            {route_html}
            {template_html}
            {finding_html}
            <p class="small text-muted mb-0 mt-2">{limitation}</p>
        </div>
        """

    def _da_nonadmin_starters_block(self, starters: dict[str, Any]) -> str:
        principals = starters.get("principals") or []
        if not principals:
            return ""
        headline = html_stdlib.escape(str(starters.get("headline") or ""))
        limitation = html_stdlib.escape(str(starters.get("limitation") or ""))
        cards = []
        for principal in principals:
            sam = html_stdlib.escape(str(principal.get("sam") or "unknown"))
            kind = html_stdlib.escape(str(principal.get("kind") or "principal"))
            sid = html_stdlib.escape(str(principal.get("sid") or ""))
            hops = principal.get("shortest_hops")
            hop_badge = (
                f'<span class="badge bg-danger">{html_stdlib.escape(str(hops))} hop(s)</span>'
                if hops is not None
                else '<span class="badge bg-secondary">finding foothold</span>'
            )
            route_html = ""
            routes = principal.get("routes") or []
            if routes:
                items = []
                for route in routes:
                    labels = " → ".join(
                        html_stdlib.escape(str(label)) for label in (route.get("labels") or [])
                    )
                    hop_count = int(route.get("hop_count") or 0)
                    types = ", ".join(
                        html_stdlib.escape(str(hop.get("type") or ""))
                        for hop in (route.get("hops") or [])
                        if hop.get("type")
                    )
                    extra = f" <span class='text-muted'>({html_stdlib.escape(types)})</span>" if types else ""
                    items.append(f"<div class='da-route'>{hop_count} hop: {labels}{extra}</div>")
                route_html = "<h6 class='mt-2'>Graph routes</h6>" + "".join(items)
            technique_html = []
            for technique in principal.get("techniques") or []:
                name = html_stdlib.escape(str(technique.get("name") or technique.get("id") or ""))
                reason = html_stdlib.escape(str(technique.get("reason") or ""))
                pending = " <span class='badge bg-secondary'>requires validation</span>" if technique.get("pending") else ""
                evidence_items = []
                for item in technique.get("evidence") or []:
                    title = html_stdlib.escape(str(item.get("title") or item.get("type") or ""))
                    obj = html_stdlib.escape(str(item.get("object") or ""))
                    perm = html_stdlib.escape(str(item.get("permission") or ""))
                    ev_type = html_stdlib.escape(str(item.get("type") or ""))
                    detail = html_stdlib.escape(str(item.get("detail") or ""))
                    confirmed = "confirmed" if item.get("confirmed") else "needs validation"
                    bits = [title]
                    if obj:
                        bits.append(f"object <code>{obj}</code>")
                    if ev_type:
                        bits.append(f"<code>{ev_type}</code>")
                    if perm:
                        bits.append(perm)
                    bits.append(confirmed)
                    line = " — ".join(bits)
                    if detail:
                        line += f"<div class='small text-muted'>{detail}</div>"
                    evidence_items.append(f"<li>{line}</li>")
                evidence_html = (
                    f"<ul class='da-evidence-list mb-2'>{''.join(evidence_items)}</ul>"
                    if evidence_items
                    else "<p class='small text-muted'>No finding row attached; the graph route is the evidence.</p>"
                )
                technique_html.append(
                    f"""<div class="mb-3">
                        <h6 class="mb-1">{name}{pending}</h6>
                        <p class="da-why mb-2">{reason}</p>
                        <p class="mb-1"><strong>Evidence</strong></p>
                        {evidence_html}
                    </div>"""
                )
            sid_badge = f'<span class="badge bg-dark">{sid}</span>' if sid else ""
            cards.append(
                f"""<article class="da-path is-high" data-da-starter="{sam}">
                    <div class="da-meta">
                        <span class="badge bg-warning text-dark">Non-admin foothold</span>
                        <span class="badge bg-dark">{kind}</span>
                        {hop_badge}
                        <span class="badge bg-info text-dark">{int(principal.get('technique_count') or 0)} technique(s)</span>
                        {sid_badge}
                    </div>
                    <h4>{sam}</h4>
                    {''.join(technique_html)}
                    {route_html}
                </article>"""
            )
        return f"""
        <h5 class="mb-2">Non-admin accounts that can reach Domain Admin</h5>
        <p class="text-muted">{headline}</p>
        <p class="small text-muted">{limitation}</p>
        <div id="da-nonadmin-starters">{''.join(cards)}</div>
        """

    def _da_empty_state(self) -> str:
        return """
        <div class="card"><div class="card-body">
            <p class="mb-0">No scan finding currently maps to a Domain Admin technique. That does not prove the domain is clean. Review the assessment-account block and the catalog below — several DA paths require host, CA, or network evidence that LDAP cannot always prove.</p>
        </div></div>
        """

    def _da_path_card(self, path: dict[str, Any], *, emphasized: bool) -> str:
        pid = html_stdlib.escape(str(path.get("id") or ""))
        name = html_stdlib.escape(str(path.get("name") or "Unnamed path"))
        category = str(path.get("category") or "other")
        severity = str(path.get("severity") or "medium").lower()
        mitre = html_stdlib.escape(str(path.get("mitre") or ""))
        starting = html_stdlib.escape(str(path.get("starting_access") or ""))
        why = html_stdlib.escape(str(path.get("why_da") or ""))
        detection = html_stdlib.escape(str(path.get("detection") or ""))
        da_eq = "DA equivalent" if path.get("da_equivalent") else "Enables DA targeting"
        status = {"open": "open", "needs_validation": "Requires validation"}.get(path.get("status"), "not observed")
        objects = path.get("evidence_objects") or []
        types = path.get("evidence_types") or []
        object_html = ", ".join(f"<code>{html_stdlib.escape(str(item))}</code>" for item in objects) or "<span class='text-muted'>No named object</span>"
        type_html = ", ".join(f"<code>{html_stdlib.escape(str(item))}</code>" for item in types[:8])
        stages = path.get("stages") or []
        stage_html = "".join(
            f"""<div class="da-stage">
                    <div class="da-num">{idx}</div>
                    <div>
                        <strong>{html_stdlib.escape(str(stage.get('title') or ''))}</strong>
                        <div class="da-why">{html_stdlib.escape(str(stage.get('why') or ''))}</div>
                        <div class="small text-muted">{html_stdlib.escape(str(stage.get('action') or ''))}</div>
                    </div>
                </div>"""
            for idx, stage in enumerate(stages, 1)
        )
        breaks = path.get("break_path") or []
        break_html = "".join(f"<li>{html_stdlib.escape(str(item))}</li>" for item in breaks)
        extra_class = "is-closed"
        if emphasized:
            extra_class = f"is-{severity}" if severity in {"critical", "high"} else ""
        evidence_block = ""
        if emphasized:
            summaries = path.get("evidence_summaries") or []
            summary_html = ""
            if summaries:
                items = []
                for item in summaries:
                    title = html_stdlib.escape(str(item.get("title") or item.get("type") or ""))
                    obj = html_stdlib.escape(str(item.get("object") or ""))
                    detail = title if not obj else f"{title} ({obj})"
                    items.append(f"<li>{detail}</li>")
                summary_html = "<div class='da-evidence-list'><ul class='mb-2'>" + "".join(items) + "</ul></div>"
            options = path.get("options") or []
            option_html = ""
            if options:
                rows = []
                for option in options:
                    obj = html_stdlib.escape(str(option.get("object") or ""))
                    count = int(option.get("finding_count") or 0)
                    types = ", ".join(html_stdlib.escape(str(item)) for item in (option.get("types") or [])[:8])
                    rows.append(
                        f"<li><code>{obj}</code> — {count} finding(s)"
                        f"{f' (<code>{types}</code>)' if types else ''}</li>"
                    )
                option_html = (
                    f"<p class='mb-1'><strong>Object-level options ({len(options)}):</strong></p>"
                    f"<ul class='mb-2'>{''.join(rows)}</ul>"
                )
            evidence_block = f"""
                <p class="mb-1"><strong>Why this finding is in the map:</strong> matched scan evidence ({int(path.get('evidence_count') or 0)}).</p>
                {option_html}
                {summary_html}
                <p class="mb-1"><strong>Affected objects:</strong> {object_html}</p>
                <p class="small text-muted">Matched finding types: {type_html or '—'}</p>
            """
        return f"""
        <article class="da-path {extra_class}" data-da-id="{pid}" data-da-category="{html_stdlib.escape(category)}">
            <div class="da-meta">
                <span class="badge bg-{'danger' if severity == 'critical' else 'warning' if severity == 'high' else 'secondary'}">{html_stdlib.escape(severity)}</span>
                <span class="badge bg-dark">{html_stdlib.escape(category.replace('_', ' '))}</span>
                <span class="badge bg-info text-dark">{html_stdlib.escape(da_eq)}</span>
                <span class="badge bg-secondary">{html_stdlib.escape(status)}</span>
                <span class="badge bg-outline-light">{mitre}</span>
            </div>
            <h4>{name}</h4>
            <p class="mb-2"><strong>Why this becomes Domain Admin:</strong> {why}</p>
            <p class="mb-2"><strong>Starting access a tester assumes:</strong> {starting}</p>
            {evidence_block}
            <h6 class="mt-3">Logical attack chain</h6>
            {stage_html}
            {self._da_evidence_dossiers(path)}
            {self._da_poc_block(path)}
            {self._da_commands_block(path)}
            <h6 class="mt-3">How to break the path</h6>
            <ul class="da-break">{break_html}</ul>
            <p class="small text-muted mb-0"><strong>Detection:</strong> {detection}</p>
        </article>
        """

    def _da_evidence_dossiers(self, path: dict[str, Any]) -> str:
        """Render every mapped observation with its validation contract."""
        rows = path.get("evidence_dossiers") or []
        if not rows:
            return ""
        def esc(value: Any) -> str:
            return html_stdlib.escape(str(value or "—"))

        cards = []
        for row in rows:
            checks = "".join(f"<li>{esc(check)}</li>" for check in row.get("checks") or [])
            cards.append(f"""<details class="da-evidence-dossier mb-2">
                <summary><strong>{esc(row.get('object'))}</strong> — <code>{esc(row.get('type'))}</code>
                    <span class="badge bg-secondary">{esc(row.get('evidence_state'))}</span></summary>
                <dl class="mt-2">
                    <dt>Finding reference</dt><dd><code>{esc(row.get('finding_id'))}</code></dd>
                    <dt>Target DN / trustee</dt><dd><code>{esc(row.get('target_dn'))}</code> / <code>{esc(row.get('trustee'))}</code></dd>
                    <dt>Observed permissions</dt><dd>{esc(row.get('permissions'))}</dd>
                    <dt>Observation</dt><dd>{esc(row.get('observation'))}</dd>
                </dl>
                <strong>Prerequisites to verify</strong><ul>{checks}</ul>
                <p><strong>Expected evidence:</strong> {esc(row.get('expected'))}</p>
                <p><strong>What invalidates this claim:</strong> {esc(row.get('falsifier'))}</p>
                <strong>Read-only PoC example</strong>
                <pre class="da-command"><code>{esc(row.get('read_only_poc'))}</code></pre>
                <p class="small text-muted">{esc(row.get('poc_note'))}</p>
                <p><strong>Retest:</strong> {esc(row.get('retest'))}</p>
            </details>""")
        return '<h6 class="mt-3">Finding evidence and validation</h6>' + "".join(cards)

    def _da_poc_block(self, path: dict[str, Any]) -> str:
        """Render the detailed PoC roadmap for one path."""
        steps = path.get("poc_roadmap") or []
        if not steps:
            return ""
        items = []
        for idx, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                continue
            title = html_stdlib.escape(str(step.get("step") or ""))
            detail = html_stdlib.escape(str(step.get("detail") or ""))
            expected = html_stdlib.escape(str(step.get("expected") or ""))
            expected_html = (
                f'<div class="da-expected"><strong>Expected evidence:</strong> {expected}</div>'
                if expected
                else ""
            )
            command_html = self._da_command_items(step.get("commands") or [])
            command_block = (
                f'<div class="mt-2"><strong>Example command:</strong>{command_html}</div>'
                if command_html
                else ""
            )
            items.append(
                f"""<div class="da-poc-step da-stage">
                    <div class="da-num">{idx}</div>
                    <div>
                        <strong>{title}</strong>
                        <div class="da-why"><strong>What to do:</strong> {detail}</div>
                        {command_block}
                        {expected_html}
                    </div>
                </div>"""
            )
        return f"""
            <h6 class="mt-3">PoC roadmap</h6>
            <p class="small text-muted">
                Follow the steps in order. Record the expected evidence before continuing.
                Stop after evidence is recorded; do not persist privileged access.
            </p>
            <div class="da-poc">{''.join(items)}</div>
        """

    def _da_command_items(self, commands: list[Any]) -> str:
        blocks = []
        for item in commands:
            if not isinstance(item, dict):
                continue
            label = html_stdlib.escape(str(item.get("label") or item.get("id") or "Command"))
            command = html_stdlib.escape(str(item.get("command") or ""))
            if not command:
                continue
            blocks.append(
                f"""<div class="da-cmd">
                    <div class="small"><strong>{label}</strong></div>
                    <pre class="mb-0"><code>{command}</code></pre>
                </div>"""
            )
        return "".join(blocks)

    def _da_commands_block(self, path: dict[str, Any]) -> str:
        """Render verification and authorized-assessment command templates."""
        verify = self._da_command_items(path.get("verify_commands") or [])
        assess = self._da_command_items(path.get("assessment_commands") or [])
        tools = path.get("tools") or []
        if not verify and not assess:
            return ""
        tool_html = ""
        if tools:
            badges = " ".join(
                f'<span class="badge bg-secondary">{html_stdlib.escape(str(tool))}</span>'
                for tool in tools
            )
            tool_html = f'<p class="small mb-2"><strong>Assessment tools:</strong> {badges}</p>'
        verify_html = (
            f"<h6 class='mt-2'>Finding verification commands</h6>{verify}" if verify else ""
        )
        assess_html = (
            f"<h6 class='mt-2'>Authorized assessment commands</h6>{assess}" if assess else ""
        )
        return f"""
            <h6 class="mt-3">Usable commands</h6>
            <p class="small text-muted">
                Placeholders are filled from this scan when possible ({html_stdlib.escape(str((path.get('evidence_objects') or ['TARGET'])[0]))}).
                Use only in authorized engagements.
            </p>
            {tool_html}
            {verify_html}
            {assess_html}
        """
