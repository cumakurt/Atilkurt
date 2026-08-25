"""Dedicated Domain Admin takeover map for the HTML report."""

from __future__ import annotations

import html as html_stdlib
from typing import Any


class DomainAdminSectionMixin:
    """Render pentest-oriented Domain Admin takeover paths."""

    def _generate_domain_admin_takeover_section(self, takeover: dict[str, Any] | None) -> str:
        """Return HTML for the Domain Admin takeover map tab."""
        takeover = takeover or {}
        summary = takeover.get("summary") or {}
        open_paths = takeover.get("open_paths") or []
        unobserved = takeover.get("unobserved_paths") or []
        headline = html_stdlib.escape(str(summary.get("headline") or "Domain Admin takeover map."))

        open_count = int(summary.get("open_path_count") or 0)
        da_count = int(summary.get("da_equivalent_open_count") or 0)
        critical_count = int(summary.get("critical_open_count") or 0)
        high_count = int(summary.get("high_open_count") or 0)
        catalog_count = int(summary.get("catalog_count") or 0)

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
        </style>
        <div class="da-hero">
            <h3 class="mb-2"><i class="fas fa-crown text-warning"></i> Domain Admin takeover map</h3>
            <p class="mb-0">{headline}</p>
            <p class="text-muted small mt-2 mb-0">
                This view is written the way an internal penetration test is scoped: every technique that
                can become Domain Admin (or a Domain Admin equivalent such as DCSync, KRBTGT, or a
                privileged certificate). Each open path is backed by findings from this scan. Stages
                describe attack <em>logic</em> for assessment and defense — not exploit procedures.
            </p>
            <div class="da-kpis">
                <div class="da-kpi"><div class="n">{open_count}</div><div class="l">Open paths</div></div>
                <div class="da-kpi"><div class="n">{da_count}</div><div class="l">DA-equivalent</div></div>
                <div class="da-kpi"><div class="n">{critical_count}</div><div class="l">Critical</div></div>
                <div class="da-kpi"><div class="n">{high_count}</div><div class="l">High</div></div>
                <div class="da-kpi"><div class="n">{catalog_count}</div><div class="l">Techniques in catalog</div></div>
            </div>
        </div>
        <div class="mb-3 d-flex flex-wrap gap-2">{''.join(filter_buttons)}</div>
        <h5 class="mb-3">Open paths evidenced in this domain</h5>
        <div id="da-open-paths">{open_html}</div>
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
                        the supporting attributes.
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

    def _da_empty_state(self) -> str:
        return """
        <div class="card"><div class="card-body">
            <p class="mb-0">No scan finding currently maps to a Domain Admin technique.
            Review the catalog below — several DA paths require host, CA, or network evidence
            that LDAP cannot always prove.</p>
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
        status = "open" if path.get("status") == "open" else "not observed"
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
                summary_html = "<ul class='mb-2'>" + "".join(items) + "</ul>"
            evidence_block = f"""
                <p class="mb-1"><strong>Why this finding is in the map:</strong> matched scan evidence ({int(path.get('evidence_count') or 0)}).</p>
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
            <h6 class="mt-3">How to break the path</h6>
            <ul class="da-break">{break_html}</ul>
            <p class="small text-muted mb-0"><strong>Detection:</strong> {detection}</p>
        </article>
        """
