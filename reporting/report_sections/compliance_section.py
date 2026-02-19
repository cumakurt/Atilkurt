"""
Mixin for compliance reporting (CIS, NIST, ISO, GDPR) and risk management.
"""

from collections import defaultdict
import html as html_stdlib



class ComplianceSectionMixin:
    """Mixin for compliance reporting (CIS, NIST, ISO, GDPR) and risk management."""

    def _generate_compliance_section(self, compliance_data):
        """Generate compliance reporting section."""
        if not compliance_data:
            return ''
        
        cis_data = compliance_data.get('cis_benchmark', {})
        nist_data = compliance_data.get('nist_csf', {})
        iso_data = compliance_data.get('iso_27001', {})
        gdpr_data = compliance_data.get('gdpr', {})
        
        cis_html = self._generate_cis_compliance_html(cis_data)
        nist_html = self._generate_nist_compliance_html(nist_data)
        iso_html = self._generate_iso_compliance_html(iso_data)
        gdpr_html = self._generate_gdpr_compliance_html(gdpr_data)
        
        overall_score = (
            cis_data.get('compliance_score', 0) +
            nist_data.get('compliance_score', 0) +
            iso_data.get('compliance_score', 0) +
            gdpr_data.get('compliance_score', 0)
        ) / 4 if compliance_data else 0
        
        return f"""
        <div id="compliance" class="tab-pane" role="tabpanel" aria-labelledby="compliance-tab">
            <nav aria-label="breadcrumb" class="mb-4">
                <ol class="breadcrumb">
                    <li class="breadcrumb-item"><a href="#dashboard" onclick="if(typeof window.navigateToTab !== 'undefined'){{window.navigateToTab('dashboard-tab');}}">Dashboard</a></li>
                    <li class="breadcrumb-item active" aria-current="page">Compliance Reporting</li>
                </ol>
            </nav>
            
            <div class="card mb-4">
                <div class="card-header bg-primary text-white">
                    <h4><i class="fas fa-clipboard-check"></i> Overall Compliance Score</h4>
                </div>
                <div class="card-body text-center">
                    <div class="display-1 fw-bold" style="color: {'var(--success-color)' if overall_score >= 80 else 'var(--warning-color)' if overall_score >= 60 else 'var(--danger-color)'}">
                        {overall_score:.1f}%
                    </div>
                    <p class="text-muted">Average compliance across all frameworks</p>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-4">
                    {cis_html}
                </div>
                <div class="col-md-6 mb-4">
                    {nist_html}
                </div>
                <div class="col-md-6 mb-4">
                    {iso_html}
                </div>
                <div class="col-md-6 mb-4">
                    {gdpr_html}
                </div>
            </div>
        </div>
        """

    def _generate_cis_compliance_html(self, cis_data):
        """Generate CIS Benchmark compliance HTML."""
        if not cis_data:
            return '<div class="card"><div class="card-body"><p class="text-muted">No CIS Benchmark data available.</p></div></div>'
        
        score = cis_data.get('compliance_score', 0)
        
        # Check if advanced LDAP-based analysis was used
        if 'controls' in cis_data:
            # Advanced analysis with detailed controls
            controls = cis_data.get('controls', [])
            passed = [c for c in controls if c.get('status') == 'passed']
            failed = [c for c in controls if c.get('status') == 'failed']
            warnings = [c for c in controls if c.get('status') == 'warning']
            
            controls_html = '<div class="accordion report-accordion mt-3" id="cisControlsAccordion">'
            for idx, control in enumerate(controls):
                status_badge = {
                    'passed': '<span class="badge bg-success">PASSED</span>',
                    'failed': '<span class="badge bg-danger">FAILED</span>',
                    'warning': '<span class="badge bg-warning">WARNING</span>',
                    'unknown': '<span class="badge bg-secondary">UNKNOWN</span>'
                }.get(control.get('status', 'unknown'), '<span class="badge bg-secondary">UNKNOWN</span>')
                
                details = control.get('details', {})
                details_html = '<ul class="list-unstyled">'
                for key, value in details.items():
                    if key not in ['affected_users', 'affected_computers', 'affected_trusts', 'members']:
                        details_html += f'<li><strong>{key.replace("_", " ").title()}:</strong> {value}</li>'
                if 'affected_users' in details and details['affected_users']:
                    details_html += f'<li><strong>Affected Users:</strong> {", ".join(details["affected_users"][:5])}</li>'
                if 'affected_computers' in details and details['affected_computers']:
                    details_html += f'<li><strong>Affected Computers:</strong> {", ".join(details["affected_computers"][:5])}</li>'
                details_html += '</ul>'
                
                controls_html += f"""
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#cisControl{idx}">
                            {status_badge} {control.get('control_id')} - {control.get('control_name')}
                        </button>
                    </h2>
                    <div id="cisControl{idx}" class="accordion-collapse collapse" data-bs-parent="#cisControlsAccordion">
                        <div class="accordion-body">
                            <p><strong>LDAP Query:</strong> <code>{control.get('ldap_query', 'N/A')}</code></p>
                            <p><strong>Recommendation:</strong> {control.get('recommendation', 'N/A')}</p>
                            <div class="mt-2">
                                <strong>Details:</strong>
                                {details_html}
                            </div>
                        </div>
                    </div>
                </div>
                """
            controls_html += '</div>'
            
            return f"""
            <div class="card">
                <div class="card-header">
                    <h5><i class="fas fa-shield-alt"></i> CIS Benchmark</h5>
                </div>
                <div class="card-body">
                    <div class="mb-3">
                        <h3 class="text-{'success' if score >= 80 else 'warning' if score >= 60 else 'danger'}">{score:.1f}%</h3>
                        <p class="text-muted">Compliance Score</p>
                    </div>
                    <div class="mb-3">
                        <p><strong>Total Controls:</strong> {cis_data.get('total_controls', 0)}</p>
                        <p><strong>Passed:</strong> <span class="text-success">{len(passed)}</span></p>
                        <p><strong>Failed:</strong> <span class="text-danger">{len(failed)}</span></p>
                        <p><strong>Warnings:</strong> <span class="text-warning">{len(warnings)}</span></p>
                    </div>
                    {controls_html}
                </div>
            </div>
            """
        else:
            # Legacy risk-based analysis
            failed = cis_data.get('failed_controls', [])
            passed = cis_data.get('passed_controls', [])
            
            failed_html = ''.join([
                f'<li><span class="badge bg-danger">{c.get("control")}</span> - {c.get("risk_type")} ({c.get("count", 0)} instances)</li>'
                for c in failed[:10]
            ])
            
            return f"""
            <div class="card">
                <div class="card-header">
                    <h5><i class="fas fa-shield-alt"></i> CIS Benchmark</h5>
                </div>
                <div class="card-body">
                    <div class="mb-3">
                        <h3 class="text-{'success' if score >= 80 else 'warning' if score >= 60 else 'danger'}">{score:.1f}%</h3>
                        <p class="text-muted">Compliance Score</p>
                    </div>
                    <div class="mb-3">
                        <p><strong>Total Controls:</strong> {cis_data.get('total_controls', 0)}</p>
                        <p><strong>Passed:</strong> <span class="text-success">{len(passed)}</span></p>
                        <p><strong>Failed:</strong> <span class="text-danger">{len(failed)}</span></p>
                    </div>
                    {f'<div class="mt-3"><h6>Failed Controls:</h6><ul>{failed_html}</ul></div>' if failed else ''}
                </div>
            </div>
            """

    def _generate_nist_compliance_html(self, nist_data):
        """Generate NIST CSF compliance HTML."""
        if not nist_data:
            return '<div class="card"><div class="card-body"><p class="text-muted">No NIST CSF data available.</p></div></div>'
        
        score = nist_data.get('compliance_score', 0)
        functions = nist_data.get('functions', {})
        
        functions_html = '<div class="accordion report-accordion mt-3" id="nistFunctionsAccordion">'
        for func_id, func in functions.items():
            controls = func.get('controls', [])
            if controls:
                func_score = func.get('score', 0)
                func_status = func.get('status', 'partial')
                
                controls_list_html = '<ul class="list-unstyled mt-2">'
                for control in controls:
                    status_badge = {
                        'passed': '<span class="badge bg-success">PASSED</span>',
                        'failed': '<span class="badge bg-danger">FAILED</span>',
                        'warning': '<span class="badge bg-warning">WARNING</span>'
                    }.get(control.get('status', 'unknown'), '<span class="badge bg-secondary">UNKNOWN</span>')
                    
                    details = control.get('details', {})
                    details_str = ', '.join([f"{k}: {v}" for k, v in details.items() if k not in ['affected_users', 'affected_computers']])
                    
                    controls_list_html += f"""
                    <li class="mb-2">
                        {status_badge} <strong>{control.get('control_id')}</strong> - {control.get('control_name')}
                        <br><small class="text-muted">LDAP: <code>{control.get('ldap_query', 'N/A')}</code></small>
                        {f'<br><small class="text-muted">Details: {details_str}</small>' if details_str else ''}
                    </li>
                    """
                controls_list_html += '</ul>'
                
                functions_html += f"""
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#nistFunc{func_id}">
                            <strong>{func_id}:</strong> {func.get('name')} - <span class="badge bg-{"success" if func_status == "passed" else "warning" if func_status == "partial" else "danger"} ms-2">{func_score:.1f}%</span>
                        </button>
                    </h2>
                    <div id="nistFunc{func_id}" class="accordion-collapse collapse" data-bs-parent="#nistFunctionsAccordion">
                        <div class="accordion-body">
                            {controls_list_html}
                        </div>
                    </div>
                </div>
                """
        functions_html += '</div>'
        
        return f"""
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-network-wired"></i> NIST Cybersecurity Framework</h5>
            </div>
            <div class="card-body">
                <div class="mb-3">
                    <h3 class="text-{'success' if score >= 80 else 'warning' if score >= 60 else 'danger'}">{score:.1f}%</h3>
                    <p class="text-muted">Compliance Score</p>
                </div>
                <div class="mt-3">
                    <h6>Functions:</h6>
                    {functions_html}
                </div>
            </div>
        </div>
        """

    def _generate_iso_compliance_html(self, iso_data):
        """Generate ISO 27001 compliance HTML."""
        if not iso_data:
            return '<div class="card"><div class="card-body"><p class="text-muted">No ISO 27001 data available.</p></div></div>'
        
        score = iso_data.get('compliance_score', 0)
        domains = iso_data.get('domains', {})
        domain_scores = iso_data.get('domain_scores', {})
        
        domains_html = '<div class="accordion report-accordion mt-3" id="isoDomainsAccordion">'
        for domain, controls in domains.items():
            domain_score = domain_scores.get(domain, 0)
            passed = sum(1 for c in controls if c.get('status') == 'passed')
            failed = sum(1 for c in controls if c.get('status') == 'failed')
            
            controls_list_html = '<ul class="list-unstyled mt-2">'
            for control in controls:
                status_badge = {
                    'passed': '<span class="badge bg-success">PASSED</span>',
                    'failed': '<span class="badge bg-danger">FAILED</span>',
                    'warning': '<span class="badge bg-warning">WARNING</span>'
                }.get(control.get('status', 'unknown'), '<span class="badge bg-secondary">UNKNOWN</span>')
                
                details = control.get('details', {})
                details_str = ', '.join([f"{k}: {v}" for k, v in details.items() if k not in ['affected_users', 'affected_computers']])
                
                controls_list_html += f"""
                <li class="mb-2">
                    {status_badge} <strong>{control.get('control_id')}</strong> - {control.get('control_name')}
                    <br><small class="text-muted">LDAP: <code>{control.get('ldap_query', 'N/A')}</code></small>
                    {f'<br><small class="text-muted">Details: {details_str}</small>' if details_str else ''}
                </li>
                """
            controls_list_html += '</ul>'
            
            domains_html += f"""
            <div class="accordion-item">
                <h2 class="accordion-header">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#isoDomain{domain.replace('.', '_')}">
                        <strong>{domain}:</strong> <span class="badge bg-{"success" if domain_score >= 80 else "warning" if domain_score >= 50 else "danger"} ms-2">{domain_score:.1f}%</span> ({passed} passed, {failed} failed)
                    </button>
                </h2>
                <div id="isoDomain{domain.replace('.', '_')}" class="accordion-collapse collapse" data-bs-parent="#isoDomainsAccordion">
                    <div class="accordion-body">
                        {controls_list_html}
                    </div>
                </div>
            </div>
            """
        domains_html += '</div>'
        
        return f"""
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-certificate"></i> ISO 27001</h5>
            </div>
            <div class="card-body">
                <div class="mb-3">
                    <h3 class="text-{'success' if score >= 80 else 'warning' if score >= 60 else 'danger'}">{score:.1f}%</h3>
                    <p class="text-muted">Compliance Score</p>
                </div>
                <div class="mt-3">
                    <h6>Domains:</h6>
                    {domains_html}
                </div>
            </div>
        </div>
        """

    def _generate_gdpr_compliance_html(self, gdpr_data):
        """Generate GDPR compliance HTML."""
        if not gdpr_data:
            return '<div class="card"><div class="card-body"><p class="text-muted">No GDPR data available.</p></div></div>'
        
        score = gdpr_data.get('compliance_score', 0)
        articles = gdpr_data.get('articles', {})
        article_scores = gdpr_data.get('article_scores', {})
        
        articles_html = '<div class="accordion report-accordion mt-3" id="gdprArticlesAccordion">'
        for article, controls in articles.items():
            article_score = article_scores.get(article, 0)
            passed = sum(1 for c in controls if c.get('status') == 'passed')
            failed = sum(1 for c in controls if c.get('status') == 'failed')
            
            controls_list_html = '<ul class="list-unstyled mt-2">'
            for control in controls:
                status_badge = {
                    'passed': '<span class="badge bg-success">PASSED</span>',
                    'failed': '<span class="badge bg-danger">FAILED</span>',
                    'warning': '<span class="badge bg-warning">WARNING</span>'
                }.get(control.get('status', 'unknown'), '<span class="badge bg-secondary">UNKNOWN</span>')
                
                details = control.get('details', {})
                details_str = ', '.join([f"{k}: {v}" for k, v in details.items() if k not in ['affected_users', 'affected_computers']])
                
                controls_list_html += f"""
                <li class="mb-2">
                    {status_badge} <strong>{control.get('control_id')}</strong> - {control.get('control_name')}
                    <br><small class="text-muted">{control.get('description', '')}</small>
                    <br><small class="text-muted">LDAP: <code>{control.get('ldap_query', 'N/A')}</code></small>
                    {f'<br><small class="text-muted">Details: {details_str}</small>' if details_str else ''}
                </li>
                """
            controls_list_html += '</ul>'
            
            articles_html += f"""
            <div class="accordion-item">
                <h2 class="accordion-header">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#gdprArticle{article.replace(' ', '_')}">
                        <strong>{article}:</strong> <span class="badge bg-{"success" if article_score >= 80 else "warning" if article_score >= 50 else "danger"} ms-2">{article_score:.1f}%</span> ({passed} passed, {failed} failed)
                    </button>
                </h2>
                <div id="gdprArticle{article.replace(' ', '_')}" class="accordion-collapse collapse" data-bs-parent="#gdprArticlesAccordion">
                    <div class="accordion-body">
                        {controls_list_html}
                    </div>
                </div>
            </div>
            """
        articles_html += '</div>'
        
        return f"""
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-gavel"></i> GDPR</h5>
            </div>
            <div class="card-body">
                <div class="mb-3">
                    <h3 class="text-{'success' if score >= 80 else 'warning' if score >= 60 else 'danger'}">{score:.1f}%</h3>
                    <p class="text-muted">Compliance Score</p>
                </div>
                <div class="mt-3">
                    <h6>Articles:</h6>
                    {articles_html}
                </div>
            </div>
        </div>
        """

    def _generate_risk_management_section(self, risk_management_data):
        """Generate risk management section with heat map and ROI."""
        if not risk_management_data:
            return ''
        
        heat_map_data = risk_management_data.get('heat_map', {})
        prioritized_risks = risk_management_data.get('prioritized_risks', [])
        
        # Generate heat map HTML
        heat_map_html = self._generate_heat_map_html(heat_map_data)
        
        # Generate prioritized risks HTML
        prioritized_html = self._generate_prioritized_risks_html(prioritized_risks[:20])  # Top 20
        
        return f"""
        <div id="risk-management" class="tab-pane" role="tabpanel" aria-labelledby="risk-management-tab">
            <nav aria-label="breadcrumb" class="mb-4">
                <ol class="breadcrumb">
                    <li class="breadcrumb-item"><a href="#dashboard" onclick="if(typeof window.navigateToTab !== 'undefined'){{window.navigateToTab('dashboard-tab');}}">Dashboard</a></li>
                    <li class="breadcrumb-item active" aria-current="page">Risk Management</li>
                </ol>
            </nav>
            
            <div class="card mb-4">
                <div class="card-header bg-info text-white">
                    <h4><i class="fas fa-chart-line"></i> Risk Heat Map</h4>
                </div>
                <div class="card-body">
                    {heat_map_html}
                </div>
            </div>
            
            <div class="card">
                <div class="card-header bg-success text-white">
                    <h4><i class="fas fa-sort-amount-down"></i> Prioritized Risks by ROI</h4>
                </div>
                <div class="card-body">
                    {prioritized_html}
                </div>
            </div>
        </div>
        """

    def _generate_heat_map_html(self, heat_map_data):
        """Generate risk heat map HTML with severity-based row coloring (same as risk cards)."""
        if not heat_map_data:
            return '<p class="text-muted">No heat map data available.</p>'
        
        heat_map = heat_map_data.get('heat_map', {})
        stats = heat_map_data.get('statistics', {})
        
        severity_levels = ['critical', 'high', 'medium', 'low']
        likelihood_levels = ['high', 'medium', 'low']
        
        grid_html = '<div class="table-responsive"><table class="table table-bordered align-middle"><thead><tr><th>Severity / Likelihood</th>'
        for likelihood in likelihood_levels:
            grid_html += f'<th class="text-center">{likelihood.upper()}</th>'
        grid_html += '</tr></thead><tbody>'
        
        for severity in severity_levels:
            row_class = self._get_severity_heat_class(severity)
            grid_html += f'<tr class="{row_class}"><th>{severity.upper()}</th>'
            for likelihood in likelihood_levels:
                key = f'{severity}_{likelihood}'
                items = heat_map.get(key, [])
                count = len(items)
                grid_html += f'<td class="text-center"><strong>{count}</strong></td>'
            grid_html += '</tr>'
        
        grid_html += '</tbody></table></div>'
        return grid_html

    def _group_prioritized_risks_by_type(self, prioritized_risks):
        """Group prioritized risks by risk type so same finding appears once with all affected users."""
        from collections import defaultdict
        groups = defaultdict(list)
        for item in prioritized_risks:
            risk = item.get('risk', {})
            rtype = risk.get('type', 'unknown')
            groups[rtype].append(item)
        grouped = []
        for rtype, items in groups.items():
            base = items[0].copy()
            risk = base.get('risk', {})
            affected = []
            seen = set()
            scores = []
            for it in items:
                r = it.get('risk', {})
                obj = r.get('affected_object')
                if obj and obj not in seen:
                    seen.add(obj)
                    affected.append(obj)
                for o in r.get('affected_objects', []) or []:
                    if o not in seen:
                        seen.add(o)
                        affected.append(o)
                sc = it.get('priority_score', 0)
                if isinstance(sc, (int, float)):
                    scores.append(sc)
            max_sev = self._max_severity_in_group([it.get('risk', {}) for it in items])
            base['risk'] = risk.copy()
            base['risk']['affected_objects'] = affected
            base['risk']['affected_object'] = f'{len(affected)} affected' if len(affected) > 1 else (affected[0] if affected else risk.get('affected_object', 'Unknown'))
            base['risk']['severity'] = max_sev
            base['risk']['severity_level'] = max_sev.capitalize() if max_sev else 'Medium'
            base['_group_count'] = len(items)
            base['_affected_list'] = affected
            base['priority_score'] = max(scores) if scores else base.get('priority_score', 0)
            grouped.append(base)
        grouped.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
        return grouped

    def _generate_prioritized_risks_html(self, prioritized_risks):
        """Generate prioritized risks HTML: same finding type once, with affected users listed."""
        if not prioritized_risks:
            return '<p class="text-muted">No prioritized risks available.</p>'
        
        grouped = self._group_prioritized_risks_by_type(prioritized_risks)
        risks_html = '<div class="list-group">'
        for idx, item in enumerate(grouped[:25], 1):
            risk = item.get('risk', {})
            impact = item.get('impact', {})
            cost = item.get('cost', {})
            roi = item.get('roi', {})
            priority_score = item.get('priority_score', 0)
            severity = (risk.get('severity') or risk.get('severity_level') or 'medium').lower()
            badge_class = self._get_severity_badge_class(severity)
            severity_class = f'risk-{severity}' if severity in ('critical', 'high', 'medium', 'low') else 'risk-medium'
            affected_list = item.get('_affected_list', []) or risk.get('affected_objects', []) or ([risk.get('affected_object')] if risk.get('affected_object') else [])
            count = item.get('_group_count', 1)
            count_badge = f' <span class="badge bg-secondary">{len(affected_list)} affected</span>' if len(affected_list) > 1 else ''
            affected_chips = ''
            if affected_list:
                affected_chips = '<div class="mt-2"><strong>Affected:</strong> ' + ''.join(
                    f'<span class="badge bg-light text-dark border me-1 mb-1">{html_stdlib.escape(str(a))}</span>'
                    for a in affected_list[:20]
                )
                if len(affected_list) > 20:
                    affected_chips += f' <span class="text-muted small">+{len(affected_list) - 20} more</span>'
                affected_chips += '</div>'
            desc = (risk.get('description') or '')[:200]
            if count > 1 and affected_list:
                desc = f"This finding applies to {len(affected_list)} object(s). " + (desc or '')
            
            risks_html += f"""
            <div class="list-group-item border-start border-4 risk-card {severity_class}">
                <div class="d-flex w-100 justify-content-between align-items-center flex-wrap gap-2">
                    <h5 class="mb-1">#{idx}. {html_stdlib.escape(risk.get('title', 'Unknown Risk'))}{count_badge}</h5>
                    <span class="badge bg-{badge_class} me-1">{severity.upper()}</span>
                    <span class="badge bg-primary">Priority: {priority_score:.2f}</span>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3">
                        <small><strong>Impact:</strong> {impact.get('overall_impact', 0):.1f}/100</small>
                    </div>
                    <div class="col-md-3">
                        <small><strong>Cost:</strong> ${cost.get('total_cost', 0):.2f}</small>
                    </div>
                    <div class="col-md-3">
                        <small><strong>ROI:</strong> {roi.get('roi_percentage', 0):.1f}%</small>
                    </div>
                    <div class="col-md-3">
                        <small><strong>Payback:</strong> {roi.get('payback_period_months', 0):.1f} months</small>
                    </div>
                </div>
                {affected_chips}
                <p class="mb-1 mt-2"><small>{html_stdlib.escape(desc)}{'...' if len(risk.get('description') or '') > 200 else ''}</small></p>
            </div>
            """
        
        risks_html += '</div>'
        return risks_html
