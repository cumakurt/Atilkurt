"""
Mixin for risk list rendering, risk grouping, severity helpers, exploitability, and kerberoasting section.
"""

from collections import defaultdict
import html as html_stdlib



class RiskSectionsMixin:
    """Mixin for risk list rendering, risk grouping, severity helpers, exploitability, and kerberoasting section."""

    def _generate_exploitability_badge(self, risk):
        """Generate exploitability badge for risk card."""
        exploitability = risk.get('exploitability')
        if not exploitability:
            return ""
        
        score = exploitability.get('exploitability_score', 0)
        difficulty = exploitability.get('difficulty', 'Unknown')
        
        # Color based on score
        if score >= 9.0:
            color = 'danger'
        elif score >= 7.0:
            color = 'warning'
        elif score >= 5.0:
            color = 'info'
        else:
            color = 'secondary'
        
        return f'<span class="badge bg-{color}" title="Exploitability Score: {score}/10, Difficulty: {difficulty}">Exploitability: {score:.1f}/10</span>'

    def _generate_exploitability_details(self, risk):
        """Generate exploitability details section."""
        exploitability = risk.get('exploitability')
        if not exploitability:
            return ""
        
        tools = exploitability.get('exploitation_tools', [])
        public_exploits = exploitability.get('public_exploits', [])
        metasploit_modules = exploitability.get('metasploit_modules', [])
        poc = exploitability.get('proof_of_concept', '')
        
        html = f"""
        <div class="mt-3 p-3 report-stat-box rounded">
            <h6><i class="fas fa-bug"></i> Exploitability Information</h6>
            <p><strong>Exploitability Score:</strong> {exploitability.get('exploitability_score', 0):.1f}/10</p>
            <p><strong>Difficulty:</strong> {exploitability.get('difficulty', 'Unknown')}</p>
            <p><strong>Complexity:</strong> {exploitability.get('complexity', 'Unknown')}</p>
            <p><strong>Attack Vector:</strong> {exploitability.get('attack_vector', 'Unknown')}</p>
        """
        
        if tools:
            html += f"""
            <p class="mt-2"><strong>Exploitation Tools:</strong></p>
            <ul>
                {''.join([f'<li>{tool}</li>' for tool in tools])}
            </ul>
            """
        
        if public_exploits:
            html += f"""
            <p class="mt-2"><strong>Public Exploits:</strong></p>
            <ul>
                {''.join([f'<li>{exploit}</li>' for exploit in public_exploits])}
            </ul>
            """
        
        if metasploit_modules:
            html += f"""
            <p class="mt-2"><strong>Metasploit Modules:</strong></p>
            <ul>
                {''.join([f'<li><code>{module}</code></li>' for module in metasploit_modules])}
            </ul>
            """
        
        if poc:
            html += f"""
            <p class="mt-2"><strong>Proof of Concept:</strong></p>
            <p class="text-muted small">{poc}</p>
            """
        
        html += "</div>"
        return html

    def _generate_kerberoasting_section(self, kerberoasting_risks):
        """Generate special section for Kerberoasting targets."""
        if not kerberoasting_risks:
            return """
            <div class="card">
                <div class="card-body text-center">
                    <h5>Kerberoasting & AS-REP Roasting Targets</h5>
                    <p class="text-muted">No Kerberoasting or AS-REP roasting targets found.</p>
                </div>
            </div>
            """
        
        risk_cards = []
        for risk in kerberoasting_risks:
            sev = risk.get('severity', 'high')
            severity = getattr(sev, 'value', sev) if sev else 'high'
            severity = str(severity).lower() if severity else 'high'
            severity_class = f'risk-{severity}'
            severity_badge_color = self._get_severity_badge_class(severity)
            
            # Get export format info
            export_format = risk.get('export_format', {})
            spns = risk.get('spns', [])
            is_privileged = risk.get('is_privileged', False)
            
            risk_card = f"""
            <div class="card risk-card {severity_class} mb-3">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <h5 class="card-title">{risk.get('title', 'Unknown Risk')}</h5>
                        <span class="badge bg-{severity_badge_color}">{severity.upper()}</span>
                    </div>
                    <p class="text-muted"><strong>Target Account:</strong> {risk.get('affected_object', 'Unknown')}</p>
                    <p class="card-text">{risk.get('description', 'No description.')}</p>
                    
                    {f'<p class="mt-2"><strong>Privileged Account:</strong> <span class="badge bg-danger">YES</span></p>' if is_privileged else ''}
                    {f'<p class="mt-2"><strong>Privileged Groups:</strong> {", ".join(risk.get("privileged_groups", []))}</p>' if risk.get('privileged_groups') else ''}
                    
                    {f'<div class="mt-3"><strong>Service Principal Names:</strong><ul class="mt-2">{"".join([f"<li><code>{spn}</code></li>" for spn in spns])}</ul></div>' if spns else ''}
                    
                    <div class="accordion report-accordion mt-3" id="kerberoast{hash(risk.get('type', ''))}">
                        <div class="accordion-item">
                            <h2 class="accordion-header">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#exploit{hash(risk.get('type', ''))}">
                                    <i class="fas fa-terminal"></i> <span>Exploitation Commands</span>
                                </button>
                            </h2>
                            <div id="exploit{hash(risk.get('type', ''))}" class="accordion-collapse collapse" data-bs-parent="#kerberoast{hash(risk.get('type', ''))}">
                                <div class="accordion-body matrix-theme">
                                    {f'<p><strong>Impacket:</strong></p><pre class="p-2 rounded"><code>{export_format.get("impacket_command", "N/A")}</code></pre>' if export_format.get('impacket_command') else ''}
                                    {f'<p class="mt-2"><strong>Rubeus:</strong></p><pre class="p-2 rounded"><code>{export_format.get("rubeus_command", "N/A")}</code></pre>' if export_format.get('rubeus_command') else ''}
                                    {f'<p class="mt-2"><strong>CrackMapExec:</strong></p><pre class="p-2 rounded"><code>{export_format.get("cme_command", "N/A")}</code></pre>' if export_format.get('cme_command') else ''}
                                </div>
                            </div>
                        </div>
                        <div class="accordion-item">
                            <h2 class="accordion-header">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#details{hash(risk.get('type', ''))}">
                                    <i class="fas fa-info-circle"></i> <span>Details</span>
                                </button>
                            </h2>
                            <div id="details{hash(risk.get('type', ''))}" class="accordion-collapse collapse" data-bs-parent="#kerberoast{hash(risk.get('type', ''))}">
                                <div class="accordion-body matrix-theme">
                                    <p><strong>Impact:</strong> {risk.get('impact', 'No impact description.')}</p>
                                    <p><strong>Attack Scenario:</strong> {risk.get('attack_scenario', 'No attack scenario.')}</p>
                                    <p><strong>Mitigation:</strong> {risk.get('mitigation', 'No mitigation provided.')}</p>
                                    {f'<p class="mt-2"><small><strong>MITRE ATT&CK:</strong> {risk.get("mitre_attack", "N/A")}</small></p>' if risk.get('mitre_attack') else ''}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            """
            risk_cards.append(risk_card)
        
        return f"""
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-fire"></i> Kerberoasting & AS-REP Roasting Targets</h5>
            </div>
            <div class="card-body">
                <p class="text-muted">Accounts vulnerable to Kerberoasting and AS-REP roasting attacks. These accounts can be targeted for offline password cracking.</p>
                <div class="input-group mb-3">
                    <span class="input-group-text"><i class="fas fa-search"></i></span>
                    <input type="text" class="form-control" id="kerberoastingSearch" placeholder="Search targets by account, SPN, or description..." onkeyup="filterKerberoasting()">
                    <button class="btn btn-outline-secondary" type="button" onclick="clearKerberoastingSearch()">
                        <i class="fas fa-times"></i> Clear
                    </button>
                    <button class="btn btn-success" type="button" onclick="exportRiskSectionToCsv('kerberoastingContainer', 'kerberoasting')">
                        <i class="fas fa-download"></i> Export
                    </button>
                </div>
                <div id="kerberoastingContainer">
                    {''.join(risk_cards)}
                </div>
            </div>
        </div>
        """

    def _calculate_statistics(self, users, computers, groups, risks):
        """Calculate statistics for the report."""
        def _sev(r):
            s = r.get('severity') or r.get('severity_level') or ''
            return str(s).lower()
        stats = {
            'total_users': len(users),
            'total_computers': len(computers),
            'total_groups': len(groups),
            'total_risks': len(risks),
            'critical_count': sum(1 for r in risks if _sev(r) == 'critical'),
            'high_count': sum(1 for r in risks if _sev(r) == 'high'),
            'medium_count': sum(1 for r in risks if _sev(r) == 'medium'),
            'low_count': sum(1 for r in risks if _sev(r) == 'low')
        }
        return stats

    def _generate_charts_data(self, risks):
        """Generate data for Chart.js charts."""
        # Severity distribution
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for risk in risks:
            severity = risk.get('severity', 'medium').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Risk type distribution (top 10)
        risk_type_counts = {}
        for risk in risks:
            risk_type = risk.get('type', 'unknown')
            risk_type_counts[risk_type] = risk_type_counts.get(risk_type, 0) + 1
        
        top_risk_types = sorted(risk_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'severityLabels': ['Critical', 'High', 'Medium', 'Low'],
            'severityData': [
                severity_counts['critical'],
                severity_counts['high'],
                severity_counts['medium'],
                severity_counts['low']
            ],
            'riskTypeLabels': [rt[0] for rt in top_risk_types],
            'riskTypeData': [rt[1] for rt in top_risk_types]
        }

    def _max_severity_in_group(self, risk_list):
        """Return the highest severity in the list (critical > high > medium > low)."""
        order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        best = 'low'
        for r in risk_list:
            s = r.get('severity') or r.get('severity_level') or ''
            s = getattr(s, 'value', s)
            s = (s or '').lower().strip()
            if order.get(s, 0) > order.get(best, 0):
                best = s or best
        return best if best in order else 'medium'

    # Names that are not user/account identities (e.g. configuration placeholders)
    _NON_ACCOUNT_OBJECT_NAMES = frozenset({'Domain', 'Unknown'})

    def _group_risks_by_finding(self, risks):
        """
        Group risks by finding type. Same risk type = one group.
        Merges affected_object from each risk into affected_objects list.
        Uses max severity in group so the same finding type has one consistent level.
        Returns list of grouped risk dicts with affected_objects.
        """
        from collections import defaultdict
        groups = defaultdict(list)
        for risk in risks:
            key = risk.get('type', 'unknown')
            groups[key].append(risk)
        
        grouped_risks = []
        for risk_type, risk_list in groups.items():
            if not risk_list:
                continue
            base_risk = risk_list[0].copy()
            affected_objects = []
            seen = set()
            scores = []
            computers_with_laps = []
            affected_computers = []
            obj_type = base_risk.get('object_type', '')
            for r in risk_list:
                r_objs = r.get('affected_objects', []) or r.get('accounts', []) or []
                for obj in r_objs:
                    if obj is not None and obj not in seen:
                        if obj_type != 'user' or str(obj).strip() not in self._NON_ACCOUNT_OBJECT_NAMES:
                            seen.add(obj)
                            affected_objects.append(obj)
                obj = r.get('affected_object')
                if obj and obj_type in ('user', 'computer', 'group') and not r_objs:
                    # Support comma-separated affected_object (legacy) and exclude non-account names
                    parts = [p.strip() for p in str(obj).split(',') if p.strip()] if ',' in str(obj) else [obj]
                    for p in parts:
                        if p not in seen:
                            if obj_type != 'user' or p not in self._NON_ACCOUNT_OBJECT_NAMES:
                                seen.add(p)
                                affected_objects.append(p)
                for c in r.get('computers_with_laps', []) or []:
                    if c not in computers_with_laps:
                        computers_with_laps.append(c)
                for c in r.get('affected_computers', []) or []:
                    if c not in affected_computers:
                        affected_computers.append(c)
                sc = r.get('final_score', r.get('score', 0))
                if isinstance(sc, (int, float)):
                    scores.append(sc)
            if computers_with_laps:
                base_risk['computers_with_laps'] = computers_with_laps
            if affected_computers:
                base_risk['affected_computers'] = affected_computers
            if computers_with_laps or affected_computers:
                base_risk['affected_objects'] = computers_with_laps or affected_computers
                base_risk['affected_object'] = f'{len(base_risk["affected_objects"])} affected'
            elif affected_objects:
                base_risk['affected_objects'] = affected_objects
                base_risk['affected_object'] = f'{len(affected_objects)} affected' if len(affected_objects) > 1 else (affected_objects[0] if affected_objects else base_risk.get('affected_object', 'Unknown'))
            base_risk['_group_count'] = len(risk_list)
            # Same finding type = one severity: use max in group (so e.g. one privileged user makes whole group Critical)
            max_sev = self._max_severity_in_group(risk_list)
            base_risk['severity'] = max_sev
            base_risk['severity_level'] = max_sev.capitalize() if max_sev else 'Medium'
            if scores:
                base_risk['final_score'] = max(scores)
            # Generic description when multiple affected (avoid "User 'X' has..." repeated)
            if len(risk_list) > 1 and affected_objects:
                obj_label = {'user': 'user(s)', 'computer': 'computer(s)', 'group': 'group(s)'}.get(obj_type, 'object(s)')
                base_risk['description'] = f"{len(affected_objects)} {obj_label} affected. See list below."
            grouped_risks.append(base_risk)
        return grouped_risks

    def _generate_affected_objects_html(self, risk, accordion_id_selector, object_type_label='Affected'):
        """Generate HTML for displaying affected objects (users, computers, groups)."""
        affected_objects = risk.get('affected_objects', [])
        computers_with_laps = risk.get('computers_with_laps', [])
        affected_computers = risk.get('affected_computers', [])
        
        objects_to_show = affected_objects or computers_with_laps or affected_computers
        if not objects_to_show:
            return ''
        
        label_map = {'user': 'Affected Users', 'computer': 'Affected Computers', 'group': 'Affected Groups', 'configuration': 'Affected Computers', 'foreign_security_principal': 'Security Principal SIDs (not groups)'}
        label = label_map.get(risk.get('object_type', ''), object_type_label)
        acc_base = accordion_id_selector.replace('#', '') if accordion_id_selector else ''
        unique_id = f"aff_{acc_base}_{abs(hash(str(objects_to_show[:3])))}"
        
        items_html = ''.join(f'<span class="affected-item-chip">{html_stdlib.escape(str(obj))}</span>' for obj in objects_to_show[:50])
        if len(objects_to_show) > 50:
            items_html += f'<span class="affected-item-chip text-muted">+{len(objects_to_show) - 50} more</span>'
        
        return f"""
        <div class="accordion-item">
            <h2 class="accordion-header">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#{unique_id}">
                    <i class="fas fa-list-ul"></i> <span>{label}: {len(objects_to_show)} item(s)</span>
                </button>
            </h2>
            <div id="{unique_id}" class="accordion-collapse collapse" data-bs-parent="{accordion_id_selector}">
                <div class="accordion-body matrix-theme">
                    <div class="affected-items-container">{items_html}</div>
                </div>
            </div>
        </div>
        """

    def _generate_risk_list(self, risks, title, title_key=None, group_by_finding=False):
        """Generate HTML for a list of risks. When group_by_finding=True, groups same findings and shows affected objects."""
        if not risks:
            title_attr = f'' if title_key else ''
            return f"""
            <div class="card">
                <div class="card-body text-center">
                    <h5{title_attr}>{title}</h5>
                    <p class="text-muted">No risks found in this category.</p>
                </div>
            </div>
            """
        
        if group_by_finding:
            risks = self._group_risks_by_finding(risks)
        
        def _esc(s):
            """Escape string for safe HTML output (XSS prevention)."""
            if s is None: return ''
            return html_stdlib.escape(str(s))
        
        risk_cards = []
        for idx, risk in enumerate(risks):
            sev = risk.get('severity') or risk.get('severity_level') or 'medium'
            severity = getattr(sev, 'value', sev) if sev else 'medium'
            severity = str(severity).lower() if severity else 'medium'
            severity_class = f'risk-{severity}'
            severity_badge_color = self._get_severity_badge_class(severity)
            
            mitigation = _esc(risk.get('mitigation', 'No mitigation provided.'))
            impact = _esc(risk.get('impact', 'No impact description.'))
            attack_scenario = _esc(risk.get('attack_scenario', 'No attack scenario provided.'))
            
            risk_score = risk.get('final_score', risk.get('score', 0))
            if isinstance(risk_score, str):
                try:
                    risk_score = float(risk_score)
                except (ValueError, TypeError):
                    risk_score = 0
            
            accordion_id = f"acc_{title_key or 'risk'}_{idx}_{abs(hash(risk.get('type', '')))}"
            esc_title = _esc(risk.get('title', 'Unknown Risk'))
            esc_affected = _esc(risk.get('affected_object', 'Unknown'))
            esc_desc = _esc(risk.get('description', 'No description.'))
            esc_exec = _esc(risk.get('executive_description', 'No executive description available.'))
            esc_cis = _esc(risk.get('cis_reference', 'N/A'))
            esc_mitre = _esc(risk.get('mitre_attack', 'N/A'))
            esc_comb = _esc(risk.get('combination_bonus', ''))
            esc_type = _esc(risk.get('type', ''))
            esc_obj_type = _esc(risk.get('object_type', 'unknown'))
            
            comb_badge = f"<span class='badge bg-warning'>{esc_comb}</span>" if risk.get('combination_bonus') else ""
            cis_p = f"<p class='mt-2'><small><strong>CIS Reference:</strong> {esc_cis}</small></p>" if risk.get('cis_reference') else ""
            mitre_p = f"<p class='mt-2'><small><strong>MITRE ATT&CK:</strong> {esc_mitre}</small></p>" if risk.get('mitre_attack') else ""
            
            risk_card = f"""
            <div class="card risk-card {severity_class}" 
                 data-severity="{severity}" 
                 data-type="{esc_obj_type}" 
                 data-score="{risk_score:.1f}"
                 data-risk-id="risk_{idx}_{esc_type}">
                <div class="risk-card-header">
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="risk-title-section">
                            <h5 class="risk-title">{esc_title}</h5>
                            <div class="risk-meta">
                                <span class="badge bg-{severity_badge_color} badge-severity">{severity.upper()}</span>
                                <span class="risk-object text-muted"><strong>Affected:</strong> {esc_affected}</span>
                                <span class="risk-score badge bg-info">Score: {risk_score:.1f}/100</span>
                            </div>
                        </div>
                        <div class="risk-actions">
                            <button type="button" class="btn btn-sm btn-outline-primary" title="Export this risk" aria-label="Export risk" onclick="typeof exportSingleRiskToCsv === 'function' && exportSingleRiskToCsv(this)">
                                <i class="fas fa-download"></i>
                            </button>
                        </div>
                    </div>
                </div>
                <div class="risk-card-body">
                    <p class="card-text">{esc_desc}</p>
                    
                    <div class="mt-2 mb-2">
                        <span class="badge bg-secondary">Base Score: {risk.get('base_score', 'N/A')}</span>
                        <span class="badge bg-info">Final Score: {risk_score:.1f}/100</span>
                        {comb_badge}
                        {self._generate_exploitability_badge(risk)}
                    </div>
                    
                    <div class="accordion report-accordion mt-3" id="{accordion_id}">
                        <div class="accordion-item">
                            <h2 class="accordion-header">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#impact_{accordion_id}">
                                    <i class="fas fa-info-circle"></i> <span>Impact &amp; Attack Scenario</span>
                                </button>
                            </h2>
                            <div id="impact_{accordion_id}" class="accordion-collapse collapse" data-bs-parent="#{accordion_id}">
                                <div class="accordion-body matrix-theme">
                                    <p><strong>Impact:</strong> {impact}</p>
                                    <p><strong>Attack Scenario:</strong> {attack_scenario}</p>
                                    <p class="mt-2"><strong>Executive Summary:</strong> {esc_exec}</p>
                                </div>
                            </div>
                        </div>
                        <div class="accordion-item">
                            <h2 class="accordion-header">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#mitigation_{accordion_id}">
                                    <i class="fas fa-shield-alt"></i> <span>Mitigation</span>
                                </button>
                            </h2>
                            <div id="mitigation_{accordion_id}" class="accordion-collapse collapse" data-bs-parent="#{accordion_id}">
                                <div class="accordion-body matrix-theme">
                                    <p>{mitigation}</p>
                                    {cis_p}
                                    {mitre_p}
                                    {self._generate_exploitability_details(risk)}
                                </div>
                            </div>
                        </div>
                        {self._generate_affected_objects_html(risk, '#' + accordion_id)}
                    </div>
                </div>
            </div>
            """
            risk_cards.append(risk_card)
        
        title_attr = f'id="{title_key}"' if title_key else ''
        search_id = f'search_{title_key}' if title_key else f'search_{hash(title)}'
        container_id = f'risks_container_{title_key}' if title_key else f'risks_container_{hash(title)}'
        
        # Breadcrumb for this section
        breadcrumb_html = f"""
        <nav aria-label="breadcrumb" class="mb-4">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="#dashboard" onclick="if(typeof window.navigateToTab !== 'undefined'){{window.navigateToTab('dashboard-tab');}}">Dashboard</a></li>
                <li class="breadcrumb-item active" aria-current="page">{title}</li>
            </ol>
        </nav>
        """
        
        return f"""
        {breadcrumb_html}
        <div class="search-filter-bar mb-4">
            <div class="row g-3">
                <div class="col-md-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="{search_id}" 
                               placeholder="Search risks..." aria-label="Search risks">
                    </div>
                </div>
                <div class="col-md-2">
                    <select class="form-select" id="{search_id}_severity" aria-label="Filter by severity">
                        <option value="">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <select class="form-select" id="{search_id}_type" aria-label="Filter by type">
                        <option value="">All Types</option>
                        <option value="user">User Risks</option>
                        <option value="computer">Computer Risks</option>
                        <option value="group">Group Risks</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <select class="form-select" id="{search_id}_sort" aria-label="Sort by">
                        <option value="score-desc">Score (High to Low)</option>
                        <option value="score-asc">Score (Low to High)</option>
                        <option value="title-asc">Title (A-Z)</option>
                        <option value="title-desc">Title (Z-A)</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <button class="btn btn-primary w-100" id="{search_id}_export" aria-label="Export report">
                        <i class="fas fa-download"></i> Export
                    </button>
                </div>
            </div>
            <div class="row mt-2">
                <div class="col-12">
                    <small class="text-muted" id="{search_id}_results">Showing {len(risks)} risks</small>
                </div>
            </div>
        </div>
        <div class="card">
            <div class="card-header">
                <i class="fas fa-exclamation-triangle"></i> <span{title_attr}>{title}</span> <span class="badge bg-secondary">{len(risks)}</span>
            </div>
            <div class="card-body">
                <div class="risk-cards-container" id="{container_id}">
                    {''.join(risk_cards)}
                </div>
            </div>
        </div>
        """

    def _get_severity_badge_class(self, severity):
        """Return Bootstrap badge class for severity (report-wide consistent)."""
        if not severity:
            return 'secondary'
        s = (getattr(severity, 'value', severity) or severity)
        if hasattr(s, 'lower'):
            s = s.lower()
        else:
            s = str(s).lower()
        return {'critical': 'danger', 'high': 'warning', 'medium': 'info', 'low': 'success'}.get(s, 'secondary')

    def _get_severity_heat_class(self, severity):
        """Return heat map row CSS class for severity (same palette as risk cards)."""
        if not severity:
            return 'heat-severity-medium'
        s = (getattr(severity, 'value', severity) or severity)
        if hasattr(s, 'lower'):
            s = s.lower()
        else:
            s = str(s).lower()
        return f'heat-severity-{s}' if s in ('critical', 'high', 'medium', 'low') else 'heat-severity-medium'

    def _get_score_color(self, score):
        """Get color based on security score."""
        # Ensure score is a valid number
        try:
            score = float(score) if score is not None else 0.0
        except (ValueError, TypeError):
            score = 0.0
        
        if score >= 80:
            return 'green'
        elif score >= 60:
            return 'yellow'
        elif score >= 40:
            return 'orange'
        else:
            return 'red'
