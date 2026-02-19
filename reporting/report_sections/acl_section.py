"""
Mixin for ACL security, legacy OS, attack paths, misconfiguration, and escalation filtering.
"""

from collections import defaultdict
import html as html_stdlib



class ACLSectionMixin:
    """Mixin for ACL security, legacy OS, attack paths, misconfiguration, and escalation filtering."""

    def _generate_attack_paths(self, escalation_risks, users=None, groups=None):
        """Generate HTML for attack path visualization."""
        if not escalation_risks:
            return """
            <div class="card">
                <div class="card-body text-center">
                    <h5>Privilege Escalation Paths</h5>
                    <p class="text-muted">No privilege escalation paths detected.</p>
                </div>
            </div>
            """
        
        path_cards = []
        for risk in escalation_risks:
            # Extract user from different risk formats
            escalation_path = risk.get('escalation_path', {})
            user = escalation_path.get('user', risk.get('affected_object', risk.get('source_user', 'Unknown')))
            
            # Additional safety check: skip if user is already admin
            if users and groups and user != 'Unknown':
                if self._is_user_already_admin_in_report(user, users, groups):
                    continue
            
            path_html = f"""
            <div class="card risk-card risk-high">
                <div class="card-body">
                    <h5 class="card-title">{risk.get('title', 'Privilege Escalation Path')}</h5>
                    <p class="text-muted"><strong>User</strong>:</strong> {user}</p>
                    <p class="card-text">{risk.get('description', 'No description.')}</p>
                    
                    <div class="attack-path mt-3">
                        <strong>Escalation Path</strong>:<br>
                        <span class="path-step">{user}</span>
                        <span class="arrow">→</span>
            """
            
            # Add path steps
            direct_groups = escalation_path.get('direct_groups', [])
            for group_dn in direct_groups:
                group_name = group_dn.split('CN=')[1].split(',')[0] if 'CN=' in group_dn else group_dn
                path_html += f'<span class="path-step">{group_name}</span> <span class="arrow">→</span> '
            
            path_html += '<span class="path-step" style="background-color: #dc3545;">Privileged Access</span>'
            
            path_html += """
                    </div>
                    
                    <div class="mt-3">
                        <p><strong>Impact</strong>:</strong> """ + risk.get('impact', 'No impact description.') + """</p>
                        <p><strong>Mitigation</strong>:</strong> """ + risk.get('mitigation', 'No mitigation provided.') + """</p>
                    </div>
                </div>
            </div>
            """
            
            path_cards.append(path_html)
        
        return f"""
        <div class="card">
            <div class="card-header">
                <i class="fas fa-project-diagram"></i> <span>Privilege Escalation Paths</span> ({len(escalation_risks)})
            </div>
            <div class="card-body">
                <div class="input-group mb-3">
                    <span class="input-group-text"><i class="fas fa-search"></i></span>
                    <input type="text" class="form-control" id="attackPathsSearch" placeholder="Search paths by user, group, or description..." onkeyup="filterAttackPaths()">
                    <button class="btn btn-outline-secondary" type="button" onclick="clearAttackPathsSearch()">
                        <i class="fas fa-times"></i> Clear
                    </button>
                    <button class="btn btn-success" type="button" onclick="exportRiskSectionToCsv('attackPathsContainer', 'attack_paths')">
                        <i class="fas fa-download"></i> Export
                    </button>
                </div>
                <div id="attackPathsContainer">
                    {''.join(path_cards)}
                </div>
            </div>
        </div>
        """

    def _generate_misconfig_section(self, misconfig_findings):
        """Generate HTML for misconfiguration checklist."""
        if not misconfig_findings:
            return """
            <div class="card">
                <div class="card-body text-center">
                    <h5>Misconfiguration Checklist</h5>
                    <p class="text-muted">No misconfiguration issues found.</p>
                </div>
            </div>
            """
        
        findings_cards = []
        for finding in misconfig_findings:
            sev = finding.get('severity', 'medium')
            severity = getattr(sev, 'value', sev) if sev else 'medium'
            severity = str(severity).lower() if severity else 'medium'
            severity_badge_color = self._get_severity_badge_class(severity)
            
            finding_card = f"""
            <div class="card risk-card risk-{severity}">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <h5 class="card-title">{finding.get('title', 'Unknown Finding')}</h5>
                        <span class="badge bg-{severity_badge_color} badge-severity">{severity.upper()}</span>
                    </div>
                    <p class="text-muted"><strong>Category:</strong> {finding.get('category', 'General')}</p>
                    <p class="card-text">{finding.get('description', 'No description.')}</p>
                    
                    <div class="mt-3">
                        <p><strong>Recommendation:</strong> {finding.get('recommendation', 'No recommendation provided.')}</p>
                        <div class="mt-2">
                            <small class="text-muted">
                                <strong>CIS Reference:</strong> {finding.get('cis_reference', 'N/A')}<br>
                                <strong>Microsoft Reference:</strong> {finding.get('microsoft_reference', 'N/A')}
                            </small>
                        </div>
                    </div>
                </div>
            </div>
            """
            findings_cards.append(finding_card)
        
        return f"""
        <div class="card">
            <div class="card-header">
                <i class="fas fa-check-circle"></i> <span>CIS & Microsoft Best Practices Checklist</span> ({len(misconfig_findings)})
            </div>
            <div class="card-body">
                <p class="text-muted">This section contains findings based on CIS Benchmark and Microsoft Security Baseline recommendations.</p>
                <div class="input-group mb-3">
                    <span class="input-group-text"><i class="fas fa-search"></i></span>
                    <input type="text" class="form-control" id="misconfigSearch" placeholder="Search findings by title, category, or description..." onkeyup="filterMisconfig()">
                    <button class="btn btn-outline-secondary" type="button" onclick="clearMisconfigSearch()">
                        <i class="fas fa-times"></i> Clear
                    </button>
                    <button class="btn btn-success" type="button" onclick="exportRiskSectionToCsv('misconfigContainer', 'misconfig')">
                        <i class="fas fa-download"></i> Export
                    </button>
                </div>
                <div id="misconfigContainer">
                    {''.join(findings_cards)}
                </div>
            </div>
        </div>
        """

    def _generate_legacy_os_section(self, legacy_os_risks):
        """Generate Legacy OS section."""
        if not legacy_os_risks:
            return """
            <div class="card">
                <div class="card-body text-center">
                    <h5>Legacy Operating Systems</h5>
                    <p class="text-muted">No legacy operating systems detected.</p>
                </div>
            </div>
            """
        
        risks_html = ""
        for risk in legacy_os_risks:
            severity = risk.get('severity', 'medium').lower()
            severity_badge = f'<span class="badge bg-{self._get_severity_badge_class(severity)}">{severity.upper()}</span>'
            
            os_name = risk.get('operating_system', 'Unknown')
            is_eol = risk.get('is_eol', False)
            eol_date = risk.get('eol_date', 'N/A')
            days_since_eol = risk.get('days_since_eol')
            
            risks_html += f"""
            <div class="card mb-3 risk-card risk-{severity}">
                <div class="card-header">
                    <i class="fas fa-desktop"></i> {risk.get('affected_object', 'Unknown')} {severity_badge}
                </div>
                <div class="card-body">
                    <h6 class="card-title">{risk.get('title', 'Legacy OS')}</h6>
                    <p><strong>Operating System:</strong> {os_name}</p>
                    <p><strong>EOL Status:</strong> {'Yes' if is_eol else 'No'}</p>
                    {f'<p><strong>EOL Date:</strong> {eol_date}</p>' if eol_date != 'N/A' else ''}
                    {f'<p><strong>Days Since EOL:</strong> {days_since_eol}</p>' if days_since_eol else ''}
                    <p class="text-muted">{risk.get('description', '')}</p>
                    <div class="alert alert-warning matrix-theme">
                        <strong>Impact:</strong> {risk.get('impact', '')}
                    </div>
                    <div class="alert alert-danger matrix-theme">
                        <strong>Attack Scenario:</strong> {risk.get('attack_scenario', '')}
                    </div>
                    <div class="alert alert-info matrix-theme">
                        <strong>Mitigation:</strong> {risk.get('mitigation', '')}
                    </div>
                </div>
            </div>
            """
        
        return f"""
        <div class="card">
            <div class="card-header">
                <i class="fas fa-desktop"></i> Legacy Operating Systems Analysis
            </div>
            <div class="card-body">
                <p class="text-muted">Computers running legacy or end-of-life operating systems pose significant security risks.</p>
                {risks_html}
            </div>
        </div>
        """

    def _group_acl_risks(self, acl_risks):
        """
        Group ACL findings by (permission, trustee) so same permission + same trustee
        appears as one card with multiple affected objects. Reduces duplicate cards.
        """
        from collections import defaultdict
        groups = defaultdict(list)
        for risk in acl_risks:
            perm = risk.get('permission') or risk.get('type', '')
            trustee = risk.get('trustee') or 'Unknown'
            key = (perm, trustee)
            groups[key].append(risk)
        grouped = []
        for (perm, trustee), risk_list in groups.items():
            base = risk_list[0].copy()
            affected_list = []
            seen = set()
            any_inherited = False
            for r in risk_list:
                obj_type = r.get('object_type', '')
                obj_name = r.get('affected_object') or 'Unknown'
                pair = (obj_type, obj_name)
                if pair not in seen:
                    seen.add(pair)
                    affected_list.append({'object_type': obj_type, 'name': obj_name})
                if r.get('is_inherited'):
                    any_inherited = True
            base['affected_objects_detail'] = affected_list
            base['affected_count'] = len(affected_list)
            base['finding_count'] = len(risk_list)
            base['is_inherited'] = any_inherited
            grouped.append(base)
        return grouped

    def _generate_acl_security_section(self, acl_risks, shadow_admin_risks, escalation_risks):
        """Generate comprehensive ACL Security Analysis section with grouped findings."""
        sections_html = ""
        
        # ACL Risks Section (grouped by permission + trustee to avoid duplicate cards)
        if acl_risks:
            grouped_risks = self._group_acl_risks(acl_risks)
            acl_risks_html = ""
            for risk in grouped_risks:
                sev = risk.get('severity_level') or risk.get('severity', 'medium')
                severity = getattr(sev, 'value', sev) if sev else 'medium'
                if not isinstance(severity, str):
                    severity = str(severity)
                severity = severity.lower()
                severity_badge = f'<span class="badge bg-{self._get_severity_badge_class(severity)}">{severity.upper()}</span>'
                desc = risk.get('description', '')
                perm_desc = risk.get('permission_description', '')
                impact = risk.get('impact', '')
                attack = risk.get('attack_scenario', '')
                mitigation = risk.get('mitigation', '')
                mitre = risk.get('mitre_attack', '')
                inherited = risk.get('is_inherited', False)
                inherited_note = ' <span class="badge bg-secondary">Inherited</span>' if inherited else ''
                trustee_display = risk.get('trustee_display_name')
                trustee_sid = risk.get('trustee', 'Unknown')
                trustee_label = html_stdlib.escape(trustee_display or trustee_sid)
                trustee_sub = f' <span class="text-muted small">({html_stdlib.escape(trustee_sid)})</span>' if trustee_display and trustee_sid else ''
                count = risk.get('affected_count', 0)
                count_note = f' <span class="badge bg-secondary">{count} object(s)</span>' if count > 1 else ''
                affected_detail = risk.get('affected_objects_detail', [])
                affected_chips = ''.join(
                    f'<span class="badge bg-light text-dark border me-1 mb-1">{html_stdlib.escape(str(a.get("object_type", "")))}: {html_stdlib.escape(str(a.get("name", "")))}</span>'
                    for a in affected_detail[:15]
                )
                if len(affected_detail) > 15:
                    affected_chips += f'<span class="text-muted small">+{len(affected_detail) - 15} more</span>'
                affected_block = f'<div class="mt-1">{affected_chips}</div>' if affected_detail else ''
    
                acl_risks_html += f"""
                <div class="card mb-3 risk-card risk-{severity}">
                    <div class="card-body">
                        <h6>{html_stdlib.escape(risk.get('title', 'ACL Risk'))} {severity_badge}{count_note}{inherited_note}</h6>
                        <p class="mb-1"><strong>Trustee:</strong> {trustee_label}{trustee_sub}</p>
                        <p class="mb-1"><strong>Permission:</strong> {html_stdlib.escape(str(risk.get('permission', 'Unknown')))}</p>
                        <p class="mb-1"><strong>Affected objects:</strong>{affected_block}</p>
                        <p class="mb-1"><strong>What is the risk?</strong> {html_stdlib.escape(perm_desc or desc)}</p>
                        {f'<p class="mb-1"><strong>Impact:</strong> {html_stdlib.escape(impact)}</p>' if impact else ''}
                        {f'<div class="alert alert-danger mb-2 py-2"><strong>Attack scenario:</strong> {html_stdlib.escape(attack)}</div>' if attack else ''}
                        {f'<div class="alert alert-success mb-1 py-2"><strong>Recommendation:</strong> {html_stdlib.escape(mitigation)}</div>' if mitigation else ''}
                        {f'<p class="text-muted small mb-0">MITRE ATT&amp;CK: {html_stdlib.escape(mitre)}</p>' if mitre else ''}
                    </div>
                </div>
                """
            
            total_findings = len(acl_risks)
            sections_html += f"""
            <div class="card mb-4">
                <div class="card-header">
                    <i class="fas fa-shield-alt"></i> ACL Permission Risks
                </div>
                <div class="card-body">
                    <p class="text-muted small mb-3">Dangerous permissions on critical objects (domain, users, groups). Findings are grouped by permission and trustee; each card lists all affected objects.</p>
                    {acl_risks_html}
                    <p class="text-muted small mb-0">{len(grouped_risks)} group(s), {total_findings} total finding(s)</p>
                </div>
            </div>
            """
        
        # Shadow Admins Section
        if shadow_admin_risks:
            shadow_html = ""
            for risk in shadow_admin_risks:
                sev = risk.get('severity') or risk.get('risk_level', 'high')
                severity = getattr(sev, 'value', sev) if sev else 'high'
                severity = str(severity).lower()
                severity_badge = f'<span class="badge bg-{self._get_severity_badge_class(severity)}">{severity.upper()}</span>'
                display_name = risk.get('affected_object') or risk.get('user', 'Unknown')
                
                dangerous_perms = risk.get('dangerous_permissions', [])
                perms_html = ""
                for perm in dangerous_perms[:10]:
                    perm_name = perm.get('permission', 'Unknown')
                    obj_info = perm.get('object') or perm.get('object_type') or ''
                    perms_html += f"<li>{html_stdlib.escape(perm_name)}{(' on ' + html_stdlib.escape(obj_info)) if obj_info else ''}</li>"
                
                why_risky = risk.get('why_risky', 'Has dangerous permissions without being Domain Admin')
                attack_scenario = risk.get('attack_scenario', '')
                recommendation = risk.get('recommendation', '')
                
                shadow_html += f"""
                <div class="card mb-3 risk-card risk-{severity}">
                    <div class="card-header">
                        <i class="fas fa-user-secret"></i> Shadow Admin: {html_stdlib.escape(display_name)} {severity_badge}
                    </div>
                    <div class="card-body">
                        <p><strong>What is the risk?</strong> {html_stdlib.escape(why_risky)}</p>
                        <p><strong>Dangerous permissions:</strong></p>
                        <ul class="mb-2">{perms_html}</ul>
                        {f'<div class="alert alert-danger mb-2 py-2"><strong>Attack scenario:</strong> {html_stdlib.escape(attack_scenario)}</div>' if attack_scenario else ''}
                        {f'<div class="alert alert-success mb-0 py-2"><strong>Recommendation:</strong> {html_stdlib.escape(recommendation)}</div>' if recommendation else ''}
                    </div>
                </div>
                """
            
            sections_html += f"""
            <div class="card mb-4">
                <div class="card-header bg-danger text-white">
                    <i class="fas fa-user-secret"></i> Shadow Admins Detected
                </div>
                <div class="card-body">
                    <p class="text-muted">Users or accounts that have dangerous ACL permissions on critical objects but are <strong>not</strong> members of Domain Admins or Enterprise Admins. They can often achieve the same impact as a Domain Admin if compromised.</p>
                    {shadow_html}
                </div>
            </div>
            """
        
        # ACL Escalation Paths Section
        if escalation_risks:
            escalation_html = ""
            for risk in escalation_risks:
                path = risk.get('path', [])
                path_str = ' → '.join(path) if path else 'Unknown'
                source = risk.get('affected_object') or risk.get('source_user', 'Unknown')
                attack_scenario = risk.get('attack_scenario', '')
                
                escalation_html += f"""
                <div class="card mb-3">
                    <div class="card-body">
                        <h6>Path from {html_stdlib.escape(str(source))} to Domain Admin</h6>
                        <p class="mb-1"><strong>Hops:</strong> {risk.get('hops', 0)}</p>
                        <p class="mb-1"><strong>Path:</strong> {html_stdlib.escape(path_str)}</p>
                        {f'<p class="mb-1"><strong>What an attacker could do:</strong> {html_stdlib.escape(attack_scenario)}</p>' if attack_scenario else ''}
                        <div class="alert alert-success mb-0 py-2"><strong>Recommendation:</strong> Remove or restrict the dangerous ACL permissions along this path (especially on the first hop). Ensure only Tier-0/Tier-1 accounts have sensitive rights on domain and admin objects.</div>
                    </div>
                </div>
                """
            
            sections_html += f"""
            <div class="card mb-4">
                <div class="card-header">
                    <i class="fas fa-route"></i> ACL-Based Privilege Escalation Paths
                </div>
                <div class="card-body">
                    <p class="text-muted small mb-3">Chains of permissions that allow a lower-privilege account to reach Domain Admin (or equivalent) by abusing ACLs step by step.</p>
                    {escalation_html}
                </div>
            </div>
            """
        
        if not sections_html:
            return """
            <div class="card">
                <div class="card-body text-center">
                    <h5>ACL Security Analysis</h5>
                    <p class="text-muted">No ACL security risks detected.</p>
                </div>
            </div>
            """
        
        return f"""
        <div class="card">
            <div class="card-header bg-primary text-white">
                <i class="fas fa-shield-alt"></i> Comprehensive ACL Security Analysis
            </div>
            <div class="card-body">
                <p class="text-muted">Analysis of Access Control Lists, Shadow Admins, and privilege escalation paths through ACLs.</p>
                {sections_html}
            </div>
        </div>
        """

    def _filter_admin_users_from_escalation_paths(self, escalation_risks, users, groups):
        """
        Filter out escalation paths for users who are already admins.
        
        Args:
            escalation_risks: List of escalation risk dictionaries
            users: List of user dictionaries
            groups: List of group dictionaries
            
        Returns:
            list: Filtered escalation risks
        """
        if not escalation_risks or not users or not groups:
            return escalation_risks
        
        filtered_risks = []
        privileged_group_names = self._get_privileged_group_names(groups)
        
        for risk in escalation_risks:
            # Extract username from different risk formats
            user = None
            escalation_path = risk.get('escalation_path', {})
            if escalation_path:
                user = escalation_path.get('user')
            
            if not user:
                user = risk.get('affected_object') or risk.get('source_user')
            
            if not user:
                # If we can't identify the user, include the risk
                filtered_risks.append(risk)
                continue
            
            # Check if user is already admin
            if self._is_user_already_admin_in_report(user, users, groups, privileged_group_names):
                continue
            
            filtered_risks.append(risk)
        
        return filtered_risks

    def _is_user_already_admin_in_report(self, username, users, groups, privileged_group_names=None):
        """
        Check if user is already Domain Admin or Enterprise Admin.
        
        Args:
            username: Username to check
            users: List of user dictionaries
            groups: List of group dictionaries
            privileged_group_names: Optional set of privileged group names
            
        Returns:
            bool: True if user is already admin
        """
        if not username or not users:
            return False
        
        # Find user in users list
        user_obj = None
        for u in users:
            if u.get('sAMAccountName') == username:
                user_obj = u
                break
        
        if not user_obj:
            return False
        
        # Check adminCount flag
        if user_obj.get('adminCount') == 1 or user_obj.get('adminCount') == '1':
            return True
        
        # Check group memberships
        if not privileged_group_names:
            privileged_group_names = self._get_privileged_group_names(groups)
        
        member_of = user_obj.get('memberOf', [])
        if isinstance(member_of, str):
            member_of = [member_of]
        
        for group_dn in member_of:
            # Extract group name from DN
            group_name = self._extract_group_name_from_dn(group_dn)
            if group_name and group_name.lower() in privileged_group_names:
                return True
        
        return False

    def _get_privileged_group_names(self, groups):
        """
        Get set of privileged group names (lowercase).
        
        Args:
            groups: List of group dictionaries
            
        Returns:
            set: Set of privileged group names in lowercase
        """
        privileged_groups = {
            'domain admins', 'enterprise admins', 'schema admins',
            'account operators', 'backup operators', 'server operators',
            'print operators', 'administrators'
        }
        
        # Also check actual group names
        for group in groups:
            group_name = (group.get('name') or group.get('sAMAccountName') or '').lower()
            if any(priv_name in group_name for priv_name in ['domain admin', 'enterprise admin', 'schema admin']):
                privileged_groups.add(group_name)
        
        return privileged_groups

    def _extract_group_name_from_dn(self, dn):
        """
        Extract group name from distinguished name.
        
        Args:
            dn: Distinguished name string
            
        Returns:
            str: Group name or None
        """
        if not dn:
            return None
        
        try:
            if 'CN=' in dn:
                cn_part = dn.split('CN=')[1].split(',')[0]
                return cn_part.strip()
        except Exception:
            pass
        
        return None
