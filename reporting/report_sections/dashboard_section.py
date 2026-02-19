"""
Mixin for CISO dashboard, executive summary, password stats, account activity, admin groups, account status.
"""

import html as html_stdlib
import json
import re



class DashboardSectionMixin:
    """Mixin for CISO dashboard, executive summary, password stats, account activity, admin groups, account status."""

    def _generate_ciso_dashboard_html(self, ciso_data, stats):
        """Generate CISO-focused executive dashboard HTML."""
        import json
        
        kpis = ciso_data['kpis']
        risk_dist = ciso_data['risk_distribution']
        risk_categories = ciso_data['risk_by_category']
        top_objects = ciso_data['top_risky_objects']
        ciso_summary = ciso_data['ciso_summary']
        all_analyses_summary = ciso_data.get('all_analyses_summary', [])
        action_priorities = ciso_data['action_priorities']
        password_stats = ciso_data.get('password_stats', {})
        
        # KPI Cards with clickable navigation
        kpi_cards = []
        for kpi_key, kpi_data in kpis.items():
            color_class = {
                'green': 'success',
                'yellow': 'warning',
                'orange': 'warning',
                'red': 'danger'
            }.get(kpi_data['color'], 'secondary')
            
            # Determine target tab for each KPI
            target_tab = None
            onclick_handler = ""
            cursor_style = ""
            if kpi_key == 'critical_risks':
                target_tab = 'critical-risks'
                onclick_handler = 'onclick="navigateToTab(\'critical-risks-tab\')"'
                cursor_style = 'cursor: pointer;'
            elif kpi_key == 'high_risks':
                target_tab = 'high-risks'
                onclick_handler = 'onclick="navigateToTab(\'high-risks-tab\')"'
                cursor_style = 'cursor: pointer;'
            elif kpi_key == 'privileged_accounts':
                target_tab = 'privileged-accounts'
                onclick_handler = 'onclick="navigateToTab(\'privileged-accounts-tab\')"'
                cursor_style = 'cursor: pointer;'
            elif kpi_key == 'delegation_risks':
                target_tab = 'delegation-risks'
                onclick_handler = 'onclick="navigateToTab(\'delegation-risks-tab\')"'
                cursor_style = 'cursor: pointer;'
            
            # Add hover effect for clickable cards
            hover_style = ""
            if onclick_handler:
                hover_style += "transition: all 0.2s ease;"
                hover_style += "box-shadow: 0 2px 4px rgba(0,0,0,0.1);"
            
            # Create click handler with proper event handling
            click_handler_attr = ""
            if onclick_handler:
                # Extract tab ID from onclick handler
                import re
                match = re.search(r"navigateToTab\('([^']+)'\)", onclick_handler)
                if match:
                    tab_id = match.group(1)
                    click_handler_attr = f'data-tab-target="{tab_id}" onclick="if(typeof window.navigateToTab !== \'undefined\'){{window.navigateToTab(\'{tab_id}\');}}else{{console.warn(\'navigateToTab not loaded yet\');}}"'
            
            kpi_cards.append(f"""
            <div class="col-md-2 col-sm-6 mb-3">
                <div class="card text-center h-100 border-{color_class}" style="border-width: 1px !important; {cursor_style} {hover_style}" {click_handler_attr} onmouseover="if(this.style.cursor=='pointer'){{this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 8px rgba(0,0,0,0.15)';}}" onmouseout="if(this.style.cursor=='pointer'){{this.style.transform=''; this.style.boxShadow='';}}">
                    <div class="card-body" style="pointer-events: none;">
                        <h6 class="card-title text-muted mb-2" style="font-size: 0.8125rem;">{kpi_data['label']}</h6>
                        <h2 class="mb-0 text-{color_class}" style="font-size: 1.75rem;">{f"{kpi_data['value']:.1f}" if kpi_key == 'overall_score' and isinstance(kpi_data['value'], (int, float)) else kpi_data['value']}</h2>
                        {f"<small class='text-muted' style='font-size: 0.75rem;'>/100</small>" if kpi_key == 'overall_score' else ""}
                    </div>
                </div>
            </div>
            """)
        
        # Executive Summary: enhanced block (paragraph + key metrics + complete analysis table)
        summary_card = self._generate_executive_summary_block(
            ciso_summary, risk_dist, kpis, all_analyses_summary
        )
        
        # Password Statistics Section (define before charts_html)
        password_stats = ciso_data.get('password_stats', {})
        password_stats_html = self._generate_password_stats_html(password_stats)
        
        # Account Activity Statistics
        account_activity_stats = ciso_data.get('account_activity_stats', {})
        account_activity_html = self._generate_account_activity_html(account_activity_stats)
        
        # Admin Group Statistics
        admin_group_stats = ciso_data.get('admin_group_stats', {})
        admin_group_html = self._generate_admin_group_html(admin_group_stats)
        
        # Account Status Statistics
        account_status_stats = ciso_data.get('account_status_stats', {})
        account_status_html = self._generate_account_status_html(account_status_stats)
        
        # Charts HTML (OpenVAS style)
        charts_html = f"""
        <div class="row mb-3">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-chart-pie"></i> Risk Distribution
                    </div>
                    <div class="card-body" style="height: 280px; position: relative; padding: 1rem;">
                        <canvas id="cisoRiskDistributionChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-chart-bar"></i> Risks by Category
                    </div>
                    <div class="card-body" style="height: 280px; position: relative; padding: 1rem;">
                        <canvas id="cisoRiskCategoryChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        """
        
        # Top Risky Objects Table
        risky_objects_rows = []
        for i, obj in enumerate(top_objects, 1):
            type_badge = {
                'user': 'primary',
                'computer': 'info',
                'group': 'secondary'
            }.get(obj['type'].lower(), 'secondary')
            
            esc_name = html_stdlib.escape(str(obj['name']))
            esc_type = html_stdlib.escape(str(obj['type']))
            risky_objects_rows.append(f"""
            <tr>
                <td>{i}</td>
                <td><span class="badge bg-{type_badge}">{esc_type}</span></td>
                <td><strong>{esc_name}</strong></td>
                <td>{obj['total_score']:.1f}</td>
                <td>{obj['risk_count']}</td>
            </tr>
            """)
        
        risky_objects_table = f"""
        <div class="card mb-3">
            <div class="card-header">
                <i class="fas fa-exclamation-triangle"></i> Top 10 Riskiest Objects
            </div>
            <div class="card-body" style="padding: 0;">
                <div class="table-responsive">
                    <table class="table table-hover mb-0">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Type</th>
                                <th>Name</th>
                                <th>Risk Score</th>
                                <th>Risk Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(risky_objects_rows) if risky_objects_rows else '<tr><td colspan="5" class="text-center">No risky objects found.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
        
        # Action Priorities
        quick_wins_html = self._generate_action_items_html(action_priorities['quick_wins'], 'Quick Wins (0-30 Days)', 'success')
        medium_term_html = self._generate_action_items_html(action_priorities['medium_term'], 'Medium-Term Actions (30-90 Days)', 'warning')
        long_term_html = self._generate_action_items_html(action_priorities['long_term'], 'Long-Term Improvements (90+ Days)', 'info')
        
        # Charts data for JavaScript
        charts_data_json = {
            'risk_distribution': {
                'labels': list(risk_dist.keys()),
                'data': list(risk_dist.values())
            },
            'risk_categories': {
                'labels': list(risk_categories.keys()),
                'data': list(risk_categories.values())
            }
        }
        
        return f"""
        <!-- CISO Dashboard -->
        <script>
        // navigateToTab is already defined in the SaaS report template.
        // This block ensures backward-compat if the function isn't loaded yet.
        if (typeof window.navigateToTab === 'undefined') {{
            window.navigateToTab = function(tabId) {{
                var paneId = tabId.replace(/-tab$/, '');
                if (typeof window.showTab === 'function') {{ window.showTab(paneId); }}
                else {{ console.warn('showTab not loaded yet for:', tabId); }}
            }};
        }}
        </script>
        
        <div class="row mb-4">
            {''.join(kpi_cards)}
        </div>
        
        {summary_card}
        
        {charts_html}
        
        {password_stats_html}
        
        {account_activity_html}
        
        {admin_group_html}
        
        {account_status_html}
        
        {risky_objects_table}
        
        <div class="row">
            <div class="col-md-4">
                {quick_wins_html}
            </div>
            <div class="col-md-4">
                {medium_term_html}
            </div>
            <div class="col-md-4">
                {long_term_html}
            </div>
        </div>
        
        <script>
        // CISO Dashboard Charts - Initialize after DOM ready
        document.addEventListener('DOMContentLoaded', function() {{
            const cisoChartsData = {json.dumps(charts_data_json, default=str)};
            
            // Risk Distribution Chart
            const cisoRiskDistCtx = document.getElementById('cisoRiskDistributionChart');
            if (cisoRiskDistCtx) {{
                new Chart(cisoRiskDistCtx.getContext('2d'), {{
                    type: 'doughnut',
                    data: {{
                        labels: cisoChartsData.risk_distribution.labels,
                        datasets: [{{
                            data: cisoChartsData.risk_distribution.data,
                            backgroundColor: [
                                '#d9534f',
                                '#f5a623',
                                '#5bc0de',
                                '#70c050'
                            ],
                            borderWidth: 1,
                            borderColor: 'rgba(30, 41, 59, 0.8)'
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{
                                position: 'bottom',
                                labels: {{
                                    boxWidth: 12,
                                    padding: 8,
                                    font: {{
                                        size: 11
                                    }}
                                }}
                            }},
                            tooltip: {{
                                backgroundColor: 'rgba(0,0,0,0.8)',
                                padding: 10,
                                titleFont: {{
                                    size: 12
                                }},
                                bodyFont: {{
                                    size: 11
                                }}
                            }}
                        }}
                    }}
                }});
            }}
            
            // Risk Category Chart
            const cisoCategoryCtx = document.getElementById('cisoRiskCategoryChart');
            if (cisoCategoryCtx) {{
                new Chart(cisoCategoryCtx.getContext('2d'), {{
                    type: 'bar',
                    data: {{
                        labels: cisoChartsData.risk_categories.labels,
                        datasets: [{{
                            label: 'Risk Count',
                            data: cisoChartsData.risk_categories.data,
                            backgroundColor: '#4a90e2',
                            borderColor: '#357abd',
                            borderWidth: 1
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{
                                display: false
                            }},
                            tooltip: {{
                                backgroundColor: 'rgba(0,0,0,0.8)',
                                padding: 10,
                                titleFont: {{
                                    size: 12
                                }},
                                bodyFont: {{
                                    size: 11
                                }}
                            }}
                        }},
                        scales: {{
                            y: {{
                                beginAtZero: true,
                                ticks: {{
                                    font: {{
                                        size: 10
                                    }},
                                    stepSize: 1
                                }},
                                grid: {{
                                    color: 'rgba(0,0,0,0.05)'
                                }}
                            }},
                            x: {{
                                ticks: {{
                                    font: {{
                                        size: 10
                                    }},
                                    maxRotation: 45,
                                    minRotation: 0
                                }},
                                grid: {{
                                    display: false
                                }}
                            }}
                        }}
                    }}
                }});
            }}
        }});
        </script>
        """

    def _generate_password_issues_full_list(self, password_stats):
        """Generate full list of password issues with pagination."""
        if not password_stats or password_stats.get('total_users', 0) == 0:
            return """
            <div class="card">
                <div class="card-body text-center">
                    <h5>Password Issues</h5>
                    <p class="text-muted">No password issues found.</p>
                </div>
            </div>
            """
        
        import json
        all_details = password_stats.get('details', [])
        total_count = len(all_details)
        
        # Store all details in JavaScript variable
        all_details_json = json.dumps(all_details, default=str)
        
        return f"""
        <div class="card">
            <div class="card-header bg-warning text-white">
                <i class="fas fa-key"></i> All Password Issues ({total_count})
            </div>
            <div class="card-body">
                <div class="input-group mb-3">
                    <span class="input-group-text"><i class="fas fa-search"></i></span>
                    <input type="text" class="form-control" id="passwordIssuesFullSearch" placeholder="Search by username or issue..." onkeyup="filterPasswordIssuesFull()">
                    <button class="btn btn-outline-secondary" type="button" onclick="clearPasswordIssuesFullSearch()">
                        <i class="fas fa-times"></i> Clear
                    </button>
                </div>
                <div class="table-responsive">
                    <table class="table table-sm table-hover" id="passwordIssuesFullTable">
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Issue</th>
                                <th>Age (Days)</th>
                            </tr>
                        </thead>
                        <tbody id="passwordIssuesFullTableBody">
                            <!-- Content will be populated by JavaScript -->
                        </tbody>
                    </table>
                </div>
                <div class="d-flex justify-content-between align-items-center mt-3" id="passwordIssuesFullPagination">
                    <div>
                        <button class="btn btn-sm btn-success me-2" onclick="exportTableToExcel('passwordIssuesFullTable', 'Password_Issues_Full')">
                            <i class="fas fa-file-excel"></i> Export to Excel
                        </button>
                        <small class="text-muted" id="passwordIssuesFullInfo">Loading...</small>
                    </div>
                    <nav>
                        <ul class="pagination pagination-sm mb-0">
                            <li class="page-item disabled" id="passwordIssuesFullPrev">
                                <a class="page-link" href="#" onclick="changePasswordIssuesFullPage(-1); return false;">Previous</a>
                            </li>
                            <li class="page-item active">
                                <span class="page-link" id="passwordIssuesFullPageInfo">Page 1</span>
                            </li>
                            <li class="page-item" id="passwordIssuesFullNext">
                                <a class="page-link" href="#" onclick="changePasswordIssuesFullPage(1); return false;">Next</a>
                            </li>
                        </ul>
                    </nav>
                </div>
            </div>
        </div>
        <script>
        // Store password issues full data
        if (!window.passwordIssuesFullData) {{
            window.passwordIssuesFullData = {all_details_json};
            window.passwordIssuesFullCurrentPage = 1;
            window.passwordIssuesFullPageSize = 10;
        }}
        
        function changePasswordIssuesFullPage(direction) {{
            const data = window.passwordIssuesFullData;
            const totalPages = Math.ceil(data.length / window.passwordIssuesFullPageSize);
            const newPage = window.passwordIssuesFullCurrentPage + direction;
            
            if (newPage < 1 || newPage > totalPages) {{
                return;
            }}
            
            window.passwordIssuesFullCurrentPage = newPage;
            updatePasswordIssuesFullTable();
        }}
        
        function updatePasswordIssuesFullTable() {{
            const data = window.passwordIssuesFullData;
            const page = window.passwordIssuesFullCurrentPage;
            const pageSize = window.passwordIssuesFullPageSize;
            const start = (page - 1) * pageSize;
            const end = start + pageSize;
            const pageData = data.slice(start, end);
            
            const tbody = document.getElementById('passwordIssuesFullTableBody');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            pageData.forEach(detail => {{
                let daysBadge = '';
                if (detail.days !== null && detail.days !== undefined) {{
                    const days = detail.days;
                    if (days > 365) {{
                        daysBadge = `<span class="badge bg-danger">${{days}}</span>`;
                    }} else if (days > 180) {{
                        daysBadge = `<span class="badge bg-warning">${{days}}</span>`;
                    }} else if (days > 90) {{
                        daysBadge = `<span class="badge bg-info">${{days}}</span>`;
                    }} else {{
                        daysBadge = `<span class="badge bg-secondary">${{days}}</span>`;
                    }}
                }} else {{
                    daysBadge = '<span class="badge bg-danger">N/A</span>';
                }}
                
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td><strong>${{detail.username || 'Unknown'}}</strong></td>
                    <td>${{detail.issue || 'N/A'}}</td>
                    <td>${{daysBadge}}</td>
                `;
                tbody.appendChild(row);
            }});
            
            // Update pagination controls
            const totalPages = Math.ceil(data.length / pageSize);
            const prevBtn = document.getElementById('passwordIssuesFullPrev');
            const nextBtn = document.getElementById('passwordIssuesFullNext');
            const pageInfo = document.getElementById('passwordIssuesFullPageInfo');
            const info = document.getElementById('passwordIssuesFullInfo');
            
            if (prevBtn) {{
                prevBtn.classList.toggle('disabled', page === 1);
            }}
            if (nextBtn) {{
                nextBtn.classList.toggle('disabled', page === totalPages);
            }}
            if (pageInfo) {{
                pageInfo.textContent = `Page ${{page}} of ${{totalPages}}`;
            }}
            if (info) {{
                info.textContent = `Showing ${{start + 1}}-${{Math.min(end, data.length)}} of ${{data.length}} issues`;
            }}
        }}
        
        // Initialize table when tab is shown
        document.addEventListener('DOMContentLoaded', function() {{
            const passwordIssuesTab = document.getElementById('password-issues-tab');
            if (passwordIssuesTab) {{
                passwordIssuesTab.addEventListener('shown.bs.tab', function() {{
                    updatePasswordIssuesFullTable();
                }});
            }}
            // Also initialize if tab is already active
            if (passwordIssuesTab && passwordIssuesTab.classList.contains('active')) {{
                updatePasswordIssuesFullTable();
            }}
        }});
        </script>
        """

    def _generate_action_items_html(self, action_items, title, badge_color):
        """Generate HTML for action items."""
        if not action_items:
            return f"""
            <div class="card mb-4">
                <div class="card-header bg-{badge_color} text-white">
                    <i class="fas fa-tasks"></i> {title}
                </div>
                <div class="card-body">
                    <p class="text-muted">No actions in this category.</p>
                </div>
            </div>
            """
        
        items_html = []
        for item in action_items[:5]:
            items_html.append(f"""
            <div class="card mb-2">
                <div class="card-body">
                    <h6 class="card-title">{item.get('action', 'Unknown Action')}</h6>
                    <p class="mb-1"><small class="text-muted">Impact: <span class="badge bg-warning">{item.get('impact', 'Medium')}</span></small></p>
                    <p class="mb-1"><small class="text-muted">Affected: {item.get('affected_count', 0)} objects</small></p>
                    <p class="mb-1"><small class="text-muted">Risk Reduction: {item.get('estimated_risk_reduction', 'N/A')}</small></p>
                    <p class="mb-0 text-muted small">{item.get('description', '')[:100]}...</p>
                </div>
            </div>
            """)
        
        return f"""
        <div class="card mb-4">
            <div class="card-header bg-{badge_color} text-white">
                <i class="fas fa-tasks"></i> {title}
            </div>
            <div class="card-body">
                {''.join(items_html)}
            </div>
        </div>
        """

    def _generate_executive_summary_section(self, executive_summary):
        """Generate executive summary section for dashboard."""
        if not executive_summary:
            return ""
        
        # Top critical risks
        top_risks_html = ""
        for i, risk in enumerate(executive_summary.get('top_critical_risks', [])[:5], 1):
            top_risks_html += f"""
            <div class="card risk-card risk-high mb-2">
                <div class="card-body">
                    <h6 class="card-title">#{i}. {risk.get('title', 'Unknown Risk')}</h6>
                    <p class="mb-1"><strong>Score</strong>:</strong> {risk.get('score', 0):.1f}/100</p>
                    <p class="mb-1"><strong>Affected</strong>:</strong> {risk.get('affected_object', 'Unknown')}</p>
                    <p class="mb-0 text-muted small">{risk.get('executive_description', '')}</p>
                </div>
            </div>
            """
        
        # Most risky object
        most_risky_html = ""
        most_risky = executive_summary.get('most_risky_object')
        if most_risky:
            most_risky_html = f"""
            <div class="card">
                <div class="card-body">
                    <h6 class="card-title"><i class="fas fa-exclamation-circle text-danger"></i> <span>Most Risky Object</span></h6>
                    <p><strong>Object</strong>:</strong> {most_risky.get('object', 'Unknown')}</p>
                    <p><strong>Total Risk Score</strong>:</strong> {most_risky.get('total_risk_score', 0):.1f}</p>
                    <p><strong>Number of Risks</strong>:</strong> {most_risky.get('risk_count', 0)}</p>
                </div>
            </div>
            """
        
        # Quick wins
        quick_wins_html = ""
        for win in executive_summary.get('quick_wins', [])[:5]:
            quick_wins_html += f"""
            <div class="card mb-2">
                <div class="card-body">
                    <h6 class="card-title">{win.get('action', 'Unknown Action')}</h6>
                    <p class="mb-1"><strong>Impact</strong>:</strong> <span class="badge bg-warning">{win.get('impact', 'Medium')}</span></p>
                    <p class="mb-1"><strong>Effort</strong>:</strong> <span class="badge bg-success">{win.get('effort', 'Low')}</span></p>
                    <p class="mb-1"><strong>Affected</strong>:</strong> {win.get('affected_count', 0)} <span>object(s)</span></p>
                    <p class="mb-0 text-muted small">{win.get('description', '')}</p>
                </div>
            </div>
            """
        
        # Long-term improvements
        long_term_html = ""
        for improvement in executive_summary.get('long_term_improvements', []):
            long_term_html += f"""
            <div class="card mb-2">
                <div class="card-body">
                    <h6 class="card-title">{improvement.get('action', 'Unknown Action')}</h6>
                    <p class="mb-1"><strong>Timeline</strong>:</strong> {improvement.get('timeline', 'Unknown')}</p>
                    <p class="mb-1"><strong>Impact</strong>:</strong> <span class="badge bg-danger">{improvement.get('impact', 'High')}</span></p>
                    <p class="mb-0 text-muted small">{improvement.get('description', '')}</p>
                </div>
            </div>
            """
        
        return f"""
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-star"></i> <span>Top 5 Critical Risks</span>
                    </div>
                    <div class="card-body">
                        {top_risks_html if top_risks_html else '<p class="text-muted">No critical risks found.</p>'}
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                {most_risky_html}
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-bolt"></i> <span>Quick Wins (High Impact, Low Effort)</span>
                    </div>
                    <div class="card-body">
                        {quick_wins_html if quick_wins_html else '<p class="text-muted">No quick wins identified.</p>'}
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-road"></i> <span>Long-Term Improvements</span>
                    </div>
                    <div class="card-body">
                        {long_term_html if long_term_html else '<p class="text-muted">No long-term improvements identified.</p>'}
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_executive_summary_block(self, ciso_summary, risk_dist, kpis, all_analyses_summary):
        """Generate enhanced Executive Summary: paragraph, key metrics, and complete analysis table."""
        critical = risk_dist.get('Critical', 0)
        high = risk_dist.get('High', 0)
        medium = risk_dist.get('Medium', 0)
        low = risk_dist.get('Low', 0)
        total_risks = critical + high + medium + low
        domain_score = kpis.get('overall_score', {}).get('value', 0)

        esc_summary = html_stdlib.escape(ciso_summary) if ciso_summary else "No summary available."

        # Key metrics bar
        key_metrics_html = f"""
        <div class="d-flex flex-wrap gap-3 align-items-center mb-3" style="font-size: 0.9rem;">
            <span><strong>Domain score:</strong> <span class="badge bg-{'danger' if domain_score < 40 else 'warning' if domain_score < 70 else 'success'}">{domain_score:.1f}/100</span></span>
            <span><strong>Total risks:</strong> {total_risks}</span>
            <span><strong>Critical:</strong> <span class="badge bg-danger">{critical}</span></span>
            <span><strong>High:</strong> <span class="badge bg-warning text-dark">{high}</span></span>
            <span><strong>Medium:</strong> <span class="badge bg-info">{medium}</span></span>
            <span><strong>Low:</strong> <span class="badge bg-secondary">{low}</span></span>
        </div>
        """

        # Complete Analysis Summary table rows
        rows = []
        for item in all_analyses_summary:
            label = html_stdlib.escape(item.get('label', ''))
            count = item.get('count', 0)
            status = item.get('status', 'ok')
            if status == 'critical':
                badge = '<span class="badge bg-danger">Findings</span>'
            elif status == 'warning':
                badge = '<span class="badge bg-warning text-dark">Findings</span>'
            else:
                badge = '<span class="badge bg-success">OK</span>'
            rows.append(f"""
            <tr>
                <td>{label}</td>
                <td class="text-end"><strong>{count}</strong></td>
                <td class="text-end">{badge}</td>
            </tr>
            """)

        table_body = ''.join(rows) if rows else '<tr><td colspan="3" class="text-center text-muted">No analysis data available.</td></tr>'

        return f"""
        <div class="card mb-3" style="background: var(--header-bg); color: white; border: 1px solid var(--border-color);">
            <div class="card-body">
                <h5 class="card-title mb-3" style="font-size: 1.1rem;"><i class="fas fa-chart-line"></i> Executive Summary</h5>
                <p class="card-text mb-0" style="font-size: 0.9375rem; line-height: 1.65;">
                    {esc_summary}
                </p>
                <div class="mt-3 pt-3" style="border-top: 1px solid rgba(255,255,255,0.2);">
                    {key_metrics_html}
                </div>
            </div>
        </div>
        <div class="card mb-3">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span><i class="fas fa-list-check"></i> Complete Analysis Summary</span>
                <small class="text-muted">All {len(all_analyses_summary)} analyses</small>
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-hover table-striped mb-0">
                        <thead>
                            <tr>
                                <th>Analysis</th>
                                <th class="text-end">Count</th>
                                <th class="text-end">Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {table_body}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """

    def _generate_password_stats_html(self, password_stats):
        """Generate HTML for password statistics section."""
        if not password_stats or password_stats.get('total_users', 0) == 0:
            return ""
        
        import json
        stats = password_stats
        all_details = stats.get('details', [])
        total_count = len(all_details)
        
        # First 10 for preview
        preview_details = all_details[:10]
        
        # Build preview details HTML with pagination
        preview_details_html = ""
        if preview_details:
            preview_details_html = '<div class="table-responsive"><table class="table table-sm table-hover sortable-table" id="passwordIssuesPreviewTable"><thead><tr><th class="sortable" onclick="sortTable(\'passwordIssuesPreviewTable\', 0)">Username <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'passwordIssuesPreviewTable\', 1)">Issue <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'passwordIssuesPreviewTable\', 2)">Age (Days) <i class="fas fa-sort"></i></th></tr></thead><tbody>'
            for detail in preview_details:
                days_badge = ""
                if detail.get('days'):
                    days = detail['days']
                    if days > 365:
                        days_badge = f'<span class="badge bg-danger">{days}</span>'
                    elif days > 180:
                        days_badge = f'<span class="badge bg-warning">{days}</span>'
                    elif days > 90:
                        days_badge = f'<span class="badge bg-info">{days}</span>'
                    else:
                        days_badge = f'<span class="badge bg-secondary">{days}</span>'
                else:
                    days_badge = '<span class="badge bg-danger">N/A</span>'
                
                preview_details_html += f"""
                <tr>
                    <td><strong>{detail.get('username', 'Unknown')}</strong></td>
                    <td>{detail.get('issue', 'N/A')}</td>
                    <td>{days_badge}</td>
                </tr>
                """
            preview_details_html += '</tbody></table></div>'
            
            # Pagination controls
            total_pages = (total_count + 9) // 10  # Round up division
            pagination_html = ""
            if total_pages > 1:
                pagination_html = f"""
                <div class="d-flex justify-content-between align-items-center mt-2">
                    <div>
                        <small class="text-muted">Showing 1-{min(10, total_count)} of {total_count} issues</small>
                    </div>
                    <nav>
                        <ul class="pagination pagination-sm mb-0" id="passwordIssuesPagination">
                            <li class="page-item disabled" id="passwordIssuesPrev">
                                <a class="page-link" href="#" onclick="changePasswordIssuesPage(-1); return false;">Previous</a>
                            </li>
                            <li class="page-item active">
                                <span class="page-link" id="passwordIssuesPageInfo">Page 1 of {total_pages}</span>
                            </li>
                            <li class="page-item" id="passwordIssuesNext">
                                <a class="page-link" href="#" onclick="changePasswordIssuesPage(1); return false;">Next</a>
                            </li>
                        </ul>
                    </nav>
                </div>
                """
            
            # View all button
            view_all_button = f"""
            <div class="mt-2">
                <button class="btn btn-sm btn-primary" onclick="if(typeof window.navigateToTab !== 'undefined'){{window.navigateToTab('password-issues-tab');}}else{{console.warn('navigateToTab not loaded yet');}}" style="cursor: pointer;">
                    <i class="fas fa-list"></i> View All Password Issues ({total_count})
                </button>
            </div>
            """
        else:
            preview_details_html = '<p class="text-muted">No password issues found.</p>'
            pagination_html = ""
            view_all_button = ""
        
        # Store all details in JavaScript variable for pagination
        all_details_json = json.dumps(all_details, default=str)
        
        return f"""
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-warning text-white">
                        <i class="fas fa-key"></i> Password Security Statistics
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-3">
                                <div class="text-center p-3 border rounded">
                                    <h4 class="text-danger">{stats.get('never_changed', 0)}</h4>
                                    <small class="text-muted">Password Never Changed</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-3 border rounded">
                                    <h4 class="text-danger">{stats.get('same_as_creation', 0)}</h4>
                                    <small class="text-muted">Same Password Since Creation</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-3 border rounded">
                                    <h4 class="text-warning">{stats.get('over_365_days', 0)}</h4>
                                    <small class="text-muted">Not Changed for 365+ Days</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-3 border rounded">
                                    <h4 class="text-info">{stats.get('over_90_days', 0)}</h4>
                                    <small class="text-muted">Not Changed for 90+ Days</small>
                                </div>
                            </div>
                        </div>
                        <div class="mt-3">
                            <div class="d-flex justify-content-between align-items-center mb-3">
                                <h6 class="mb-0"><i class="fas fa-list"></i> Password Issues Details</h6>
                                <button class="btn btn-sm btn-success" onclick="exportTableToExcel('passwordIssuesPreviewTable', 'Password_Issues')">
                                    <i class="fas fa-file-excel"></i> Export to Excel
                                </button>
                            </div>
                            <div class="input-group mb-3">
                                <span class="input-group-text"><i class="fas fa-search"></i></span>
                                <input type="text" class="form-control" id="passwordIssuesPreviewSearch" placeholder="Search by username or issue..." onkeyup="filterPasswordIssuesPreview()">
                                <button class="btn btn-outline-secondary" type="button" onclick="clearPasswordIssuesPreviewSearch()">
                                    <i class="fas fa-times"></i> Clear
                                </button>
                            </div>
                            {preview_details_html}
                            {pagination_html}
                            {view_all_button}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <script>
        // Store password issues data for pagination
        window.passwordIssuesData = {all_details_json};
        window.passwordIssuesCurrentPage = 1;
        window.passwordIssuesPageSize = 10;
        
        function changePasswordIssuesPage(direction) {{
            const totalPages = Math.ceil(window.passwordIssuesData.length / window.passwordIssuesPageSize);
            const newPage = window.passwordIssuesData.currentPage + direction;
            
            if (newPage < 1 || newPage > totalPages) {{
                return;
            }}
            
            window.passwordIssuesCurrentPage = newPage;
            updatePasswordIssuesTable();
        }}
        
        function updatePasswordIssuesTable() {{
            const data = window.passwordIssuesData;
            const page = window.passwordIssuesCurrentPage;
            const pageSize = window.passwordIssuesPageSize;
            const start = (page - 1) * pageSize;
            const end = start + pageSize;
            const pageData = data.slice(start, end);
            
            const tbody = document.querySelector('#passwordIssuesPreviewTable tbody');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            pageData.forEach(detail => {{
                let daysBadge = '';
                if (detail.days !== null && detail.days !== undefined) {{
                    const days = detail.days;
                    if (days > 365) {{
                        daysBadge = `<span class="badge bg-danger">${{days}}</span>`;
                    }} else if (days > 180) {{
                        daysBadge = `<span class="badge bg-warning">${{days}}</span>`;
                    }} else if (days > 90) {{
                        daysBadge = `<span class="badge bg-info">${{days}}</span>`;
                    }} else {{
                        daysBadge = `<span class="badge bg-secondary">${{days}}</span>`;
                    }}
                }} else {{
                    daysBadge = '<span class="badge bg-danger">N/A</span>';
                }}
                
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td><strong>${{detail.username || 'Unknown'}}</strong></td>
                    <td>${{detail.issue || 'N/A'}}</td>
                    <td>${{daysBadge}}</td>
                `;
                tbody.appendChild(row);
            }});
            
            // Update pagination controls
            const totalPages = Math.ceil(data.length / pageSize);
            const prevBtn = document.getElementById('passwordIssuesPrev');
            const nextBtn = document.getElementById('passwordIssuesNext');
            const pageInfo = document.getElementById('passwordIssuesPageInfo');
            
            if (prevBtn) {{
                prevBtn.classList.toggle('disabled', page === 1);
            }}
            if (nextBtn) {{
                nextBtn.classList.toggle('disabled', page === totalPages);
            }}
            if (pageInfo) {{
                pageInfo.textContent = `Page ${{page}} of ${{totalPages}}`;
            }}
            
            // Update showing info
            const showingInfo = document.querySelector('.d-flex.justify-content-between.align-items-center.mt-2 small');
            if (showingInfo) {{
                showingInfo.textContent = `Showing ${{start + 1}}-${{Math.min(end, data.length)}} of ${{data.length}} issues`;
            }}
        }}
        </script>
        """

    def _generate_account_activity_html(self, account_activity_stats):
        """Generate HTML for account activity statistics."""
        if not account_activity_stats:
            return ""
        
        import json
        recently_created = account_activity_stats.get('recently_created', {})
        recently_group_changed = account_activity_stats.get('recently_group_changed', {})
        
        # Recently created accounts table
        created_details = recently_created.get('details', [])
        created_details_json = json.dumps(created_details, default=str)
        created_details_html = ""
        created_pagination_html = ""
        created_total = len(created_details)
        created_page_size = 10
        
        if created_details:
            # First page
            preview_created = created_details[:created_page_size]
            created_details_html = '<div class="table-responsive"><table class="table table-sm table-hover sortable-table" id="recentlyCreatedTable"><thead><tr><th class="sortable" onclick="sortTable(\'recentlyCreatedTable\', 0)">Username <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'recentlyCreatedTable\', 1)">Account Age (Days) <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'recentlyCreatedTable\', 2)">Period <i class="fas fa-sort"></i></th></thead><tbody>'
            for detail in preview_created:
                created_details_html += f"""
                <tr>
                    <td><strong>{detail.get('username', 'Unknown')}</strong></td>
                    <td><span class="badge bg-info">{detail.get('days_ago', 0)}</span></td>
                    <td><span class="badge bg-warning">{detail.get('period', 'N/A')}</span></td>
                </tr>
                """
            created_details_html += '</tbody></table></div>'
            
            # Pagination
            if created_total > created_page_size:
                total_pages = (created_total + created_page_size - 1) // created_page_size
                created_pagination_html = f"""
                <div class="d-flex justify-content-between align-items-center mt-2">
                    <div>
                        <small class="text-muted">Showing 1-{min(created_page_size, created_total)} of {created_total} accounts</small>
                    </div>
                    <nav>
                        <ul class="pagination pagination-sm mb-0" id="recentlyCreatedPagination">
                            <li class="page-item disabled" id="recentlyCreatedPrev">
                                <a class="page-link" href="#" onclick="changePage('recentlyCreated', -1); return false;">Previous</a>
                            </li>
                            <li class="page-item active">
                                <span class="page-link" id="recentlyCreatedPageInfo">Page 1 of {total_pages}</span>
                            </li>
                            <li class="page-item" id="recentlyCreatedNext">
                                <a class="page-link" href="#" onclick="changePage('recentlyCreated', 1); return false;">Next</a>
                            </li>
                        </ul>
                    </nav>
                </div>
                """
        else:
            created_details_html = '<p class="text-muted">No recently created accounts found.</p>'
        
        # Recently group changed accounts table
        group_changed_details = recently_group_changed.get('details', [])
        group_changed_details_json = json.dumps(group_changed_details, default=str)
        group_changed_details_html = ""
        group_changed_pagination_html = ""
        group_changed_total = len(group_changed_details)
        group_changed_page_size = 10
        
        if group_changed_details:
            # First page
            preview_group_changed = group_changed_details[:group_changed_page_size]
            group_changed_details_html = '<div class="table-responsive"><table class="table table-sm table-hover sortable-table" id="recentlyGroupChangedTable"><thead><tr><th class="sortable" onclick="sortTable(\'recentlyGroupChangedTable\', 0)">Username <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'recentlyGroupChangedTable\', 1)">Period <i class="fas fa-sort"></i></th></thead><tbody>'
            for detail in preview_group_changed:
                group_changed_details_html += f"""
                <tr>
                    <td><strong>{detail.get('username', 'Unknown')}</strong></td>
                    <td><span class="badge bg-warning">{detail.get('period', 'N/A')}</span></td>
                </tr>
                """
            group_changed_details_html += '</tbody></table></div>'
            
            # Pagination
            if group_changed_total > group_changed_page_size:
                total_pages = (group_changed_total + group_changed_page_size - 1) // group_changed_page_size
                group_changed_pagination_html = f"""
                <div class="d-flex justify-content-between align-items-center mt-2">
                    <div>
                        <small class="text-muted">Showing 1-{min(group_changed_page_size, group_changed_total)} of {group_changed_total} accounts</small>
                    </div>
                    <nav>
                        <ul class="pagination pagination-sm mb-0" id="recentlyGroupChangedPagination">
                            <li class="page-item disabled" id="recentlyGroupChangedPrev">
                                <a class="page-link" href="#" onclick="changePage('recentlyGroupChanged', -1); return false;">Previous</a>
                            </li>
                            <li class="page-item active">
                                <span class="page-link" id="recentlyGroupChangedPageInfo">Page 1 of {total_pages}</span>
                            </li>
                            <li class="page-item" id="recentlyGroupChangedNext">
                                <a class="page-link" href="#" onclick="changePage('recentlyGroupChanged', 1); return false;">Next</a>
                            </li>
                        </ul>
                    </nav>
                </div>
                """
        else:
            group_changed_details_html = '<p class="text-muted">No recently modified group memberships found.</p>'
        
        return f"""
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
                        <span><i class="fas fa-calendar-plus"></i> Recently Created Accounts</span>
                        <button class="btn btn-sm btn-light" onclick="exportTableToExcel('recentlyCreatedTable', 'Recently_Created_Accounts')">
                            <i class="fas fa-file-excel"></i> Export
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-3">
                                <div class="text-center p-2 border rounded">
                                    <h5 class="text-warning">{recently_created.get('last_10_days', 0)}</h5>
                                    <small class="text-muted">Last 10 Days</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-2 border rounded">
                                    <h5 class="text-info">{recently_created.get('last_30_days', 0)}</h5>
                                    <small class="text-muted">Last 30 Days</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-2 border rounded">
                                    <h5 class="text-info">{recently_created.get('last_60_days', 0)}</h5>
                                    <small class="text-muted">Last 60 Days</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-2 border rounded">
                                    <h5 class="text-info">{recently_created.get('last_90_days', 0)}</h5>
                                    <small class="text-muted">Last 90 Days</small>
                                </div>
                            </div>
                        </div>
                        {created_details_html}
                        {created_pagination_html}
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-warning text-dark d-flex justify-content-between align-items-center">
                        <span><i class="fas fa-exchange-alt"></i> Recently Modified Group Memberships</span>
                        <button class="btn btn-sm btn-dark" onclick="exportTableToExcel('recentlyGroupChangedTable', 'Recently_Modified_Group_Memberships')">
                            <i class="fas fa-file-excel"></i> Export
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-3">
                                <div class="text-center p-2 border rounded">
                                    <h5 class="text-warning">{recently_group_changed.get('last_10_days', 0)}</h5>
                                    <small class="text-muted">Last 10 Days</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-2 border rounded">
                                    <h5 class="text-info">{recently_group_changed.get('last_30_days', 0)}</h5>
                                    <small class="text-muted">Last 30 Days</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-2 border rounded">
                                    <h5 class="text-info">{recently_group_changed.get('last_60_days', 0)}</h5>
                                    <small class="text-muted">Last 60 Days</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-2 border rounded">
                                    <h5 class="text-info">{recently_group_changed.get('last_90_days', 0)}</h5>
                                    <small class="text-muted">Last 90 Days</small>
                                </div>
                            </div>
                        </div>
                        {group_changed_details_html}
                        {group_changed_pagination_html}
                    </div>
                </div>
            </div>
        </div>
        <script>
        // Store data for pagination
        window.recentlyCreatedData = {created_details_json};
        window.recentlyCreatedCurrentPage = 1;
        window.recentlyCreatedPageSize = {created_page_size};
        
        window.recentlyGroupChangedData = {group_changed_details_json};
        window.recentlyGroupChangedCurrentPage = 1;
        window.recentlyGroupChangedPageSize = {group_changed_page_size};
        
        function changePage(tableType, direction) {{
            let data, currentPage, pageSize, tableId, prevId, nextId, pageInfoId, paginationId;
            
            if (tableType === 'recentlyCreated') {{
                data = window.recentlyCreatedData;
                currentPage = window.recentlyCreatedCurrentPage;
                pageSize = window.recentlyCreatedPageSize;
                tableId = 'recentlyCreatedTable';
                prevId = 'recentlyCreatedPrev';
                nextId = 'recentlyCreatedNext';
                pageInfoId = 'recentlyCreatedPageInfo';
            }} else if (tableType === 'recentlyGroupChanged') {{
                data = window.recentlyGroupChangedData;
                currentPage = window.recentlyGroupChangedCurrentPage;
                pageSize = window.recentlyGroupChangedPageSize;
                tableId = 'recentlyGroupChangedTable';
                prevId = 'recentlyGroupChangedPrev';
                nextId = 'recentlyGroupChangedNext';
                pageInfoId = 'recentlyGroupChangedPageInfo';
            }} else {{
                return;
            }}
            
            const totalPages = Math.ceil(data.length / pageSize);
            const newPage = currentPage + direction;
            
            if (newPage < 1 || newPage > totalPages) {{
                return;
            }}
            
            if (tableType === 'recentlyCreated') {{
                window.recentlyCreatedCurrentPage = newPage;
            }} else {{
                window.recentlyGroupChangedCurrentPage = newPage;
            }}
            
            updateTablePage(tableType, tableId, prevId, nextId, pageInfoId, data, newPage, pageSize);
        }}
        
        function updateTablePage(tableType, tableId, prevId, nextId, pageInfoId, data, page, pageSize) {{
            const start = (page - 1) * pageSize;
            const end = start + pageSize;
            const pageData = data.slice(start, end);
            
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const tbody = table.querySelector('tbody');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            pageData.forEach(detail => {{
                const row = document.createElement('tr');
                if (tableType === 'recentlyCreated') {{
                    row.innerHTML = `
                        <td><strong>${{detail.username || 'Unknown'}}</strong></td>
                        <td><span class="badge bg-info">${{detail.days_ago || 0}}</span></td>
                        <td><span class="badge bg-warning">${{detail.period || 'N/A'}}</span></td>
                    `;
                }} else if (tableType === 'recentlyGroupChanged') {{
                    row.innerHTML = `
                        <td><strong>${{detail.username || 'Unknown'}}</strong></td>
                        <td><span class="badge bg-warning">${{detail.period || 'N/A'}}</span></td>
                    `;
                }}
                tbody.appendChild(row);
            }});
            
            // Update pagination controls
            const totalPages = Math.ceil(data.length / pageSize);
            const prevBtn = document.getElementById(prevId);
            const nextBtn = document.getElementById(nextId);
            const pageInfo = document.getElementById(pageInfoId);
            
            if (prevBtn) {{
                prevBtn.classList.toggle('disabled', page === 1);
            }}
            if (nextBtn) {{
                nextBtn.classList.toggle('disabled', page === totalPages);
            }}
            if (pageInfo) {{
                pageInfo.textContent = `Page ${{page}} of ${{totalPages}}`;
            }}
            
            // Update showing info
            const showingInfo = document.querySelector(`#${{tableId.replace('Table', 'Pagination')}}`).parentElement.previousElementSibling;
            if (showingInfo) {{
                showingInfo.querySelector('small').textContent = `Showing ${{start + 1}}-${{Math.min(end, data.length)}} of ${{data.length}} accounts`;
            }}
        }}
        </script>
        """

    def _generate_admin_group_html(self, admin_group_stats):
        """Generate HTML for admin group membership statistics."""
        if not admin_group_stats:
            return ""
        
        import json
        domain_admins = admin_group_stats.get('domain_admins', {})
        enterprise_admins = admin_group_stats.get('enterprise_admins', {})
        schema_admins = admin_group_stats.get('schema_admins', {})
        
        # Domain Admins table
        da_members = domain_admins.get('members', [])
        da_members_json = json.dumps(da_members, default=str)
        da_members_html = ""
        da_pagination_html = ""
        da_total = len(da_members)
        da_page_size = 10
        
        if da_members:
            preview_da = da_members[:da_page_size]
            da_members_html = '<div class="table-responsive"><table class="table table-sm table-hover sortable-table" id="domainAdminTable" style="font-size: 0.85rem;"><thead><tr><th class="sortable" onclick="sortTable(\'domainAdminTable\', 0)">Username <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'domainAdminTable\', 1)">Groups <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'domainAdminTable\', 2)">Account Created <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'domainAdminTable\', 3)">Group Added <i class="fas fa-sort"></i></th></thead><tbody>'
            for member in preview_da:
                groups_str = ', '.join(member.get('groups', []))
                account_created = member.get('accountCreated', 'N/A')
                group_added = member.get('groupAdded', 'N/A')
                da_members_html += f"""
                <tr>
                    <td><strong>{member.get('username', 'Unknown')}</strong></td>
                    <td><span class="badge bg-danger">{groups_str}</span></td>
                    <td><small class="text-muted">{account_created}</small></td>
                    <td><small class="text-muted">{group_added}</small></td>
                </tr>
                """
            da_members_html += '</tbody></table></div>'
            
            if da_total > da_page_size:
                total_pages = (da_total + da_page_size - 1) // da_page_size
                da_pagination_html = f"""
                <div class="d-flex justify-content-between align-items-center mt-2">
                    <div>
                        <small class="text-muted">Showing 1-{min(da_page_size, da_total)} of {da_total} members</small>
                    </div>
                    <nav>
                        <ul class="pagination pagination-sm mb-0" id="domainAdminPagination">
                            <li class="page-item disabled" id="domainAdminPrev">
                                <a class="page-link" href="#" onclick="changePage('domainAdmin', -1); return false;">Previous</a>
                            </li>
                            <li class="page-item active">
                                <span class="page-link" id="domainAdminPageInfo">Page 1 of {total_pages}</span>
                            </li>
                            <li class="page-item" id="domainAdminNext">
                                <a class="page-link" href="#" onclick="changePage('domainAdmin', 1); return false;">Next</a>
                            </li>
                        </ul>
                    </nav>
                </div>
                """
        else:
            da_members_html = '<p class="text-muted">No Domain Admin members found.</p>'
        
        # Enterprise Admins table
        ea_members = enterprise_admins.get('members', [])
        ea_members_json = json.dumps(ea_members, default=str)
        ea_members_html = ""
        ea_pagination_html = ""
        ea_total = len(ea_members)
        ea_page_size = 10
        
        if ea_members:
            preview_ea = ea_members[:ea_page_size]
            ea_members_html = '<div class="table-responsive"><table class="table table-sm table-hover sortable-table" id="enterpriseAdminTable" style="font-size: 0.85rem;"><thead><tr><th class="sortable" onclick="sortTable(\'enterpriseAdminTable\', 0)">Username <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'enterpriseAdminTable\', 1)">Groups <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'enterpriseAdminTable\', 2)">Account Created <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'enterpriseAdminTable\', 3)">Group Added <i class="fas fa-sort"></i></th></thead><tbody>'
            for member in preview_ea:
                groups_str = ', '.join(member.get('groups', []))
                account_created = member.get('accountCreated', 'N/A')
                group_added = member.get('groupAdded', 'N/A')
                ea_members_html += f"""
                <tr>
                    <td><strong>{member.get('username', 'Unknown')}</strong></td>
                    <td><span class="badge bg-danger">{groups_str}</span></td>
                    <td><small class="text-muted">{account_created}</small></td>
                    <td><small class="text-muted">{group_added}</small></td>
                </tr>
                """
            ea_members_html += '</tbody></table></div>'
            
            if ea_total > ea_page_size:
                total_pages = (ea_total + ea_page_size - 1) // ea_page_size
                ea_pagination_html = f"""
                <div class="d-flex justify-content-between align-items-center mt-2">
                    <div>
                        <small class="text-muted">Showing 1-{min(ea_page_size, ea_total)} of {ea_total} members</small>
                    </div>
                    <nav>
                        <ul class="pagination pagination-sm mb-0" id="enterpriseAdminPagination">
                            <li class="page-item disabled" id="enterpriseAdminPrev">
                                <a class="page-link" href="#" onclick="changePage('enterpriseAdmin', -1); return false;">Previous</a>
                            </li>
                            <li class="page-item active">
                                <span class="page-link" id="enterpriseAdminPageInfo">Page 1 of {total_pages}</span>
                            </li>
                            <li class="page-item" id="enterpriseAdminNext">
                                <a class="page-link" href="#" onclick="changePage('enterpriseAdmin', 1); return false;">Next</a>
                            </li>
                        </ul>
                    </nav>
                </div>
                """
        else:
            ea_members_html = '<p class="text-muted">No Enterprise Admin members found.</p>'
        
        # Schema Admins table
        sa_members = schema_admins.get('members', [])
        sa_members_json = json.dumps(sa_members, default=str)
        sa_members_html = ""
        sa_pagination_html = ""
        sa_total = len(sa_members)
        sa_page_size = 10
        
        if sa_members:
            preview_sa = sa_members[:sa_page_size]
            sa_members_html = '<div class="table-responsive"><table class="table table-sm table-hover sortable-table" id="schemaAdminTable" style="font-size: 0.85rem;"><thead><tr><th class="sortable" onclick="sortTable(\'schemaAdminTable\', 0)">Username <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'schemaAdminTable\', 1)">Groups <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'schemaAdminTable\', 2)">Account Created <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'schemaAdminTable\', 3)">Group Added <i class="fas fa-sort"></i></th></thead><tbody>'
            for member in preview_sa:
                groups_str = ', '.join(member.get('groups', []))
                account_created = member.get('accountCreated', 'N/A')
                group_added = member.get('groupAdded', 'N/A')
                sa_members_html += f"""
                <tr>
                    <td><strong>{member.get('username', 'Unknown')}</strong></td>
                    <td><span class="badge bg-danger">{groups_str}</span></td>
                    <td><small class="text-muted">{account_created}</small></td>
                    <td><small class="text-muted">{group_added}</small></td>
                </tr>
                """
            sa_members_html += '</tbody></table></div>'
            
            if sa_total > sa_page_size:
                total_pages = (sa_total + sa_page_size - 1) // sa_page_size
                sa_pagination_html = f"""
                <div class="d-flex justify-content-between align-items-center mt-2">
                    <div>
                        <small class="text-muted">Showing 1-{min(sa_page_size, sa_total)} of {sa_total} members</small>
                    </div>
                    <nav>
                        <ul class="pagination pagination-sm mb-0" id="schemaAdminPagination">
                            <li class="page-item disabled" id="schemaAdminPrev">
                                <a class="page-link" href="#" onclick="changePage('schemaAdmin', -1); return false;">Previous</a>
                            </li>
                            <li class="page-item active">
                                <span class="page-link" id="schemaAdminPageInfo">Page 1 of {total_pages}</span>
                            </li>
                            <li class="page-item" id="schemaAdminNext">
                                <a class="page-link" href="#" onclick="changePage('schemaAdmin', 1); return false;">Next</a>
                            </li>
                        </ul>
                    </nav>
                </div>
                """
        else:
            sa_members_html = '<p class="text-muted">No Schema Admin members found.</p>'
        
        return f"""
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <i class="fas fa-shield-alt"></i> Admin Group Memberships
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-4">
                                <div class="text-center p-3 border rounded report-stat-box">
                                    <h4 class="text-danger">{domain_admins.get('count', 0)}</h4>
                                    <small class="text-muted">Domain Admins</small>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="text-center p-3 border rounded report-stat-box">
                                    <h4 class="text-danger">{enterprise_admins.get('count', 0)}</h4>
                                    <small class="text-muted">Enterprise Admins</small>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="text-center p-3 border rounded report-stat-box">
                                    <h4 class="text-danger">{schema_admins.get('count', 0)}</h4>
                                    <small class="text-muted">Schema Admins</small>
                                </div>
                            </div>
                        </div>
                        <div class="alert alert-info mb-3">
                            <i class="fas fa-info-circle"></i> <strong>Note:</strong> "Group Added" time is approximate (based on account's last modification time).
                        </div>
                        <div class="row">
                            <div class="col-md-12 mb-3">
                                <div class="d-flex justify-content-between align-items-center mb-2">
                                    <h6 class="mb-0"><i class="fas fa-users-cog"></i> Domain Admin Members</h6>
                                    <button class="btn btn-sm btn-success" onclick="exportTableToExcel('domainAdminTable', 'Domain_Admin_Members')">
                                        <i class="fas fa-file-excel"></i> Export
                                    </button>
                                </div>
                                {da_members_html}
                                {da_pagination_html}
                            </div>
                            <div class="col-md-12 mb-3">
                                <div class="d-flex justify-content-between align-items-center mb-2">
                                    <h6 class="mb-0"><i class="fas fa-users-cog"></i> Enterprise Admin Members</h6>
                                    <button class="btn btn-sm btn-success" onclick="exportTableToExcel('enterpriseAdminTable', 'Enterprise_Admin_Members')">
                                        <i class="fas fa-file-excel"></i> Export
                                    </button>
                                </div>
                                {ea_members_html}
                                {ea_pagination_html}
                            </div>
                            <div class="col-md-12">
                                <div class="d-flex justify-content-between align-items-center mb-2">
                                    <h6 class="mb-0"><i class="fas fa-users-cog"></i> Schema Admin Members</h6>
                                    <button class="btn btn-sm btn-success" onclick="exportTableToExcel('schemaAdminTable', 'Schema_Admin_Members')">
                                        <i class="fas fa-file-excel"></i> Export
                                    </button>
                                </div>
                                {sa_members_html}
                                {sa_pagination_html}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <script>
        // Store admin group data for pagination
        window.domainAdminData = {da_members_json};
        window.domainAdminCurrentPage = 1;
        window.domainAdminPageSize = {da_page_size};
        
        window.enterpriseAdminData = {ea_members_json};
        window.enterpriseAdminCurrentPage = 1;
        window.enterpriseAdminPageSize = {ea_page_size};
        
        window.schemaAdminData = {sa_members_json};
        window.schemaAdminCurrentPage = 1;
        window.schemaAdminPageSize = {sa_page_size};
        
        // Extend changePage function for admin groups
        const originalChangePage = window.changePage;
        window.changePage = function(tableType, direction) {{
            if (tableType === 'domainAdmin' || tableType === 'enterpriseAdmin' || tableType === 'schemaAdmin') {{
                let data, currentPage, pageSize, tableId, prevId, nextId, pageInfoId;
                
                if (tableType === 'domainAdmin') {{
                    data = window.domainAdminData;
                    currentPage = window.domainAdminCurrentPage;
                    pageSize = window.domainAdminPageSize;
                    tableId = 'domainAdminTable';
                    prevId = 'domainAdminPrev';
                    nextId = 'domainAdminNext';
                    pageInfoId = 'domainAdminPageInfo';
                }} else if (tableType === 'enterpriseAdmin') {{
                    data = window.enterpriseAdminData;
                    currentPage = window.enterpriseAdminCurrentPage;
                    pageSize = window.enterpriseAdminPageSize;
                    tableId = 'enterpriseAdminTable';
                    prevId = 'enterpriseAdminPrev';
                    nextId = 'enterpriseAdminNext';
                    pageInfoId = 'enterpriseAdminPageInfo';
                }} else if (tableType === 'schemaAdmin') {{
                    data = window.schemaAdminData;
                    currentPage = window.schemaAdminCurrentPage;
                    pageSize = window.schemaAdminPageSize;
                    tableId = 'schemaAdminTable';
                    prevId = 'schemaAdminPrev';
                    nextId = 'schemaAdminNext';
                    pageInfoId = 'schemaAdminPageInfo';
                }}
                
                const totalPages = Math.ceil(data.length / pageSize);
                const newPage = currentPage + direction;
                
                if (newPage < 1 || newPage > totalPages) {{
                    return;
                }}
                
                if (tableType === 'domainAdmin') {{
                    window.domainAdminCurrentPage = newPage;
                }} else if (tableType === 'enterpriseAdmin') {{
                    window.enterpriseAdminCurrentPage = newPage;
                }} else if (tableType === 'schemaAdmin') {{
                    window.schemaAdminCurrentPage = newPage;
                }}
                
                updateAdminTablePage(tableType, tableId, prevId, nextId, pageInfoId, data, newPage, pageSize);
            }} else {{
                if (originalChangePage) {{
                    originalChangePage(tableType, direction);
                }}
            }}
        }};
        
        function updateAdminTablePage(tableType, tableId, prevId, nextId, pageInfoId, data, page, pageSize) {{
            const start = (page - 1) * pageSize;
            const end = start + pageSize;
            const pageData = data.slice(start, end);
            
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const tbody = table.querySelector('tbody');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            pageData.forEach(member => {{
                const row = document.createElement('tr');
                const groups_str = (member.groups || []).join(', ');
                row.innerHTML = `
                    <td><strong>${{member.username || 'Unknown'}}</strong></td>
                    <td><span class="badge bg-danger">${{groups_str}}</span></td>
                    <td><small class="text-muted">${{member.accountCreated || 'N/A'}}</small></td>
                    <td><small class="text-muted">${{member.groupAdded || 'N/A'}}</small></td>
                `;
                tbody.appendChild(row);
            }});
            
            // Update pagination controls
            const totalPages = Math.ceil(data.length / pageSize);
            const prevBtn = document.getElementById(prevId);
            const nextBtn = document.getElementById(nextId);
            const pageInfo = document.getElementById(pageInfoId);
            
            if (prevBtn) {{
                prevBtn.classList.toggle('disabled', page === 1);
            }}
            if (nextBtn) {{
                nextBtn.classList.toggle('disabled', page === totalPages);
            }}
            if (pageInfo) {{
                pageInfo.textContent = `Page ${{page}} of ${{totalPages}}`;
            }}
            
            // Update showing info
            const pagination = document.getElementById(tableId.replace('Table', 'Pagination'));
            if (pagination) {{
                const showingInfo = pagination.parentElement.previousElementSibling;
                if (showingInfo) {{
                    showingInfo.querySelector('small').textContent = `Showing ${{start + 1}}-${{Math.min(end, data.length)}} of ${{data.length}} members`;
                }}
            }}
        }}
        </script>
        """

    def _generate_account_status_html(self, account_status_stats):
        """Generate HTML for account status statistics (disabled, locked)."""
        if not account_status_stats:
            return ""
        
        import json
        disabled = account_status_stats.get('disabled', {})
        locked = account_status_stats.get('locked', {})
        disabled_and_locked = account_status_stats.get('disabled_and_locked', {})
        
        # Disabled accounts table
        disabled_accounts = disabled.get('accounts', [])
        disabled_accounts_json = json.dumps(disabled_accounts, default=str)
        disabled_html = ""
        disabled_pagination_html = ""
        disabled_total = len(disabled_accounts)
        disabled_page_size = 10
        
        if disabled_accounts:
            preview_disabled = disabled_accounts[:disabled_page_size]
            disabled_html = '<div class="table-responsive"><table class="table table-sm table-hover sortable-table" id="disabledAccountsTable"><thead><tr><th class="sortable" onclick="sortTable(\'disabledAccountsTable\', 0)">Username <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'disabledAccountsTable\', 1)">Display Name <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'disabledAccountsTable\', 2)">Disabled Time <i class="fas fa-sort"></i></th></thead><tbody>'
            for account in preview_disabled:
                disabled_time = account.get('disabledTime', 'N/A')
                disabled_html += f"""
                <tr>
                    <td><strong>{account.get('username', 'Unknown')}</strong></td>
                    <td>{account.get('displayName', 'N/A')}</td>
                    <td><small class="text-muted">{disabled_time}</small></td>
                </tr>
                """
            disabled_html += '</tbody></table></div>'
            
            if disabled_total > disabled_page_size:
                total_pages = (disabled_total + disabled_page_size - 1) // disabled_page_size
                disabled_pagination_html = f"""
                <div class="d-flex justify-content-between align-items-center mt-2">
                    <div>
                        <small class="text-muted">Showing 1-{min(disabled_page_size, disabled_total)} of {disabled_total} accounts</small>
                    </div>
                    <nav>
                        <ul class="pagination pagination-sm mb-0" id="disabledAccountsPagination">
                            <li class="page-item disabled" id="disabledAccountsPrev">
                                <a class="page-link" href="#" onclick="changePage('disabledAccounts', -1); return false;">Previous</a>
                            </li>
                            <li class="page-item active">
                                <span class="page-link" id="disabledAccountsPageInfo">Page 1 of {total_pages}</span>
                            </li>
                            <li class="page-item" id="disabledAccountsNext">
                                <a class="page-link" href="#" onclick="changePage('disabledAccounts', 1); return false;">Next</a>
                            </li>
                        </ul>
                    </nav>
                </div>
                """
        else:
            disabled_html = '<p class="text-muted">No disabled accounts found.</p>'
        
        # Locked accounts table
        locked_accounts = locked.get('accounts', [])
        locked_accounts_json = json.dumps(locked_accounts, default=str)
        locked_html = ""
        locked_pagination_html = ""
        locked_total = len(locked_accounts)
        locked_page_size = 10
        
        if locked_accounts:
            preview_locked = locked_accounts[:locked_page_size]
            locked_html = '<div class="table-responsive"><table class="table table-sm table-hover sortable-table" id="lockedAccountsTable"><thead><tr><th class="sortable" onclick="sortTable(\'lockedAccountsTable\', 0)">Username <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'lockedAccountsTable\', 1)">Display Name <i class="fas fa-sort"></i></th><th class="sortable" onclick="sortTable(\'lockedAccountsTable\', 2)">Locked Time <i class="fas fa-sort"></i></th></thead><tbody>'
            for account in preview_locked:
                locked_time = account.get('lockedTime', 'N/A')
                locked_html += f"""
                <tr>
                    <td><strong>{account.get('username', 'Unknown')}</strong></td>
                    <td>{account.get('displayName', 'N/A')}</td>
                    <td><small class="text-muted">{locked_time}</small></td>
                </tr>
                """
            locked_html += '</tbody></table></div>'
            
            if locked_total > locked_page_size:
                total_pages = (locked_total + locked_page_size - 1) // locked_page_size
                locked_pagination_html = f"""
                <div class="d-flex justify-content-between align-items-center mt-2">
                    <div>
                        <small class="text-muted">Showing 1-{min(locked_page_size, locked_total)} of {locked_total} accounts</small>
                    </div>
                    <nav>
                        <ul class="pagination pagination-sm mb-0" id="lockedAccountsPagination">
                            <li class="page-item disabled" id="lockedAccountsPrev">
                                <a class="page-link" href="#" onclick="changePage('lockedAccounts', -1); return false;">Previous</a>
                            </li>
                            <li class="page-item active">
                                <span class="page-link" id="lockedAccountsPageInfo">Page 1 of {total_pages}</span>
                            </li>
                            <li class="page-item" id="lockedAccountsNext">
                                <a class="page-link" href="#" onclick="changePage('lockedAccounts', 1); return false;">Next</a>
                            </li>
                        </ul>
                    </nav>
                </div>
                """
        else:
            locked_html = '<p class="text-muted">No locked accounts found.</p>'
        
        return f"""
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-secondary text-white d-flex justify-content-between align-items-center">
                        <span><i class="fas fa-user-slash"></i> Disabled Accounts</span>
                        <button class="btn btn-sm btn-light" onclick="exportTableToExcel('disabledAccountsTable', 'Disabled_Accounts')">
                            <i class="fas fa-file-excel"></i> Export
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="text-center mb-3">
                            <h3 class="text-secondary">{disabled.get('count', 0)}</h3>
                            <small class="text-muted">Total Disabled Accounts</small>
                        </div>
                        {disabled_html}
                        {disabled_pagination_html}
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-danger text-white d-flex justify-content-between align-items-center">
                        <span><i class="fas fa-lock"></i> Locked Accounts</span>
                        <button class="btn btn-sm btn-light" onclick="exportTableToExcel('lockedAccountsTable', 'Locked_Accounts')">
                            <i class="fas fa-file-excel"></i> Export
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="text-center mb-3">
                            <h3 class="text-danger">{locked.get('count', 0)}</h3>
                            <small class="text-muted">Total Locked Accounts</small>
                        </div>
                        {locked_html}
                        {locked_pagination_html}
                        {f'<div class="alert alert-warning mt-3"><i class="fas fa-exclamation-triangle"></i> {disabled_and_locked.get("count", 0)} account(s) are both disabled and locked.</div>' if disabled_and_locked.get('count', 0) > 0 else ''}
                    </div>
                </div>
            </div>
        </div>
        <script>
        // Store account status data for pagination
        window.disabledAccountsData = {disabled_accounts_json};
        window.disabledAccountsCurrentPage = 1;
        window.disabledAccountsPageSize = {disabled_page_size};
        
        window.lockedAccountsData = {locked_accounts_json};
        window.lockedAccountsCurrentPage = 1;
        window.lockedAccountsPageSize = {locked_page_size};
        
        // Extend changePage function for account status
        const originalChangePage2 = window.changePage;
        window.changePage = function(tableType, direction) {{
            if (tableType === 'disabledAccounts' || tableType === 'lockedAccounts') {{
                let data, currentPage, pageSize, tableId, prevId, nextId, pageInfoId;
                
                if (tableType === 'disabledAccounts') {{
                    data = window.disabledAccountsData;
                    currentPage = window.disabledAccountsCurrentPage;
                    pageSize = window.disabledAccountsPageSize;
                    tableId = 'disabledAccountsTable';
                    prevId = 'disabledAccountsPrev';
                    nextId = 'disabledAccountsNext';
                    pageInfoId = 'disabledAccountsPageInfo';
                }} else if (tableType === 'lockedAccounts') {{
                    data = window.lockedAccountsData;
                    currentPage = window.lockedAccountsCurrentPage;
                    pageSize = window.lockedAccountsPageSize;
                    tableId = 'lockedAccountsTable';
                    prevId = 'lockedAccountsPrev';
                    nextId = 'lockedAccountsNext';
                    pageInfoId = 'lockedAccountsPageInfo';
                }}
                
                const totalPages = Math.ceil(data.length / pageSize);
                const newPage = currentPage + direction;
                
                if (newPage < 1 || newPage > totalPages) {{
                    return;
                }}
                
                if (tableType === 'disabledAccounts') {{
                    window.disabledAccountsCurrentPage = newPage;
                }} else if (tableType === 'lockedAccounts') {{
                    window.lockedAccountsCurrentPage = newPage;
                }}
                
                updateAccountStatusTablePage(tableType, tableId, prevId, nextId, pageInfoId, data, newPage, pageSize);
            }} else {{
                if (originalChangePage2) {{
                    originalChangePage2(tableType, direction);
                }}
            }}
        }};
        
        function updateAccountStatusTablePage(tableType, tableId, prevId, nextId, pageInfoId, data, page, pageSize) {{
            const start = (page - 1) * pageSize;
            const end = start + pageSize;
            const pageData = data.slice(start, end);
            
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const tbody = table.querySelector('tbody');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            pageData.forEach(account => {{
                const row = document.createElement('tr');
                if (tableType === 'disabledAccounts') {{
                    row.innerHTML = `
                        <td><strong>${{account.username || 'Unknown'}}</strong></td>
                        <td>${{account.displayName || 'N/A'}}</td>
                        <td><small class="text-muted">${{account.disabledTime || 'N/A'}}</small></td>
                    `;
                }} else if (tableType === 'lockedAccounts') {{
                    row.innerHTML = `
                        <td><strong>${{account.username || 'Unknown'}}</strong></td>
                        <td>${{account.displayName || 'N/A'}}</td>
                        <td><small class="text-muted">${{account.lockedTime || 'N/A'}}</small></td>
                    `;
                }}
                tbody.appendChild(row);
            }});
            
            // Update pagination controls
            const totalPages = Math.ceil(data.length / pageSize);
            const prevBtn = document.getElementById(prevId);
            const nextBtn = document.getElementById(nextId);
            const pageInfo = document.getElementById(pageInfoId);
            
            if (prevBtn) {{
                prevBtn.classList.toggle('disabled', page === 1);
            }}
            if (nextBtn) {{
                nextBtn.classList.toggle('disabled', page === totalPages);
            }}
            if (pageInfo) {{
                pageInfo.textContent = `Page ${{page}} of ${{totalPages}}`;
            }}
            
            // Update showing info
            const pagination = document.getElementById(tableId.replace('Table', 'Pagination'));
            if (pagination) {{
                const showingInfo = pagination.parentElement.previousElementSibling;
                if (showingInfo) {{
                    showingInfo.querySelector('small').textContent = `Showing ${{start + 1}}-${{Math.min(end, data.length)}} of ${{data.length}} accounts`;
                }}
            }}
        }}
        </script>
        """
