"""
HTML Report Generator Module
Generates interactive HTML reports using Bootstrap and Chart.js

This module is the main entry point. All section-specific HTML generation
is delegated to mixin classes in the report_sections/ package.
"""

import html as html_stdlib
import json
import logging
import os
import shutil
from datetime import datetime

from core.constants import DEVELOPER_INFO
from reporting.ciso_dashboard import CISODashboardGenerator
from reporting.saas_report_template import build_saas_report

from reporting.report_sections.risk_sections import RiskSectionsMixin
from reporting.report_sections.purple_team import PurpleTeamMixin
from reporting.report_sections.dashboard_section import DashboardSectionMixin
from reporting.report_sections.directory_section import DirectorySectionMixin
from reporting.report_sections.acl_section import ACLSectionMixin
from reporting.report_sections.compliance_section import ComplianceSectionMixin
from reporting.report_sections.risk_tab_builder import RiskTabBuilderMixin

logger = logging.getLogger(__name__)


class HTMLReportGenerator(
    RiskSectionsMixin,
    PurpleTeamMixin,
    DashboardSectionMixin,
    DirectorySectionMixin,
    ACLSectionMixin,
    ComplianceSectionMixin,
    RiskTabBuilderMixin,
):
    """Generates interactive HTML security reports.
    
    HTML generation is split across mixins in reporting/report_sections/:
      - RiskSectionsMixin:      Risk list rendering, grouping, severity helpers
      - PurpleTeamMixin:        Red Team Playbook & Blue Team Checklist
      - DashboardSectionMixin:  CISO dashboard, password stats, account activity
      - DirectorySectionMixin:  Directory objects tables (users, groups, computers)
      - ACLSectionMixin:        ACL security, legacy OS, attack paths, misconfig
      - ComplianceSectionMixin: CIS, NIST, ISO, GDPR compliance & risk management
      - RiskTabBuilderMixin:    Main risk sections tab orchestration
    """
    
    def __init__(self):
        """Initialize HTML report generator."""
        pass

    def _copy_vendor_to_output(self, output_file):
        """Copy reporting/vendor to the same directory as output_file so the report works offline."""
        try:
            output_dir = os.path.dirname(os.path.abspath(output_file))
            if not output_dir:
                output_dir = os.getcwd()
            vendor_src = os.path.join(os.path.dirname(__file__), 'vendor')
            vendor_dst = os.path.join(output_dir, 'vendor')
            if not os.path.isdir(vendor_src):
                logger.warning("Reporting vendor folder not found; report may need network for assets.")
                return
            os.makedirs(vendor_dst, exist_ok=True)
            for name in os.listdir(vendor_src):
                src_path = os.path.join(vendor_src, name)
                if os.path.isfile(src_path):
                    shutil.copy2(src_path, os.path.join(vendor_dst, name))
            logger.debug("Vendor assets copied for offline report.")
        except Exception as e:
            logger.warning("Could not copy vendor assets for offline report: %s", e)

    def generate(self, users, computers, groups, gpos, risks, misconfig_findings,
                 domain_score, executive_summary=None, output_file='report.html',
                 legacy_os_data=None, acl_security_data=None, compliance_data=None,
                 risk_management_data=None, domain=None, dc_ip=None,
                 kerberoasting_targets=None, asrep_targets=None,
                 analysis_summary_counts=None, inline_assets: bool = False):
        """
        Generate HTML report.

        Args:
            users: List of user dictionaries
            computers: List of computer dictionaries
            groups: List of group dictionaries
            gpos: List of GPO dictionaries
            risks: List of risk dictionaries
            misconfig_findings: List of misconfiguration findings
            domain_score: Overall domain security score (0-100)
            executive_summary: Optional executive summary text
            output_file: Output HTML file path
            legacy_os_data: Optional legacy OS data
            acl_security_data: Optional ACL security data
            compliance_data: Optional compliance data
            risk_management_data: Optional risk management data
            domain: Domain name (for Red Team Playbook commands)
            dc_ip: Domain Controller IP (for Red Team Playbook commands)
            kerberoasting_targets: Kerberoasting target list
            asrep_targets: AS-REP roasting target list
            analysis_summary_counts: Optional dict of analysis key -> count for Executive Summary
        """
        html_content = self._generate_html(
            users, computers, groups, gpos, risks, misconfig_findings,
            domain_score, executive_summary, legacy_os_data, acl_security_data,
            compliance_data, risk_management_data, domain, dc_ip,
            kerberoasting_targets, asrep_targets, analysis_summary_counts, inline_assets
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Copy vendor assets next to report so the report works offline (file://)
        # Skipped when assets are fully inlined into the HTML.
        if not inline_assets:
            self._copy_vendor_to_output(output_file)
        
        logger.info(f"HTML report generated: {output_file}")

    def _generate_html(self, users, computers, groups, gpos, risks,
                       misconfig_findings, domain_score, executive_summary,
                       legacy_os_data=None, acl_security_data=None,
                       compliance_data=None, risk_management_data=None,
                       domain=None, dc_ip=None, kerberoasting_targets=None,
                       asrep_targets=None, analysis_summary_counts=None,
                       inline_assets: bool = False):
        """Generate complete HTML content."""
        import base64
        
        # Load logo if exists
        logo_base64 = None
        logo_paths = [
            os.path.join(os.path.dirname(__file__), 'logo.png'),
        ]
        for logo_path in logo_paths:
            if os.path.exists(logo_path):
                try:
                    with open(logo_path, 'rb') as f:
                        logo_data = f.read()
                        logo_base64 = base64.b64encode(logo_data).decode('utf-8')
                        # Determine image type
                        if logo_path.endswith('.png'):
                            logo_mime = 'image/png'
                        elif logo_path.endswith('.jpg') or logo_path.endswith('.jpeg'):
                            logo_mime = 'image/jpeg'
                        else:
                            logo_mime = 'image/png'
                        logo_base64 = f'data:{logo_mime};base64,{logo_base64}'
                        break
                except Exception as e:
                    logger.warning(f"Could not load logo from {logo_path}: {e}")
        
        # Calculate statistics
        stats = self._calculate_statistics(users, computers, groups, risks)
        
        # Generate CISO dashboard data (includes enhanced Executive Summary + all analyses overview)
        ciso_generator = CISODashboardGenerator()
        ciso_data = ciso_generator.generate_dashboard_data(
            risks, users, computers, groups, domain_score, executive_summary,
            analysis_summary_counts=analysis_summary_counts
        )
        
        # Update KPIs with domain score - ensure it's a valid number
        if domain_score is None:
            domain_score = 0.0
        try:
            domain_score = float(domain_score)
            # Ensure score is between 0 and 100
            domain_score = max(0.0, min(100.0, domain_score))
            domain_score = round(domain_score, 1)
        except (ValueError, TypeError):
            domain_score = 0.0
        
        ciso_data['kpis']['overall_score']['value'] = domain_score
        ciso_data['kpis']['overall_score']['color'] = self._get_score_color(domain_score)
        
        # Generate charts data
        charts_data = self._generate_charts_data(risks)
        
        # Generate CISO dashboard HTML
        ciso_dashboard_html = self._generate_ciso_dashboard_html(ciso_data, stats)
        
        # Generate risk sections (with dashboard)
        password_stats = ciso_data.get('password_stats', {})
        risk_sections = self._generate_risk_sections(
            risks, misconfig_findings, ciso_dashboard_html,
            users, groups, computers, password_stats,
            compliance_data, risk_management_data,
            domain, dc_ip, kerberoasting_targets, asrep_targets
        )
        
        # Optional: inline vendor CSS/JS so the HTML file is completely self-contained
        inline_css = None
        inline_js = None
        if inline_assets:
            vendor_dir = os.path.join(os.path.dirname(__file__), "vendor")
            css_parts = []
            js_parts = []
            try:
                # CSS assets
                for name in ("bootstrap.min.css", "fontawesome.min.css", "google-fonts.css"):
                    path = os.path.join(vendor_dir, name)
                    if os.path.exists(path):
                        with open(path, "r", encoding="utf-8") as f:
                            css_parts.append(f.read())
                # JS assets (order matters: bootstrap, chart, lucide)
                for name in ("bootstrap.bundle.min.js", "chart.umd.min.js", "lucide.min.js"):
                    path = os.path.join(vendor_dir, name)
                    if os.path.exists(path):
                        with open(path, "r", encoding="utf-8") as f:
                            js_parts.append(f.read())
            except Exception as e:
                logger.warning("Could not inline vendor assets into HTML report: %s", e)
            inline_css = "\n\n".join(css_parts) if css_parts else None
            inline_js = "\n\n".join(js_parts) if js_parts else None
        
        report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = build_saas_report(
            logo_base64 or '',
            report_date,
            stats,
            ciso_data,
            risk_sections,
            charts_data,
            DEVELOPER_INFO,
            inline_assets=inline_assets,
            inline_css=inline_css,
            inline_js=inline_js,
        )
        return html
