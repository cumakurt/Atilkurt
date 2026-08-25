"""
HTML Report Generator Module
Generates interactive HTML reports using Bootstrap and Chart.js

This module is the main entry point. All section-specific HTML generation
is delegated to mixin classes in the report_sections/ package.
"""

import logging
import base64
import mimetypes
import os
import re
import shutil
from datetime import datetime

from core.constants import DEVELOPER_INFO
from core.secure_file import atomic_write_text
from reporting.ciso_dashboard import CISODashboardGenerator
from reporting.saas_report_template import build_saas_report
from reporting.localization import (
    localize_finding_list,
    localize_html_document,
    localize_report_structure,
    normalize_language,
)

from reporting.report_sections.risk_sections import RiskSectionsMixin
from reporting.report_sections.purple_team import PurpleTeamMixin
from reporting.report_sections.dashboard_section import DashboardSectionMixin
from reporting.report_sections.directory_section import DirectorySectionMixin
from reporting.report_sections.acl_section import ACLSectionMixin
from reporting.report_sections.compliance_section import ComplianceSectionMixin
from reporting.report_sections.risk_tab_builder import RiskTabBuilderMixin
from reporting.report_sections.domain_admin_section import DomainAdminSectionMixin

logger = logging.getLogger(__name__)


class HTMLReportGenerator(
    RiskSectionsMixin,
    PurpleTeamMixin,
    DashboardSectionMixin,
    DirectorySectionMixin,
    ACLSectionMixin,
    ComplianceSectionMixin,
    DomainAdminSectionMixin,
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
      - DomainAdminSectionMixin: Pentest-oriented Domain Admin takeover map
      - RiskTabBuilderMixin:    Main risk sections tab orchestration
    """

    def __init__(self, language: str = 'en'):
        """Initialize HTML report generator."""
        self.language = normalize_language(language)

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
                 analysis_summary_counts=None, domain_admin_takeover=None,
                 inline_assets: bool = True):
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
            domain_admin_takeover: Optional Domain Admin takeover map from scoring
        """
        html_content = self._generate_html(
            users, computers, groups, gpos, risks, misconfig_findings,
            domain_score, executive_summary, legacy_os_data, acl_security_data,
            compliance_data, risk_management_data, domain, dc_ip,
            kerberoasting_targets, asrep_targets, analysis_summary_counts,
            domain_admin_takeover, inline_assets
        )

        atomic_write_text(output_file, html_content)

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
                       domain_admin_takeover=None, inline_assets: bool = True):
        """Generate complete HTML content."""
        if self.language == 'tr':
            risks = localize_finding_list(risks, self.language)
            misconfig_findings = localize_finding_list(
                misconfig_findings,
                self.language,
                finding_kind='misconfiguration',
            )
            executive_summary = localize_report_structure(
                executive_summary,
                self.language,
            )
            risk_management_data = localize_report_structure(
                risk_management_data,
                self.language,
            )
            compliance_data = localize_report_structure(
                compliance_data,
                self.language,
                structure_kind='compliance',
            )
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
        if domain_admin_takeover is None:
            from analysis.domain_admin_takeover_analyzer import DomainAdminTakeoverAnalyzer
            domain_admin_takeover = DomainAdminTakeoverAnalyzer().analyze(
                risks, users=users, groups=groups, computers=computers
            )
        if self.language == 'tr':
            domain_admin_takeover = localize_report_structure(
                domain_admin_takeover,
                self.language,
                structure_kind='domain_admin_takeover',
            )
        summary = (domain_admin_takeover or {}).get("summary") or {}
        stats["da_takeover_count"] = int(summary.get("open_path_count") or 0)

        # Generate CISO dashboard data (includes enhanced Executive Summary + all analyses overview)
        ciso_generator = CISODashboardGenerator()
        ciso_data = ciso_generator.generate_dashboard_data(
            risks, users, computers, groups, domain_score, executive_summary,
            analysis_summary_counts=analysis_summary_counts
        )
        if self.language == 'tr':
            ciso_data = localize_report_structure(ciso_data, self.language)

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
            domain, dc_ip, kerberoasting_targets, asrep_targets,
            domain_admin_takeover=domain_admin_takeover,
        )

        # Inline vendor CSS/JS so the HTML file is completely self-contained.
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
                        with open(path, encoding="utf-8") as f:
                            css_parts.append(self._inline_css_asset_urls(f.read(), path, vendor_dir))
                # JS assets (order matters: bootstrap, chart, lucide)
                for name in ("bootstrap.bundle.min.js", "chart.umd.min.js", "lucide.min.js"):
                    path = os.path.join(vendor_dir, name)
                    if os.path.exists(path):
                        with open(path, encoding="utf-8") as f:
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
        return localize_html_document(html, self.language)

    def _inline_css_asset_urls(self, css: str, css_path: str, vendor_dir: str) -> str:
        """Replace local or vendored CSS url(...) references with data URIs."""
        css_dir = os.path.dirname(css_path)

        def replace_url(match):
            raw_url = match.group(1).strip().strip("\"'")
            if not raw_url or raw_url.startswith(("data:", "#")):
                return match.group(0)

            asset_path = self._resolve_css_asset_path(raw_url, css_dir, vendor_dir)
            if not asset_path:
                logger.debug("Could not inline CSS asset URL: %s", raw_url)
                return f'url("{self._empty_data_uri_for_url(raw_url)}")'

            data_uri = self._file_to_data_uri(asset_path)
            if not data_uri:
                return match.group(0)
            return f'url("{data_uri}")'

        return re.sub(r"url\(([^)]+)\)", replace_url, css)

    def _resolve_css_asset_path(self, raw_url: str, css_dir: str, vendor_dir: str) -> str:
        """Resolve relative and vendored font URLs used by bundled CSS."""
        url_without_fragment = raw_url.split("#", 1)[0].split("?", 1)[0]
        basename = os.path.basename(url_without_fragment)
        candidates = []

        if re.match(r"^https?://", raw_url):
            candidates.extend([
                os.path.join(vendor_dir, "fonts", basename),
                os.path.join(vendor_dir, "webfonts", basename),
            ])
        else:
            candidates.extend([
                os.path.normpath(os.path.join(css_dir, url_without_fragment)),
                os.path.normpath(os.path.join(vendor_dir, url_without_fragment.lstrip("/"))),
                os.path.join(vendor_dir, "fonts", basename),
                os.path.join(vendor_dir, "webfonts", basename),
            ])

        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return ""

    def _file_to_data_uri(self, path: str) -> str:
        """Read a local asset and return a data URI."""
        try:
            mime_type, _ = mimetypes.guess_type(path)
            if path.endswith(".woff2"):
                mime_type = "font/woff2"
            elif path.endswith(".woff"):
                mime_type = "font/woff"
            elif path.endswith(".ttf"):
                mime_type = "font/ttf"
            if not mime_type:
                mime_type = "application/octet-stream"
            with open(path, "rb") as f:
                encoded = base64.b64encode(f.read()).decode("ascii")
            return f"data:{mime_type};base64,{encoded}"
        except OSError as e:
            logger.debug("Could not inline asset %s: %s", path, e)
            return ""

    def _empty_data_uri_for_url(self, raw_url: str) -> str:
        """Return an inert data URI for optional CSS fallback assets that are not bundled."""
        url_path = raw_url.split("#", 1)[0].split("?", 1)[0]
        mime_type, _ = mimetypes.guess_type(url_path)
        if url_path.endswith(".woff2"):
            mime_type = "font/woff2"
        elif url_path.endswith(".woff"):
            mime_type = "font/woff"
        elif url_path.endswith(".ttf"):
            mime_type = "font/ttf"
        if not mime_type:
            mime_type = "application/octet-stream"
        return f"data:{mime_type};base64,"
