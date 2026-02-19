"""
Export Formats Module
Supports multiple export formats for integration with other tools
"""

import json
import csv
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class ExportFormats:
    """Handles export to various formats."""
    
    @staticmethod
    def export_csv(risks: List[Dict[str, Any]], output_file: str) -> None:
        """
        Export risks to CSV format.
        
        Args:
            risks: List of risk dictionaries
            output_file: Output file path
        """
        if not risks:
            logger.warning("No risks to export")
            return
        
        # Get all unique keys from risks
        fieldnames = set()
        for risk in risks:
            fieldnames.update(risk.keys())
        
        fieldnames = sorted(list(fieldnames))
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for risk in risks:
                # Convert complex types to strings
                row = {}
                for key, value in risk.items():
                    if isinstance(value, (list, dict)):
                        row[key] = json.dumps(value)
                    else:
                        row[key] = value
                writer.writerow(row)
        
        logger.info(f"CSV export saved to {output_file}")
    
    @staticmethod
    def export_nessus_xml(risks: List[Dict[str, Any]], output_file: str, 
                         domain: str) -> None:
        """
        Export risks in Nessus XML format (simplified).
        
        Args:
            risks: List of risk dictionaries
            output_file: Output file path
            domain: Domain name
        """
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom
        
        root = Element('NessusClientData_v2')
        policy = SubElement(root, 'Policy')
        SubElement(policy, 'policyName').text = 'AtilKurt AD Security Scan'
        
        report = SubElement(root, 'Report')
        report.set('name', f'AD Security Scan - {domain}')
        
        report_host = SubElement(report, 'ReportHost')
        report_host.set('name', domain)
        
        for risk in risks:
            if risk.get('severity') in ['high', 'critical']:
                item = SubElement(report_host, 'ReportItem')
                item.set('port', '0')
                item.set('svc_name', 'ldap')
                item.set('protocol', 'tcp')
                item.set('severity', risk.get('severity', 'medium'))
                item.set('pluginID', str(hash(risk.get('type', '')) % 100000))
                item.set('pluginName', risk.get('title', 'Unknown Risk'))
                item.set('pluginFamily', 'Active Directory')
                
                SubElement(item, 'description').text = risk.get('description', '')
                SubElement(item, 'solution').text = risk.get('mitigation', '')
                SubElement(item, 'risk_factor').text = risk.get('severity', 'medium').upper()
        
        # Pretty print
        xml_str = minidom.parseString(tostring(root)).toprettyxml(indent="  ")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(xml_str)
        
        logger.info(f"Nessus XML export saved to {output_file}")
    
    @staticmethod
    def export_kerberoasting_list(kerberoasting_targets: List[Dict[str, Any]], 
                                 output_file: str) -> None:
        """
        Export Kerberoasting targets in a format suitable for exploitation tools.
        
        Args:
            kerberoasting_targets: List of Kerberoasting target dictionaries
            output_file: Output file path
        """
        export_data = {
            'export_date': datetime.now().isoformat(),
            'targets': []
        }
        
        for target in kerberoasting_targets:
            export_format = target.get('export_format', {})
            export_data['targets'].append({
                'username': target.get('affected_object', ''),
                'spns': target.get('spns', []),
                'is_privileged': target.get('is_privileged', False),
                'impacket_command': export_format.get('impacket_command', ''),
                'rubeus_command': export_format.get('rubeus_command', ''),
                'cme_command': export_format.get('cme_command', '')
            })
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Kerberoasting targets export saved to {output_file}")
    
    @staticmethod
    def export_siem_json(
        risks: List[Dict[str, Any]],
        output_file: str,
        domain: str = '',
        host: str = 'atilkurt'
    ) -> None:
        """
        Export risks in SIEM-friendly JSON format for Splunk/Elastic.
        Each risk is a separate JSON object (ndjson) for easy ingestion.
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            for risk in risks:
                siem_event = {
                    'timestamp': datetime.now().isoformat(),
                    'source': 'AtilKurt',
                    'domain': domain,
                    'host': host,
                    'event_type': 'ad_security_risk',
                    'risk_type': risk.get('type', ''),
                    'severity': risk.get('severity', ''),
                    'title': risk.get('title', ''),
                    'description': risk.get('description', '')[:500],
                    'affected_object': risk.get('affected_object', ''),
                    'object_type': risk.get('object_type', ''),
                    'mitre_attack': risk.get('mitre_attack', ''),
                    'cve': risk.get('cve', ''),
                }
                f.write(json.dumps(siem_event, default=str, ensure_ascii=False) + '\n')
        logger.info(f"SIEM JSON export saved to {output_file}")

    @staticmethod
    def export_cef(
        risks: List[Dict[str, Any]],
        output_file: str,
        domain: str = '',
        device_vendor: str = 'AtilKurt',
        device_product: str = 'AD-Security-Scan'
    ) -> None:
        """
        Export risks in CEF (Common Event Format) for ArcSight/Splunk/syslog.
        """
        def _cef_escape(s: str) -> str:
            if not s:
                return ''
            return str(s).replace('\\', '\\\\').replace('=', '\\=').replace('\n', ' ')

        with open(output_file, 'w', encoding='utf-8') as f:
            for risk in risks:
                ext = (
                    f"rt={int(datetime.now().timestamp()) * 1000} "
                    f"cn1={4 if risk.get('severity') == 'critical' else 3 if risk.get('severity') == 'high' else 2} "
                    f"cs1Label=riskType cs1={_cef_escape(risk.get('type', ''))} "
                    f"cs2Label=affectedObject cs2={_cef_escape(str(risk.get('affected_object', '')))} "
                    f"msg={_cef_escape(risk.get('title', '')[:200])}"
                )
                cef = f"CEF:0|{device_vendor}|{device_product}|1.0|AD_SECURITY_RISK|{risk.get('type', 'risk')}|{risk.get('severity', 'medium').upper()}|{ext}"
                f.write(cef + '\n')
        logger.info(f"CEF export saved to {output_file}")

    @staticmethod
    def _extract_group_name(group_dn: str) -> str:
        """Extract group name from DN."""
        if not group_dn:
            return ''
        if 'CN=' in group_dn:
            try:
                return group_dn.split('CN=')[1].split(',')[0]
            except Exception:
                return ''
        return group_dn
    
    @staticmethod
    def _extract_member_name(member_dn: str) -> str:
        """Extract member name from DN."""
        return ExportFormats._extract_group_name(member_dn)
