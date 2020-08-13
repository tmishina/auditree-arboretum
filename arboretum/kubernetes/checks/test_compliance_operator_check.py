# -*- coding:utf-8; mode:python -*-
"""Compliance Operator result checks."""

import base64
import bz2
import json
import re

from compliance.check import ComplianceCheck
from compliance.evidence import DAY, ReportEvidence, evidences

from defusedxml import ElementTree


class ComplianceOperatorResultCheck(ComplianceCheck):
    """Check all of the controls are compliant."""

    @property
    def title(self):
        """
        Return the title of the checks.

        :returns: the title of the checks
        """
        return 'Compliance Operator Result Check'

    @classmethod
    def setUpClass(cls):
        """Initialize the check object with configuration settings."""
        cls.config.add_evidences(
            [
                ReportEvidence(
                    'compliance_operator_result.md',
                    'compliance_operator',
                    DAY,
                    'Compliance Operator Check Result Report'
                )
            ]
        )
        cls.logger = cls.locker.logger.getChild(
            'kubernetes.compliance_operator.check.'
            'ComplianceOperatorResultCheck'
        )
        return cls

    def test_compliance_by_control_id(self):
        """Check all controls are compliant."""
        target_clusters = self.config.get(
            'org.kubernetes.compliance_operator.target_cluster', {}
        )

        evidence = {}
        evidence_filepath = 'raw/kubernetes/cluster_resource.json'
        with evidences(self.locker, evidence_filepath) as e:
            evidence = json.loads(e.content)
            if not evidence:
                self.add_failures('No evidence found', evidence_filepath)
                return

        for cluster_type in target_clusters:
            for account in target_clusters[cluster_type]:
                for c in target_clusters[cluster_type][account]:
                    cluster = self._search_cluster(
                        evidence, cluster_type, account, c
                    )
                    if cluster:
                        self._process_cluster(cluster, cluster_type, account)

    def _process_cluster(self, cluster, cluster_type, account):
        xccdf = None
        for resource in cluster['resources']:
            if resource['kind'] == 'ConfigMap':
                metadata = resource['metadata']
                if ('labels' in metadata
                        and 'compliance-scan' in metadata['labels']
                        and 'results' in resource['data']):
                    raw_data = resource['data']['results']
                    xccdf = None
                    if raw_data.startswith('<?xml'):
                        xccdf = raw_data.encode('utf-8')
                    else:
                        xccdf = bz2.decompress(base64.b64decode(raw_data))
                    break
        if xccdf is None:
            self.add_failures(
                f'Target cluster `{cluster["name"]}`'
                ' does not contain XCCDF result',
                cluster['name']
            )
            return

        # process XML here
        # remove default namespace due to the limitation of ElementTree
        xml_string = re.sub(
            r'\sxmlns="[^"]+"', '', xccdf.decode('utf-8'), count=1
        )
        root = ElementTree.fromstring(xml_string)
        result_map = {}
        for child in root:
            if child.tag != 'rule-result':
                continue
            rule_result = child
            xccdf_id = rule_result.attrib['idref']
            result = rule_result.findall('result')[0].text
            result_map[xccdf_id] = result
            self.logger.debug('%s: %s', xccdf_id, result)
        mappings = self.config.get(
            'org.kubernetes.compliance_operator.mappings', {}
        )
        for std in mappings:
            for ctrl_id in mappings[std]:
                for xccdf_id in mappings[std][ctrl_id]:
                    if xccdf_id not in result_map:
                        self.add_failures(
                            f'cluster {cluster["name"]}: '
                            'XCCDF check result '
                            'does not exist for a Control ID',
                            f'Control ID `{std}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'does not exist.'
                        )
                        continue
                    result = result_map[xccdf_id]
                    if result == 'fail':
                        self.add_failures(
                            f'cluster {cluster["name"]}: '
                            'XCCDF check result is `fail`',
                            f'Control ID `{std}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'is `fail`'
                        )
                    elif result == 'notapplicable':
                        self.add_warnings(
                            f'cluster {cluster["name"]}: '
                            'XCCDF check was skipped',
                            f'Control ID `{std}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'is `{result}`'
                        )
                    elif result == 'notselected':
                        self.add_warnings(
                            f'cluster {cluster["name"]}: '
                            'XCCDF check was not selected',
                            f'Control ID `{std}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'is `{result}`'
                        )
                    elif result != 'pass':
                        self.add_warnings(
                            f'cluster {cluster["name"]}: '
                            'XCCDF check was not `pass`',
                            f'Control ID `{std}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'is `{result}`'
                        )
                    elif result == 'pass':
                        self.add_warnings(
                            f'debug: cluster {cluster["name"]}: '
                            'XCCDF check was `pass`',
                            f'Control ID `{std}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'is `{result}`'
                        )

    def get_reports(self):
        """
        Provide the check report name.

        :returns: the report(s) generated for this check.
        """
        return ['kubernetes/compliance_operator_result.md']

    def get_notification_message(self):
        """Notification for the non-customer key check."""
        return {'subtitle': 'compliance-operator result'}

    def _search_cluster(self, evidence, cluster_type, account, cluster):

        if cluster_type not in evidence:
            self.add_failures('No such cluster_type in evidence', cluster_type)
            return None
        if account not in evidence[cluster_type]:
            self.add_failures(
                'No such account in evidence', f'{cluster_type}/{account}'
            )
            return None

        for ec in evidence[cluster_type][account]:
            found = False
            if cluster_type == 'kubernetes':
                found = ec['name'] == cluster['name']
            elif cluster_type == 'ibm_cloud':
                found = ec['name'] == cluster['name']
                if 'region' in cluster:
                    found = found and ec['region'] == cluster['region']
            else:
                self.add_failures(
                    'cluster_type is not supported', cluster_type
                )
            if found:
                ComplianceOperatorResultCheck.logger.info(
                    'target found: %s', cluster['name']
                )
                return ec
        return None
