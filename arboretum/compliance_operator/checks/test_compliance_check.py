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

    XMLNS_XCCDF = 'http://checklists.nist.gov/xccdf/1.2'
    EVIDENCE_FILEPATH = 'raw/kube/cluster_resource.json'

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
        cls.logger = cls.locker.logger.getChild('compliance_operator.checker')
        return cls

    def test_compliance_by_control_id(self):
        """Check all controls are compliant."""
        mappings = self.config.get('org.compliance_operator.mappings', {})
        target_clusters = self.config.get(
            'org.compliance_operator.target_cluster', {}
        )

        evidence = {}
        evidence_filepath = ComplianceOperatorResultCheck.EVIDENCE_FILEPATH
        with evidences(self.locker, evidence_filepath) as e:
            evidence = json.loads(e.content)
            if not evidence:
                self.add_failures(
                    'No evidence found',
                    ComplianceOperatorResultCheck.EVIDENCE_FILEPATH
                )
                return

        # extract XCCDF result from evidence
        for provider in target_clusters:
            clusters = self._get_clusters(evidence, provider, target_clusters)
            for cluster in clusters:
                if not cluster:
                    self.add_failures(
                        'No resource found for a target cluster',
                        {json.dumps(cluster)}
                    )
                    continue
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
                                xccdf = bz2.decompress(
                                    base64.b64decode(raw_data)
                                )
                            break
                if xccdf is None:
                    self.add_failures(
                        f'Target cluster `{cluster["name"]}`'
                        ' does not contain XCCDF result',
                        cluster['name']
                    )
                    continue

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
        return ['compliance_operator/compliance_operator_result.md']

    def get_notification_message(self):
        """Notification for the non-customer key check."""
        return {'subtitle': 'compliance-operator result'}

    def _search_cluster(
        self, evidence_clusters, target_cluster, is_same_cluster
    ):
        for ec in evidence_clusters:
            if is_same_cluster(ec, target_cluster):
                ComplianceOperatorResultCheck.logger.info(
                    'target found: %s', target_cluster['name']
                )
                return ec
        return None

    def _get_clusters(self, evidence, provider, tgt_clusters):
        logger = ComplianceOperatorResultCheck.logger
        clusters = []

        # process target cluster per provider.
        if provider == 'iks':
            logger.info('Processing IKS Cluster')
            for account in tgt_clusters[provider]:
                logger.info('Processing account: %s', account)
                evidence_clusters = None
                if provider not in evidence:
                    self.add_failures(
                        'The provider specified in the '
                        'configuration is not found in evidence',
                        f'provider: `{provider}`'
                    )
                    continue
                if account not in evidence[provider]:
                    self.add_failures(
                        'The account specified in the '
                        'configuration is not found in evidence',
                        f'account: `{account}` ('
                        f'provider: `{provider}`)'
                    )
                    continue
                evidence_clusters = evidence[provider][account]
                for cluster in tgt_clusters[provider][account]:

                    def is_same_cluster(ec, tc):
                        is_same = ec['name'] == tc['name']
                        if 'region' in tc:
                            is_same = (
                                is_same and ec['region'] == tc['region']
                            )
                        return is_same

                    c = self._search_cluster(
                        evidence_clusters, cluster, is_same_cluster
                    )
                    if c is None:
                        detailed_msg = f'name: `{cluster["name"]}`, '
                        f' (provider: `{provider}`, '
                        f'account: `{account}`, '
                        if 'region' in cluster:
                            detailed_msg += f'region: `{cluster["region"]}`, '
                        detailed_msg += ')'
                        self.add_failures(
                            'The cluster specified in the '
                            'configuration is not found '
                            'in evidence',
                            detailed_msg
                        )
                        continue
                    clusters.append(c)
        else:
            self.add_failures(
                'The provider specified '
                'in the configuration is not supported',
                f'provider: `{provider}`'
            )
        return clusters
