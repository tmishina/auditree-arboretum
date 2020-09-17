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

        self.logger.info('%d Clusters are targetted', len(target_clusters))
        for category in target_clusters:
            self.logger.info('Processing category "%s"', category)
            evidence = {}
            evidence_filepath = f'raw/{category}/cluster_resource.json'
            with evidences(self.locker, evidence_filepath) as e:
                evidence = json.loads(e.content)
                if not evidence:
                    msg = f'Evidence file found: {evidence_filepath}'
                    self.logger.error(msg)
                    self.add_failures(msg, category)
                    return
            for account in target_clusters[category]:
                self.logger.info('Processing account "%s"', account)
                for c in target_clusters[category][account]:
                    self.logger.info(
                        'Searching a target cluster "%s" in evidence',
                        c['name']
                    )
                    cluster = self._search_cluster(evidence, account, c)
                    if cluster:
                        self.logger.info(
                            'Processing a target cluster "%s"', c['name']
                        )
                        self._process_cluster(cluster, category, account)
                    else:
                        msg = (
                            f'Target cluster {c["name"]} '
                            'not found in evidence'
                        )
                        self.logger.error(msg)
                        self.add_failures(msg, c['name'])
                        return

    def _process_cluster(self, cluster, cluster_type, account):
        xccdf = {}
        if 'configmaps' not in cluster['resources']:
            msg = 'No configmap exists in evidence'
            self.logger.error(msg)
            self.add_failures(msg, cluster['name'])
            return
        for resource in cluster['resources']['configmaps']:
            metadata = resource['metadata']
            if ('labels' in metadata
                    and 'compliance-scan' in metadata['labels']
                    and 'results' in resource['data']):
                raw_data = resource['data']['results']
                if raw_data.startswith('<?xml'):
                    xccdf[metadata['name']] = raw_data.encode('utf-8')
                else:
                    xccdf[metadata['name']] = bz2.decompress(
                        base64.b64decode(raw_data)
                    )

        # process XML here
        # remove default namespace due to the limitation of ElementTree
        result_map = {}
        for configmap in xccdf:
            xml_string = re.sub(
                r'\sxmlns="[^"]+"',
                '',
                xccdf[configmap].decode('utf-8'),
                count=1
            )
            root = ElementTree.fromstring(xml_string)
            for child in root:
                if child.tag != 'rule-result':
                    continue
                rule_result = child
                xccdf_id = rule_result.attrib['idref']
                result = rule_result.findall('result')[0].text
                if configmap not in result_map:
                    result_map[configmap] = {}
                result_map[configmap][xccdf_id] = result
                self.logger.debug('%s: %s', xccdf_id, result)
        osco_config = self.config.get('org.kubernetes.compliance_operator', {})
        for def_id in osco_config['target_catalog']:
            configmap = osco_config['target_catalog'][def_id]['configmap']
            mappings = osco_config['target_catalog'][def_id]['mappings']
            for ctrl_id in mappings:
                for xccdf_id in mappings[ctrl_id]:
                    configmaps = result_map.keys()
                    self.logger.info('configmaps: %s', ','.join(configmaps))
                    # tentative
                    for c in configmaps:
                        if c.startswith(configmap):
                            configmap = c
                            break
                    if xccdf_id not in result_map[configmap]:
                        self.add_failures(
                            f'cluster {cluster["name"]}: '
                            'XCCDF check result '
                            'does not exist for a Control ID',
                            f'Control ID `{def_id}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'does not exist.'
                        )
                        continue
                    result = result_map[configmap][xccdf_id]
                    if result == 'fail':
                        self.add_failures(
                            f'cluster {cluster["name"]}: '
                            'XCCDF check result is `fail`',
                            f'Control ID `{def_id}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'is `fail`'
                        )
                    elif result == 'notapplicable':
                        self.add_warnings(
                            f'cluster {cluster["name"]}: '
                            'XCCDF check was skipped',
                            f'Control ID `{def_id}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'is `{result}`'
                        )
                    elif result == 'notselected':
                        self.add_warnings(
                            f'cluster {cluster["name"]}: '
                            'XCCDF check was not selected',
                            f'Control ID `{def_id}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'is `{result}`'
                        )
                    elif result != 'pass':
                        self.add_warnings(
                            f'cluster {cluster["name"]}: '
                            'XCCDF check was not `pass`',
                            f'Control ID `{def_id}`/`{ctrl_id}`: '
                            f'XCCDF ID `{xccdf_id}` '
                            f'is `{result}`'
                        )
                    elif result == 'pass':
                        self.logger.info(
                            'cluster %s: XCCDF check was `pass`'
                            '(ctrl: %s/%s, xccdf: %s)',
                            cluster['name'],
                            def_id,
                            ctrl_id,
                            xccdf_id
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

    def _search_cluster(self, evidence, account, target_cluster):

        if account not in evidence:
            self.add_failures('No such account in evidence', f'{account}')
            return None

        for ec in evidence[account]:
            found = True
            for k in target_cluster:
                if k in ec:
                    found = found and target_cluster[k] == ec[k]
            if found:
                ComplianceOperatorResultCheck.logger.info(
                    'target found: %s', target_cluster['name']
                )
                return ec
        return None
