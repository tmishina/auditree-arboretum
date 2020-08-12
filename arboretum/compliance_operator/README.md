# Compliance Operator provider library

The checks contained within this `compliance_operator` provider folder are common tests that can be configured and
executed for the purpose of generating compliance reports and notifications using the [compliance-tool][compliance-tool].
See [compliance-tool documentation][compliance-tool-docs] for more details on the compliance tooling framework.

These tests are normally executed by the Whitewater Travis CI system as part of another project that uses this library
package as a dependency.

## Usage as a library

See [usage][usage] for specifics on including this library as a dependency and how to include the fetchers and checks
from this library in your downstream project.


## Checks

### Compliance Operator Result Check

* Class: [ComplianceOperatorResultCheck][ComplianceOperatorResultCheck]
* Purpose: Verifies the output of Compliance Operator.
* Behavior: Confirms that all of XCCDF results mapped from each control ID specified in the config are `pass`
* Evidence depended upon:
  * Compliance Operator Result
    * `raw/iks/iks_inventory_{accont}.json`
    * Gathered by the `iks` provider [InventoryFetcher][InventoryFetcher]
* Expected configuration elements:
  * `org.compliance_operator.mappings`
    * Dictionary (regulatory standard to target control ID) containing a list of XCCDF IDs
* Expected configuration:
```json
{
  "org": {
    "compliance_operator": {
      "mappings": {
        "nist": {
          "AC-3": [
            "xccdf_org.ssgproject.content_rule_api_server_admission_control_plugin_DenyEscalatingExec",
            "xccdf_org.ssgproject.content_rule_api_server_insecure_allow_any_token",
            "xccdf_org.ssgproject.content_rule_controller_disable_profiling",
            "xccdf_org.ssgproject.content_rule_api_server_admission_control_plugin_AlwaysPullImages",
            "xccdf_org.ssgproject.content_rule_etcd_peer_client_cert_auth"
          ],
          ...
```

* Import statement:

```python
from auditree_central.provider.compliance_operator.checks.test_compliance_check import ComplianceOperatorResultCheck
```


[compliance-tool]: https://github.ibm.com/cloumpose/compliance-tool
[compliance-tool-docs]: https://pages.github.ibm.com/cloumpose/compliance-tool
[usage]: https://github.ibm.com/auditree/auditree-central#usage
[ComplianceOperatorResultCheck]: https://github.ibm.com/auditree/auditree-central/blob/master/auditree_central/provider/compliance_operator/checks/test_compliance_check.py
[InventoryFetcher]: https://github.ibm.com/auditree/auditree-central/blob/master/auditree_central/provider/iks/fetchers/fetch_inventory.py
