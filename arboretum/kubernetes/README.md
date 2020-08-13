# Kubernetes library

The fetchers and checks contained within this `kubernetes` category folder are
common tests that can be configured and executed for the purpose of generating
compliance reports and notifications using the [auditree-framework][].  They
validate the configuration and ensure smooth execution of an auditree instance.
See [auditree-framework documentation](https://complianceascode.github.io/auditree-framework/)
for more details.

These tests are normally executed by a CI/CD system like
[Travis CI](https://travis-ci.com/) as part of another project that uses this
library package as a dependency.

## Usage as a library

See [usage][usage] for specifics on including this library as a dependency and
how to include the fetchers and checks from this library in your downstream project.

## Fetchers

Fetchers coming soon...

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


[usage]: https://github.com/ComplianceAsCode/auditree-arboretum#usage
