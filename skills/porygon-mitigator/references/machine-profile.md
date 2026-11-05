# Machine profile

A JSON object describing one host or appliance. `porygon profile schema` prints the JSON Schema;
`porygon profile validate <file>` checks a file. Only `name` and `os.platform` are required, but every field you add
sharpens the result.

| Field | What it's for | Tenable source |
|---|---|---|
| `name` | report title | `name`, `fqdns`, `hostnames`, `ipv4s` |
| `os.platform` / `os.name` / `os.version` / `os.distribution` | platform filter, appliance identity, distro package states | `operating_systems` |
| `vendor` | appliances (PAN-OS, FortiOS, NetScaler...) enforce their own vendor's signatures | derived from `operating_systems` |
| `installed_software[]` | is the vulnerable product present, which version | `installed_software` (CPE 2.2) and plugins 22869 / 20811 / 83991 |
| `open_ports[]` | is the vulnerable service listening, exposed | `network.open_ports`, plugins 25221 / 34252 |
| `internet_exposed` | ranking context | `is_public` |
| `network_path[]` | firewall / IPS / WAF / load balancer in front: decides which signatures apply | not in the asset record; add with `--overlay` |
| `security_tools[]` | EDR/AV present: decides EDR mitigations | installed software, connector `sources` |
| `findings[]` | a scanner finding for the CVE means "affected" | vulnerability export rows (`plugin.cve`) |
| `config_state` | sysctl, registry, services, kernel modules, app settings: "already applied" checks | plugin 10456 (services); otherwise manual |

Example (abridged):

```json
{
  "name": "bastion-01",
  "os": {"platform": "linux", "name": "Ubuntu 22.04.4 LTS", "version": "22.04", "distribution": "ubuntu"},
  "installed_software": [{"cpe": "cpe:/a:openbsd:openssh:8.9p1", "package": "openssh-server",
                          "version": "1:8.9p1-3ubuntu0.6"}],
  "open_ports": [{"port": 22, "protocol": "tcp", "service_names": ["ssh"], "internet_exposed": true}],
  "network_path": [{"role": "ngfw", "vendor": "Palo Alto Networks", "product": "PA-3220"}],
  "security_tools": [{"category": "edr", "vendor": "CrowdStrike", "product": "Falcon Sensor"}],
  "config_state": {"app_settings": {"openssh:logingracetime": "120"}}
}
```
