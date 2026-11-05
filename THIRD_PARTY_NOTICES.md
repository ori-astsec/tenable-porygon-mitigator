# Third-party notices

porygon-mitigator's code is MIT-licensed (see [LICENSE](LICENSE)). The data it reads and the small extracts it
stores come from third parties under their own terms:

- **NVD.** This product uses the NVD API but is not endorsed or certified by the NVD.
- **CVE records** (cveawg.mitre.org) are published by the CVE Program under the CVE Terms of Use.
- **CISA KEV** catalog data is a U.S. Government work published by CISA.
- **Red Hat Security Data API** content is licensed under Creative Commons Attribution 4.0 (CC BY 4.0) by Red Hat,
  Inc.
- **OSV** data (including GitHub Security Advisories served through OSV) is published under CC BY 4.0 / the
  respective database licences.
- **Ubuntu CVE tracker** data is published by Canonical Ltd.
- **Microsoft Security Update Guide / CVRF** data is published by Microsoft Corporation.
- **IPS/WAF catalogues.** `data/catalogs/` holds only CVE identifiers, rule IDs and links derived from:
  - the Snort 3 community ruleset (Cisco Talos, GPLv2);
  - Proofpoint Emerging Threats Open rules (only the BSD-licensed SID range 2000000-2799999 is indexed);
  - F5 attack-signature documentation, Microsoft Azure WAF documentation, Cloudflare WAF changelogs, and
    NetScaler signature documentation.

  No rule bodies are redistributed. Palo Alto Networks Threat Vault data needs your own API key and is only ever
  stored in your local work directory, never committed. The one exception is `demo/tenable-lab/palo_threat_ids.json`:
  threat IDs (identifiers only) for 22 CVEs, so the lab demo can name the signatures it simulates.
- **Advisory quotes** in `data/cache/` are short excerpts (at most 300 characters) cited with their source URL,
  used to let readers verify each mitigation against the original.

Product and company names are trademarks of their respective owners.
