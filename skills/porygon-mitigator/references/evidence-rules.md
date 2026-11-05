# Evidence rules

- Every mitigation carries at least one **evidence quote** copied from its source. porygon checks in code that the
  quote appears verbatim (after whitespace and punctuation normalisation) in the exact text the model read; a
  mitigation with no verified quote is dropped.
- A step's **command** is kept only if it appears verbatim in the source. Otherwise the step says "the exact command
  is not given in the source" and you must not supply one.
- **Catalogue mitigations** (Snort/Talos, ET Open, F5, Azure WAF, Cloudflare, NetScaler, Threat Vault) cite the rule
  catalogue entry instead of a prose quote: the rule IDs are read from the vendor's own catalogue.
- Notes marked **derived** (`how_to_verify`, some `rollback`/`side_effects`) are generated from the action itself,
  not stated by the source. Say so when you present them.
- **Confidence:** `vendor_documented` (vendor, distribution, government or the device vendor's catalogue),
  `third_party` (research blogs, mailing lists, GitHub advisories).
- **Withdrawn:** a source says the measure is ineffective or not a workaround. Never recommend it; warn about it.
- **No documented mitigation** is a valid, honest answer: recommend patching or isolating the machine.
