# Domain Admin takeover map — PoC roadmap and commands

- [x] Add per-technique PoC roadmaps and usable command templates (verify + authorized assessment)
- [x] Substitute scan evidence, domain, and DC into command templates
- [x] Render PoC + commands in the Domain Admin takeover HTML tab
- [x] Localize narratives, PoC steps, and command labels in Turkish; keep commands intact
- [x] Cover both English and Turkish report output with tests
- [x] Update README description of the Domain Admin map

## Review

Domain Admin takeover map cards now include a detailed PoC roadmap (step / detail / expected evidence) and usable command blocks (finding verification + authorized assessment), with `{TARGET}`, `{DOMAIN}`, and `{DC_IP}` filled from the scan. Turkish mode (`--lan tr`) translates narratives, PoC text, and command labels via `reporting/domain_admin_takeover_i18n.py` while leaving command bodies paste-ready in English. Tests cover analyzer wiring, HTML rendering, and bilingual localization.
