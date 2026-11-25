# tenantbleed documentation

| Document | For | Contents |
| --- | --- | --- |
| [Product docs](product/README.md) | Everyone | Overview, roadmap, market research, account management design, sales brochure. |
| [User guide](user-guide.md) | People using it | Setup as a GitHub Action or CLI, configuration, reading the report, severities, fixing, safety, FAQ. |
| [Developer guide](developer-guide.md) | Everyone working on product or code | Code map, build and bundles, test gates, the planted-case-first loop, rules.json, full runs and how to analyse them, debugging, Docker capacity, lab safety. Current state: [project_meta.md](../.claude/project_meta.md). |
| [Architecture](architecture/README.md) | Contributors, reviewers, technical buyers | System context and deployment modes, components and bundles, the scan pipeline, data contracts, the engine and judge in depth, safety and threat model, quality gates, operations, decision log, limits and known issues. |
| [How it works](how-it-works.md) | Technical readers | Every stage of a scan: introspection, test users, building test data, the constraint solver, ownership, probes, cleanup. |
| [Rules](rules.md) | Reviewers, support, contributors | Every finding kind and severity, every precision rule and why it exists, what is never a finding, ownership and coverage rules. |
| [Validation](validation.md) | Anyone deciding whether to trust it | The planted test app, the 39-app field test, regression process, comparison with other tools, false-positive patterns fixed, known gaps, safety rules. |
