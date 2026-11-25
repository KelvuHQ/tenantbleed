# tenantbleed: market and landscape research

Landscape brief for an open-source tool: where tenantbleed sits, who has the problem, and what else exists. Date: 2026-11-17.
Method: read-only web research. Every claim is tagged with a source number from the Sources list at the end. Tags:
- **[n]** = page opened and read for this report.
- **[s:n]** = seen only in a search-result summary, not opened (treat as weaker).
- **(approx., memory)** = from prior knowledge, not verified today.
- **(assumption)** = my estimate, shown so it can be challenged.

---

## 1. Summary

**The technical edge is genuine and rare.** As far as I could find, nobody else proves authenticated cross-tenant bugs in Supabase apps deterministically, locally, in under a minute. The two players closest to this space are both platform-native: Supabase (planned "security test harness" for 2026, RLS Tester in preview) and Lovable (scans on every publish, plus a $100 AI pentest from Aikido that already "validates exploitability" and tries to reach other users' data). tenantbleed is complementary: free, local, deterministic, and run by the builder on their own machine.

The people with the sharpest version of the problem (non-technical AI-app builders) are the least likely to run a command-line tool; the more technical multi-tenant teams and agencies are the natural first users. The authenticated logic-bug class tenantbleed targets is real (the field test proved 106 such bugs in 31 apps) but under-reported in the press, which still focuses on the anonymous, RLS-off class. A public benchmark is the clearest way to make that class visible.

**Top numbers**
| Metric | Value | Source |
| --- | --- | --- |
| Supabase developers | 4M+ (Oct 2025), 4.5M+ (Sep 2025), 9M+ (Jun 2026) | [1][s:3], [3], [2] |
| Supabase funding | $100M Series E at $5B pre (Oct 2025); $500M Series F at $10.5B (Jun 2026) | [1], [2] |
| Supabase paying customers / ARPC | ~250K paying, ~$700/yr per customer, ~$170M ARR May 2026 (estimates) | [4] |
| AI share of new Supabase databases | >60% launched by AI agents (estimate) | [4] |
| New Supabase databases | 40,000+ per day (Sep 2025) | [3] |
| Lovable | 100,000 new apps/day, 25M projects, $300M+ ARR at the time; ~$400M ARR Feb 2026 [s:9] | [16], [s:9] |
| Lovable apps leaking via Supabase | 24,664 of 34,545 Supabase-backed Lovable sites sent DB records on page load without login; 7,403 sites exposed tables with email addresses (Dec 2025 to Sep 2026 sample) | [9] |

---

## 2. Market: demand signals and incidents

### Supabase scale
- Series E, Oct 2025: $100M at $5B pre-money, led by Accel and Peak XV [1]. Fortune and others reported "over four million developers" [s:3].
- Lovable Cloud launch post, 29 Sep 2025: "over 4.5 million developers", "more than 40,000 new databases are launched on Supabase every day", and every Lovable Cloud project runs on Supabase [3].
- Series F, Jun 2026: $500M at $10.5B, led by GIC; "more than 9 million developers"; Supabase for Platforms customers grew 370% in six months [2].
- Sacra estimate (Jun 2026, third-party, not company-disclosed): ~$170M ARR in May 2026, 250K+ paying customers out of ~10M registered (about 2.5%), ARPC flat at ~$700/yr, and AI coding agents launch over 60% of new databases. Lovable and Bolt white-label Supabase through Supabase for Platforms; Replit chose Neon [4].

**So what:** the platform is huge and growing, and AI tools are now its main source of new databases, which is exactly where cross-tenant isolation bugs are generated at scale.

### AI app builders
- Lovable: 25M projects, 100,000 new apps per day, $300M+ ARR, $6.6B valuation (as cited by Aikido, Mar 2026) [16]. Later secondary reports put Lovable at ~$400M ARR (Feb 2026) and ~$500M (Jun 2026) [s:9], [4].
- Not every Lovable app uses Supabase directly: in Crissy Field's sample, 34,545 of 159,041 Lovable projects (22%) used Supabase. Lovable's own database (Lovable Cloud, itself Supabase underneath) was not examined [9].
- Bolt: no first-party security scan found in search results [s:12]. Replit uses Neon, not Supabase [4].

### Documented incidents (the fear market is real)
| Date | Incident | Root cause | Type | Source |
| --- | --- | --- | --- | --- |
| Mar to May 2025 | CVE-2025-48757: 303 endpoints in 170 Lovable apps exposed (emails, phone numbers, payment status, API keys) | Missing or weak RLS, reachable with the public anon key | Anonymous | [5] |
| Jul 2025 | Tea app: ~72,000 images including ID photos leaked | Open Firebase storage bucket | Anonymous | [s:14] |
| Oct 2025 | Escape scanned 5,600 vibe-coded apps (4,000+ Lovable): 2,000+ vulnerabilities, 400+ secrets, 175 PII exposures | Mostly missing RLS and exposed secrets; anonymous-only testing ("conservative baseline") | Anonymous | [6] |
| Jan to Feb 2026 | Moltbook: ~1.5M API tokens, 35K emails, 4,060 private DMs, unauthenticated write access | No RLS policies; fixing reads left writes open | Anonymous | [7] |
| Mar to Apr 2026 | Lovable platform BOLA: source code and Supabase credentials of other users' projects reachable; open 48 days | BOLA in Lovable's own API (not RLS) | Authenticated | [8] |
| Nov 2026 | Crissy Field / Handelsblatt: 24,664 Lovable sites sent DB records on load without login; passports, 200K+ chat messages | RLS off / permissive | Anonymous | [9], [10] |

**Disconfirming read:** almost every public incident is the *anonymous, RLS-off* class. That class is (1) already caught by Supabase's linter and alerts, a dozen free or $9 to $49 indie scanners, and Lovable's publish scan, and (2) being closed at the root: Supabase stopped auto-exposing new `public` tables to the Data API (default for new projects 30 May 2026, applied to all projects 30 Oct 2026), and dashboard tables get RLS on by default [11][12]. tenantbleed's real differentiator is the *authenticated logic bug* class (wrong `WITH CHECK`, join-any-workspace, impersonation, definer functions with no caller check). I found **no public breach story driven by that class in Supabase apps.** It is real (the field test proved 106 such bugs in 31 apps), but it is not yet what the headlines are about. tenantbleed would have to make that market through content, not ride an existing panic.

### How many apps are in scope (bottom-up, assumptions shown)
| Layer | Count | Method |
| --- | --- | --- |
| All Supabase developers | ~10M Supabase developers [2][4] | Registered, mostly free hobby projects |
| Paying Supabase accounts | ~250K [4] | Sacra estimate |
| Accounts with a multi-user app and migrations in Git | ~40K to 75K | 250K x 15 to 30% (assumption). The field test's 79% buildable rate (31/39) is on hand-picked repos; Lovable repos have known duplicate and timestamp migration problems [s:15], so the real rate is lower and **must be measured** (see open questions, section 7). |

**So what:** a large and growing population of multi-tenant Supabase apps is being generated faster than their builders can review the policies.

---

## 3. Competition

### Matrix
| Player | What it does | Proves exploits? | Authenticated cross-tenant? | In CI, pre-merge? | Price |
| --- | --- | --- | --- | --- | --- |
| **tenantbleed** | Two real users + anon attack a local stack built from migrations; DB-confirmed; rollback; fix PRs (prototype) | Yes, deterministic | Yes (reads, writes, inserts, functions, storage, GraphQL) | Local, ~30 to 50 s | Free, open source |
| Supabase Security Advisor (splinter) | Static lints, weekly emails, dashboard fixes, RLS-off alerts; CLI `db advisors` | No | No | Possible via CLI; `--fail-on` defaults to none [s:13], [13] | Free |
| Supabase RLS Tester (preview, Apr 2026) | Run a SELECT as anon or a chosen user in Studio, see which policies evaluated; AI converts client calls to SQL; mutations excluded; a pglite sandbox for mutations is in an open PR [s:16] | No (manual tool) | Manual, one query at a time | No | Free |
| Supabase planned "security test harness" (2026 roadmap) | "Validating RLS policies and authorization logic before deployment" | Unknown | Likely | Likely | Free (presumably) |
| Lovable basic scan | Every publish, 10 to 15 s; config, schema, RLS, exposed data; can block publish | No (checks RLS existence) | No | At publish | Free, all plans [15] |
| Lovable deep scan | AI code review, 2 to 4 min | No | Reasons about logic | On demand | Free on demand; scheduled is Enterprise [15] |
| **Aikido pentest inside Lovable** (Mar 2026) | AI agents attack the live app; "access to other users' data"; "validate exploitability through real exploitation"; Supabase + edge functions in scope | **Yes (claimed)** | Yes (greybox with credentials) | No, live app, 1 to 4 hours | **$100 per test** (launch offer) [16][17] |
| Aikido platform | SAST, SCA, DAST, IDOR detection in Attack module, AI pentests | Pentests yes | IDOR claimed | Partly | Free (2 users); Basic $300/mo; Pro $600/mo; pentest $50 to $30K+ [18] |
| Escape | Business-logic-aware DAST, AI pentest agents, proof of exploitation; 100+ enterprise customers; $18M Series A Mar 2026 | Yes | Business logic (unspecified) | Yes | Custom, sales-led [19][20] |
| StackHawk | DAST for APIs in CI | Partial | Not named | Yes | Wingman $10/user/mo; Scale custom [21] |
| Snyk | SAST/SCA; API and Web DAST and AI pentesting in Enterprise credits | Enterprise only | Not named | Yes | Free; Team from $25/mo; Enterprise credits [22] |
| Semgrep | SAST, supply chain; no IDOR claim | No | No | Yes | Free to 10 contributors; Teams $30/contributor/mo [23] |
| Akto | Was API/BOLA testing; pricing page now sells AI agent security | No (in field test, ~2 of 18) | Templates from traffic | Heavy | Enterprise usage-based [24] |
| OWASP ZAP, Burp | Generic DAST / manual proxy | No (0 of 18 in field test) | Manual (Burp) | ZAP yes | Free / Burp Pro (approx., memory: ~$475/yr) |
| Indie Supabase scanners (RLS Watch, UNPWNED, VibeAppScanner, Argus, LeakScope, VibeScan, GuardLayer, Apify actor) | Anon-key probes of the live site, secrets, headers; some repo scanners and PR comments | Anon reads only | **No** (RLS Watch: read-only, limit 1, no logins [25]; UNPWNED: "does not inspect complete RLS ... authorization" [26]; VibeAppScanner tells you to write your own two-user tests [27]) | GuardLayer posts on PRs [13] | Free to ~$9 to $49 per scan or month [s:17] |
| DIY: pgTAP / `supabase test db`, supabase-test | Hand-written RLS tests, multi-user | Only what you write | Yes, manually | Yes | Free; supabase-test-suite has 24 stars [28] |
| "Do nothing" | Ship and hope; rely on Supabase's warnings | | | | $0. **Wins most deals.** |

### One-paragraph reads on the three that matter

**Supabase (the platform-native option).** Supabase's 2025 security retro (Jan 2026) lists for 2026: a "security-focused test harness" to validate RLS policies, more Advisor lints, an assistant that fixes issues from GitHub, and richer alerts [12]. The RLS Tester shipped as a preview in April 2026, SELECT only, with a sandbox for mutations being explored [14][s:16]. Nothing in the Jul to Nov 2026 changelog shows the harness shipping yet [29]. Supabase has every incentive to build this: incidents hurt its brand, and the Lovable Cloud deal makes builder app safety its problem. Expect a free, good-enough version within 12 to 18 months (assumption). The Integrations marketplace "Security" category has only one partner (CipherStash) [30], so a listing slot is open today.

**Lovable + Aikido (closest functional competitor for the vibe-coder buyer).** Lovable already runs a free scan on every publish and offers a $100 dynamic pentest that claims validated exploits, including "access to other users' data" [15][16][17]. It runs against the live app, takes hours and costs money each time, so tenantbleed is faster, free, local and never touches production. For a non-technical Lovable user, "click Pentest in the security tab" is easier than running a command-line tool; tenantbleed fits the more technical builder who works in a repo. The two approaches overlap but do not do the same thing: Aikido attacks a live app, tenantbleed proves isolation on a throwaway copy before anything ships.

**Escape (where "proven exploits" is heading upmarket).** Escape scanned 5,600 vibe-coded apps for content marketing [6], raised $18M on "AI agents replace pentesters" with proof of exploitation [20], and sells enterprise-only [19]. It shows that "proof, not warnings" is a fundable message, but also that the well-funded players own that phrase in the enterprise.

**So what:** tenantbleed's defensible gap is narrow and specific: *deterministic, pre-merge, authenticated cross-tenant proof for Supabase, with a verified fix.* No competitor I found does all of these. The gap is being closed from above (AI pentests getting cheaper: Aikido's rightsized pentests start at $50 [18]) and below (Supabase native tooling).

---

## 4. Who it is for

### Segments and fit
| Segment | Pain | Works in a repo / CLI? | Fit for tenantbleed |
| --- | --- | --- | --- |
| Vibe coders / non-technical founders (Lovable, Bolt) | Highest (cannot read a policy) | Rarely; work inside the builder | Weak direct fit; reached better through the builder itself or a technical teammate |
| Indie devs and small startups on Supabase, pre-SOC2 | Medium; usually only after a scare or a customer questionnaire | Yes | Natural users: free, local, runs on their own machine |
| Agencies building Supabase apps for clients | Real: liability on client data, need proof for handover | Yes | Strong fit: the evidence export is a client-handover artifact |
| Seed to Series A SaaS on Supabase (Team plan [31]) | Enterprise questionnaires, SOC 2 | Yes | Use the proofs as evidence for security reviews, alongside Aikido/Snyk/Semgrep bundles [18][22][23] |
| AI builders (Lovable, Bolt) | Brand and liability; repeated incidents [5][8][9] | n/a | Could run a local proof on generated apps; Lovable already ships an Aikido pentest |

### Pricing of other tools (landscape, for context)
- Snyk Team from $25/mo; Semgrep Teams $30/contributor/mo (free to 10 contributors); StackHawk Wingman $10/user/mo; Aikido free for 2 users, then $300/mo flat [18][21][22][23].
- Per-test: Aikido x Lovable $100 per pentest; Aikido rightsized pentests $50 to $30K+; traditional pentest $5K to $50K (Lovable's framing) [16][18].
- Indie Supabase scanners: free to ~$9 per scan, $29 full scan, ~$49/mo [s:17].
- Supabase itself: Free, Pro from $25/mo, Team from $599/mo [31].

**So what:** tenantbleed is free and open source, so it sits below all of these on cost and runs entirely on the user's machine. The point of the landscape above is to show what builders already reach for, and where a free local proof fills a gap none of them covers: deterministic, authenticated cross-tenant proof before anything ships.

---

## 5. Adoption

### How builders would find and start using it
1. **The benchmark as content (after responsible disclosure).** "We built 31 open-source Supabase apps and proved isolation bugs in 12; the linters raised 2,498 warnings and proved none" is a strong, unusual, data-backed story. Escape [6], Wiz [7] and Crissy Field [9] show this format earns press (Handelsblatt [10]) and Hacker News. tenantbleed's angle is new: *logged-in* users attacking each other, which none of the published studies tested (Escape and Crissy Field were anonymous-only [6][9]).
2. **Supabase community** (Discord, r/Supabase, GitHub Discussions) with a two-minute "install and run" guide. Free, and the target user lives there.
3. **Supabase Integrations listing, Security category** (only one partner today [30]). A credibility signal and a way to be found by the right builders.
4. **Agencies:** through Supabase partner and agency directories; the evidence export is a client-handover artifact.
5. **AI builders:** a local proof that runs on generated apps. Slow and political (Aikido is incumbent at Lovable [16]); the opening is data from their own users' public repos.

### Biggest risks to adoption
| Risk | Likelihood | Impact | Response |
| --- | --- | --- | --- |
| Supabase ships a native RLS test harness (on its 2026 roadmap [12]) | High | High: free and built-in reaches the long tail | Stay the deeper layer (writes, functions, storage, fix verification); a neutral cross-stack proof is where the long-term value is |
| AI pentests get cheap and good enough ($50 to $100 now [16][18]) | High | Medium: they claim proof too | Different shape: deterministic, local, seconds, no production traffic, repeatable before anything ships |
| The headline problem is shrinking (no auto-exposed new tables since Oct 2026 [11]) | Certain | Medium: anon-leak fear is the hook | Lead with authenticated logic bugs; do not build the story on "RLS off" |
| Repo fit: Lovable migrations have duplicates and timestamp clashes [s:15]; 8 of 39 field-test repos would not build | Medium | High for the vibe-coder segment | Measure on Lovable-synced repos (open question 1); improve the build step |
| Liability of auto-fix PRs | Medium | Medium | The rightful-owner check is a real mitigation (rejected the naive fix); keep humans merging, no production apply; ship fixes as "suggested" before "auto" |
| Responsible-disclosure / legal exposure from the corpus | Low if handled | High | Finish private disclosures before any publication; describe apps by type only |

---

## 6. Where tenantbleed fits

- The defensible gap is narrow and specific: deterministic, local, authenticated cross-tenant proof for Supabase, with a verified fix. No competitor found does all of these.
- The anonymous RLS-off class that drives the headlines is being closed at the root by Supabase and covered by many free tools. tenantbleed's value is the authenticated logic-bug class, which the field test proved is real and which no published study tested.

As a free, open-source, local tool, success is measured in adoption and reputation, not revenue: builders running it on their own apps, a public benchmark that makes the logic-bug class visible, and agencies using the evidence export.

---

## 7. Open questions (how to answer them)

| # | Question | How to answer | What a good signal looks like |
| --- | --- | --- | --- |
| 1 | **Repo fit on AI-builder output.** Do Lovable/Bolt-synced repos build and show proven bugs? | Find 50 public GitHub repos synced from Lovable or Bolt with `supabase/migrations`; run tenantbleed locally (same safety rules as the field test). Measure buildable %, multi-user %, proven-bug %. | >= 60% build, >= 25% have a proven medium+ bug |
| 2 | **Does the benchmark land?** | After disclosures, publish method, numbers, anonymized cases; HN, r/Supabase, Supabase Discord. | Installs and sustained use; press pickup |
| 3 | **Do agencies find it useful for handover?** | Interviews: "walk me through the last client app you handed over; how did you check data isolation?" | They would use the evidence export in a handover |
| 4 | **Is a platform pilot possible?** | Apply to the Supabase Integrations Security category [30]; share the benchmark with Supabase's security team and one builder. | One technical pilot agreed |

---

## If this holds, then we should:
- Finish private disclosures, then publish the authenticated-attack benchmark; it is the evidence nobody else has.
- Keep the tool free, open source and fully local; no accounts, no hosted service, no billing.
- Answer the open questions above before investing heavily in any one direction.
- Describe tenantbleed as "proof of tenant isolation, locally, before production", never as an "RLS-off scanner" (crowded, free, and shrinking).

---

## Data gaps (not speculated; how to collect)
- **Share of paying Supabase projects that are multi-tenant with migrations in Git:** no public data. Collect via open question 1 and a GitHub code search for `supabase/migrations` repos.
- **Agency count and use of Supabase:** no public directory size found. Collect via Supabase partner pages and interviews.
- **Scope and accuracy of Lovable's Aikido pentest on cross-tenant bugs:** not public; Lovable did not disclose test scope [s:18]. Collect by running both on the planted test app (a head-to-head would also be strong content).
- **Supabase's timeline for the test harness:** not public [12][29].
- **Authenticated cross-tenant breach stories:** none found for Supabase apps; this is why the benchmark matters, to make the class visible.

---

## Sources

Opened and read for this report (accessed 2026-11-17):
1. Supabase, "Supabase Series E" blog (Oct 2025): https://supabase.com/blog/supabase-series-e
2. Orrick, "Supabase Raises $500 Million at $10.5 Billion Valuation" (8 Jun 2026): https://www.orrick.com/en/News/2026/06/Supabase-Raises-500-Million-at-10-5-Billion-Valuation-to-Accelerate-Lead-in-Agentic-Infrastructure
3. Supabase, "Lovable Cloud + Supabase: The Default Platform for AI Builders" (29 Sep 2025): https://supabase.com/blog/lovable-cloud-launch
4. Sacra, "Supabase at $170M/year growing 221% YoY" (11 Jun 2026, third-party estimates): https://sacra.com/research/supabase-170m-year-growing-221-yoy/
5. Superblocks, "Lovable Vulnerability Explained: How 170+ Apps Were Exposed" (vendor blog): https://www.superblocks.com/blog/lovable-vulnerabilities
6. Escape, "Methodology: How we discovered over 2k high-impact vulnerabilities in apps built with vibe coding platforms" (29 Oct 2025): https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/
7. Wiz, "Hacking Moltbook" (2 Feb 2026): https://wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys
8. The Next Web, "Lovable left thousands of projects exposed for 48 days" (Apr 2026): https://thenextweb.com/news/lovable-vibe-coding-security-crisis-exposed
9. Crissy Field GmbH, Lovable research (Nov 2026): https://crissyfield.de/research/lovable-en/
10. Kunal Ganglani, "Lovable AI Data Leak: 200K Messages Exposed" (14 Nov 2026, secondary): https://www.kunalganglani.com/blog/lovable-ai-app-data-leak
11. Supabase changelog, "Breaking change: tables not exposed to Data and GraphQL API automatically": https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically
12. Supabase, "Supabase Security Retro: 2025" (Jan 2026): https://supabase.com/blog/supabase-security-2025-retro
13. GuardLayer, "supabase db advisors" article: https://www.guardlayer.io/blog/supabase-db-advisors
14. Supabase changelog, "Feature Preview: RLS Tester" (24 Apr 2026): https://supabase.com/changelog/45233-feature-preview-rls-tester
15. Lovable, "How Lovable protects your apps automatically" (1 Jun 2026): https://lovable.dev/blog/how-lovable-protects-your-apps-automatically
16. Aikido, "Lovable x Aikido pentesting" (Mar 2026): https://aikido.dev/blog/lovable-aikido-pentesting
17. Lovable, "Announcing pentesting" (24 Mar 2026): https://lovable.dev/blog/announcing-pentesting
18. Aikido pricing: https://www.aikido.dev/pricing
19. Escape pricing: https://escape.tech/pricing
20. The Next Web, "Escape raises $18M to replace pen-testers with AI agents" (10 Mar 2026): https://thenextweb.com/news/escape-18m-series-a-ai-security-vibe-coding
21. StackHawk pricing: https://www.stackhawk.com/pricing/
22. Snyk plans: https://snyk.io/plans/
23. Semgrep pricing: https://semgrep.dev/pricing
24. Akto pricing: https://www.akto.io/pricing
25. EveryDev listing, RLS Watch: https://www.everydev.ai/tools/rls-watch
26. UNPWNED, Lovable platform page: https://unpwned.io/platforms/lovable
27. VibeAppScanner, Supabase RLS page: https://vibeappscanner.com/supabase-row-level-security
28. GitHub, launchql/supabase-test-suite: https://github.com/launchql/supabase-test-suite
29. Supabase changelog (entries Jul to Nov 2026): https://supabase.com/changelog
30. Supabase Integrations marketplace: https://supabase.com/partners/integrations
31. Supabase pricing: https://supabase.com/pricing

Seen only in search-result summaries (not opened; weaker evidence):
- s:3. Fortune, "Exclusive: Supabase raises $100 million at $5 billion valuation as vibe coding soars" (Oct 2025), "four million developers": https://fortune.com/2025/10/03/exclusive-supabase-raises-100-million-at-5-billion-valuation-as-vibe-coding-soars
- s:9. TechDogs and others on Lovable $400M ARR (Feb 2026): https://www.techdogs.com/tech-news/td-newsdesk/lovable-hits-400m-arr-in-february-adds-100m-in-a-month-with-146-employees
- s:12. Third-party commentary on Bolt, Replit and v0 security (no first-party scan found): https://vibeappscanner.com/bolt-vs-replit-security
- s:13. Third-party notes on `supabase db advisors` CLI flags (also in [13])
- s:14. Tea app breach coverage (Jul 2025): https://www.engadget.com/cybersecurity/tea-app-suffers-breach-exposing-thousands-of-user-images-190731414.html
- s:15. Supabase CLI issue on Lovable migration timestamp clashes: https://github.com/supabase/cli/issues/4406
- s:16. Supabase GitHub PR #45839 (pglite sandbox for RLS Tester mutations), via search summary of https://github.com/orgs/supabase/discussions/45233
- s:17. Indie scanner listings with prices (Argus, VibeScan, Apify actor): https://www.producthunt.com/posts/argus-app-scan-for-vibe-founders, https://vibescan-qyu1.vercel.app/, https://apify.com/renzomacar/supabase-rls-scanner
- s:18. createwith.com coverage noting Lovable did not disclose pentest scope: https://www.createwith.com/tool/lovable/updates/lovable-partners-with-aikido-to-offer-real-world-pentesting-for-app-builders
