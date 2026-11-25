# Security

## The model: it runs against your own local database

tenantbleed is a local tool. It connects only to a database you point it at, and it refuses
any target that is not loopback (`127.0.0.1`, `localhost`, `::1`). The probes create test
users and insert, update and delete rows, so you must run it against a local dev or staging
database, never production.

The UI server binds to `127.0.0.1` only and gates every API call behind a per-session token
carried in the URL it opens, so no other process (local or remote) can drive a scan. Nothing
is sent off the machine: there are no accounts, no telemetry, and no network calls to any
tenantbleed service.

tenantbleed pauses scheduled jobs (`pg_cron`) during a scan so a job cannot change the test
data or fire outbound requests mid-scan, and turns them back on afterwards.

## Reporting a vulnerability

If you find a security issue in tenantbleed itself, please report it privately through this
repository's GitHub Security Advisories ("Report a vulnerability"), or by email to
kelvu.sec@gmail.com, rather than opening a public issue. We will acknowledge and work with
you on a fix and disclosure timeline.

Please do not use tenantbleed against applications you do not own or are not authorized to
test. It is built to test your own app.
