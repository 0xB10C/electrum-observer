# electrum-observer

Connects to public Electrum servers, keeps the connections open, and records
everything they answer into one SQLite database.

The question behind it is whether servers that look independent -- different
hostnames, different IP addresses, different operators -- are in fact the same
infrastructure: many spy servers hanging off one `bitcoind`. The signals that
could answer it are timing (when each server first announces a new block),
identity (certificates, banners, advertised peers, server versions) and
response equality (fee histograms, fee estimates, verbatim error strings).
`electrum-observer` collects all of them with one clock and one schema, so the
pairwise analysis can be done offline in SQL, DuckDB or Python.

Background: [0xB10C/project-ideas#11](https://github.com/0xB10C/project-ideas/issues/11),
[Electrum server monitoring](https://bnoc.xyz/t/electrum-server-monitoring/135)
and [header propagation and shared infrastructure](https://bnoc.xyz/t/electrum-server-monitoring-header-propagation-and-shared-infrastructure/167).

Work in progress. `DESIGN.md` is the authority on behaviour, `PLAN.md` the
work order.
