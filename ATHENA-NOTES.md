# Athena notes

Append-only log of what Athena looked at and changed in this repository.

## 2026-11-03 — dependency floors for body-parser, compression, morgan, sequelize

Looked at `package.json` (dependencies block), `server.ts` (global `app.use` of `compression()`, `bodyParser.urlencoded`, `bodyParser.text({ type: '*/*' })`, `morgan('combined')`), the `Dockerfile` (`npm install --omit=dev` with no lockfile) and the root tree (no `package-lock.json` committed). Ruled out: none of the four packages is part of a Juice Shop challenge, and the first fixed release of every advisory lies inside the caret range already declared, so raising the floor changes nothing about what a fresh install resolves to today. Changed: raised the manifest floors to `body-parser ^1.20.9` (GHSA-27r3-jxmh-p828 / CVE-2026-111181, GHSA-v422-hmwv-36x6), `compression ^1.8.2` (GHSA-vc2v-76pw-4v95), `morgan ^1.12.1` (three log-forging advisories in the `combined` format), `sequelize ^6.37.8` (GHSA-6457-6jrx-69cr), so that no install, however old its registry snapshot, can satisfy the manifest with a vulnerable version; added `test/server/dependencyFloors.unit.test.ts`, which fails on the previous floors and passes on the new ones. The sandbox could not install dependencies in this sitting, so the suite was not run here; the repository's own CI runs it on the pull request.
