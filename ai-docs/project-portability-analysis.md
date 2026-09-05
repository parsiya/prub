# Project Portability and Identity Metadata

The normal JSON export and fields intentionally omitted from it are documented in `ai-docs/export-format.md`.
This note records what identity-like information was found in the four controlled schema-226 Burp project files and what remains unknown.

## Verified Root Metadata

Project-root descriptor `Zys` contains immutable string fields `0`, `6`, and `15`.

* Field `6` is the project display name. The project rename path writes this field.
* Field `15` is initialized from a random 20-character value. It differs in every controlled project and is treated as a per-project identifier.
* Field `0` is Burp's installation ID. `Zgaz.Zl` reads `installationId` through `Zpg6.ZT`; `Zpg6` prefixes the key as `burp.suite.installationId` and stores it under `Preferences.userNodeForPackage(StartBurp.class)`. If the value is absent or does not match `^[a-z0-9]{20}$`, Burp generates 20 random lowercase alphanumeric characters and writes the same preference key through `Zpg6.Zx`. Project creation/migration copies it into root field `0`. The parser exposes it as `installation_id`.
* Static update/download paths pass the installation ID separately from a license supplier. The installation ID is randomly generated and is not derived from the license owner, key, activation response, or entitlement.
* Header offset `16` contains a random 32-bit identifier that also travels with the file.

Observed values:

* Empty project: name `empty-project`, project ID `0s1cy72tm7ras1za8n0z`, installation ID `0kv7t3rw4hlqchbz0ilu`.
* Request-only project: name `2026-08-03-one-request`, project ID `xynn43yvy49vos2xiaky`, same installation ID.
* Request/response project: name `2026-08-03-request-response`, project ID `6vj0bxjpuzg2r3348fmy`, same installation ID.
* Repeater project: name `2026-08-030-repeater-both`, project ID `mudp8oxvxzmwhdykjij7`, same installation ID.

The installation ID is potentially linkable metadata across projects created under the same Burp user profile.

## Save-Copy Behavior
Static UI and writer paths show that Burp's save-copy flow can ask whether to include Dashboard and Collaborator IDs. These identifiers may therefore remain in a copied project depending on selected options. Their complete object locations are not yet mapped.

## Not Observed
No creator name, OS username, email address, original absolute project path, computer hostname, license key, registered owner, activation response, or entitlement record was found in the verified project-root fields or readable ASCII/UTF-16 strings of the four samples.

The project path is passed to storage open/create code for filesystem access, locking, and errors. No verified writer path stores that path in the project root.

## Limits
Absence from these controlled samples does not prove absence from every Burp project. HTTP traffic, project settings, Scanner state, imported configuration, and extension-owned project storage can contain arbitrary sensitive values. Treat `.burp` files as sensitive archives rather than anonymized exports.
