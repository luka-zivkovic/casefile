> **Resolved 2026-08-12: the product is named `casefile` — the scan report is an evidence dossier; `casefile scan`/`casefile history` read naturally at a terminal; bare npm name was available.**

# Naming shortlist

"skill-guard" is the working name. It's descriptive but generic, "guard" is overused in security
tooling, and it boxes the product into *skills* when the real scope is skills + plugins + MCP
servers (any agent capability you install). Pick a real name before going public.

## What the name has to fit

- The artifact is broader than skills: **agent capabilities** (skills, plugins, MCP servers).
- The verb is **verify before you trust / install** — an `npm audit` for agent capabilities.
- It's a CLI you run locally and in CI. Short, typeable, memorable at a terminal.
- Needs a clean npm name and a findable domain. Avoid collisions with existing security products.
- Sits in an ecosystem of working-name siblings (ironside, coeval, release-layer) — a real word or
  coined term fits that house style better than another `X-guard`.

## Candidates

Grouped by angle. Check npm + domain + GitHub availability before committing to any.

### Provenance / trust
- **Attest** — you get an attestation for a capability before installing. Clean verb, strong in the
  supply-chain space. (Check overlap with in-toto/sigstore "attestation" — could be feature-name
  confusion.)
- **Vouch** — "vouch for this plugin." Warm, short, human. Possible collisions (there's an auth
  proxy named Vouch).
- **Warrant** — a warranty for a capability; also the legal "basis." Slightly heavy.

### Inspection / X-ray
- **Lumen / Lumin** — bringing capabilities into the light; pairs tonally with your other names.
  Lumen is heavily used elsewhere, check hard.
- **Facet** — inspecting each face of an artifact. Short, neutral, likely-available-ish.
- **Assay** — to test the composition of something (metallurgy/chemistry). Precise, uncommon,
  memorable, and literally means "determine what this is made of." Strong CLI verb: `assay scan`.

### Gate / checkpoint (fits the CI story)
- **Checkpoint** — overused/trademarked (Check Point the firewall company). Avoid.
- **Portcullis** — the gate you lower before letting something in. Distinctive, on-theme with the
  ironside/fortress vibe, but long to type.
- **Ward** — to ward off; also a protected area. Short, clean, but "guard"-adjacent.

### Coined / neutral (best fit for the sibling house style)
- **Skald** — not literal, but short, ownable, Norse-flavored like "ironside." Weak semantic tie.
- **Bevel** — a machined edge; neutral, short, available-feeling. No baggage.
- **Plumb** — to measure the depth/soundness of something ("plumb the depths"), and a plumb line is
  a trueness check. Short, real verb, on-meaning, great CLI feel: `plumb scan ./plugin`.

## Recommendation

Top three to check for availability, in order:

1. **Assay** — the meaning is exactly the product (determine what this is made of), it's a clean CLI
   verb, and it's uncommon enough to likely be ownable.
2. **Plumb** — trueness/soundness check, short, memorable, on-theme.
3. **Facet** — safe, neutral, inspection-flavored if the first two collide.

Avoid: anything ending in `-guard`/`-shield`/`-sentinel` (crowded), Checkpoint (trademark), and
Lumen (heavily used).

Next step: run npm/domain/GitHub/trademark checks on the top three and lock one before the repo
goes public.
