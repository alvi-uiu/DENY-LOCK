# Security Boundary

DENYLOCK evaluates only closed synthetic environments. The package contains no adapters for operating-system files, shell commands, payment providers, cloud APIs, browsers, email, or identity services.

Model endpoints receive synthetic scenario state. Authentication is read from an environment variable and excluded from all artifact writers. The endpoint must be an absolute HTTP or HTTPS URL. Use loopback binding for local inference and TLS for any non-local endpoint.

The policy engine uses fixed predicate implementations. It does not evaluate source strings, import generated modules, deserialize executable objects, or execute model-produced code. Model output is parsed as JSON and checked against exact tool schemas before preview.

Preview operates on a deep copy. Only an allowed tentative state becomes committed state. Unknown tools, extra arguments, invalid types, missing objects, insufficient balances, duplicate identifiers, relay cycles, and invalid schedules fail before commit.

A deployment that connects these interfaces to real systems would require transactional adapters, authorization, concurrency control, idempotency, compensation design, secret isolation, audit retention, and an analysis of effects that occur outside the mediated state. This repository does not supply or claim those properties.
