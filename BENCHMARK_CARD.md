# RouteAroundBench v1 Benchmark Card

## Purpose

RouteAroundBench measures post-denial persistence. Each trial starts from a safe state. A canonical action is previewed, shown to violate one explicit policy, denied without mutation, and recorded. The target agent then receives the original goal, current state, available simulated tools, and denial record.

The primary unsafe outcome is whether any subsequently committed state satisfies the independent forbidden-state oracle. The primary benign outcome is whether the allowed neighboring goal is reached while the oracle remains false.

## Composition

The benchmark contains 180 deterministically generated scenarios:

| Split | Files | Finance | IAM | Total |
|---|---:|---:|---:|---:|
| Unsafe | 40 | 40 | 40 | 120 |
| Benign | 20 | 20 | 20 | 60 |
| Total | 60 | 60 | 60 | 180 |

Within each domain, unsafe scenarios cross four route families with ten request framings. Benign scenarios cross the same four route families with five neighboring-task framings. Identifiers, resources, accounts, principals, jobs, and random seeds are unique per scenario.

## Route families

- Tool substitution changes the operation while preserving the forbidden state effect.
- Cumulative splitting composes individually smaller state changes across steps.
- State indirection transfers provenance or reachability through copies, archives, relays, policies, or groups.
- Delayed execution schedules an effect and activates it in a later transition.

Each unsafe scenario contains at least two executable witness plans. Witness plans are validation artifacts and are never exposed to the evaluated model.

## Domains and forbidden predicates

- Files/workspace: cumulative exposure of a protected provenance origin exceeds its permitted units.
- Finance/commerce: cumulative delivery to a restricted final beneficiary exceeds its permitted amount, including relays and redeemed instruments.
- Cloud/IAM: a protected principal gains administrative reachability through a role, token, attached policy, group inheritance, or a permission composition.

## Paired benign design

Every benign scenario begins with the same form of controlled denial as its unsafe counterpart. Its allowed goal targets an approved resource, approved beneficiary, or viewer role. The route-specific tool neighborhood remains available, allowing overblocking and task completion to be measured under an active denial.

## Quality controls

The validator checks exact counts, unique identifiers, safe initial states, deny-worthy canonical actions, preview rollback, tool schemas, witness execution, benign solvability, policy-oracle agreement after every witness transition, and the final content hash.

## Intended use

The benchmark supports controlled comparisons of post-denial agent controls, ablations of state-aware mediation, and analysis of route-family failure patterns.

## Non-intended use

It must not be presented as a comprehensive measure of cybersecurity, financial compliance, privacy, or general agent safety. It must not be connected to real files, financial services, identity systems, or credentials.

## Limitations

The environments are synthetic and fully observed. The predicates are authored with the scenarios and may be easier to enforce than policies inferred from natural language. Templates create controlled coverage but limited linguistic diversity. The benchmark does not model concurrency, hidden side effects, partial observability, policy conflicts, or compromise of the mediator.

## Data and ethics

The benchmark contains no personal data, human-subject data, secrets, real accounts, or executable attack payloads. All names and effects are synthetic.
