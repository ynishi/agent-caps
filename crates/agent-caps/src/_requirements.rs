//! The requirements ledger: the use cases, the principles and the functional requirements of
//! agent-caps, in one place.
//!
//! This module is for reading. Its items are outside semver and may change in any release; do
//! not depend on them. The leading underscore says so, as it does for a tutorial module.
//!
//! ```text
//! use cases ──cite──▶ requirements ◀──cite── principles (in the requirement text)
//!                          ▲
//!                          │ cited by `UC<n>` and `FR<n>` in the doc comments of tests and code
//!                     tests/requirements.rs checks the ledger and every citation
//! ```
//!
//! # How to read this ledger
//!
//! - A use case says who wants what, in one or two sentences, and lists the requirements it
//!   needs. A use case cites only requirements that are supported or still undecided.
//! - A principle is a rule the requirements are derived from.
//! - A requirement is one thing agent-caps does, or does not do. Its decision and the layer
//!   that owns it are columns; a condition that goes with the requirement (for example, a
//!   calibration record before Force) and whether an operation needs an approver,
//!   which follows from the principles, are in its text.
//! - The legend of every value is the documentation of the variants of [`Decision`],
//!   [`Status`] and [`Layer`]. A cell holds one of those words and nothing else.
//!   A withdrawn row may name its successor after the word, written `-> <ID>`.
//! - `Issues` lists the issues related to a requirement, as plain references such as `#12`
//!   separated by `,`, and may be empty. They say where to read more; they say nothing about
//!   whether any work is done or open.
//! - Every test of the core's behavior cites at least one use case or requirement in its doc
//!   comment, and `cargo test` fails otherwise.
//!
//! # How to change this ledger
//!
//! - A row is never deleted. A row that no longer holds is withdrawn, and points at its
//!   successor when there is one. This holds for use cases, requirements and principles alike.
//! - The same row may be changed for wording, and for its decision, layer and issues.
//!   When the meaning of a requirement changes, withdraw the old row with
//!   `withdrawn -> FR<new>` and add a new row: a test or a piece of code that cites the old
//!   requirement is then pointed to the new one, where silently changing the meaning would
//!   leave the citation standing on a different requirement.
//! - Tests and code cite `UC<n>` and `FR<n>` in their doc comments and never `P<n>`: the
//!   principles are reached through the requirements. The doc comment of the `#[test]` function
//!   that checks a requirement is the place to cite it; listing citations in a module doc leaves
//!   no way to tell which test checks which requirement.
//! - An id is never changed and never reused. Use cases, requirements and principles are each
//!   numbered from 1 without gaps.
//! - A branch that adds rows takes the numbers after the last one on `main`, and renumbers its
//!   own additions just before it lands (never a number already on `main`), fixing its own
//!   citations in the same commit. Do not cite a number from another branch before it has
//!   landed.
//! - A table cell holds no square bracket, which rustdoc would read as a link.
//!
//! # Use cases
//!
//! | ID | Use case | Status | Requirements |
//! |---|---|---|---|
//! | UC1 | A developer lets an agent implement a change and wants no untested change committed; a test result that has not arrived does not count as a pass. | active | FR1, FR20, FR53 |
//! | UC2 | A developer wants the agent stopped once when it tries to end a turn without running the tests, but let through when it insists, so that it is never held forever. | active | FR1, FR41 |
//! | UC3 | A developer whose transcript gets cut or unreadable wants every rule to fall back to the stopping side, with the reason shown as unknown, and a fact already seen to stay seen within an interval known not to have restarted. | active | FR20 |
//! | UC4 | A developer wants nothing the agent writes in its transcript to loosen the rules: a mode switch or an exemption takes effect only from the developer or from caps itself. | withdrawn -> UC25 | |
//! | UC5 | A developer wants a hard line, such as never creating a public repository, stopped before the tool runs, and not removable by any layer, mode or exemption. | active | FR1, FR14 |
//! | UC6 | A developer wants to lift one guard for a bounded time on a given target, such as one file for one task, with a reason, and to have it return afterwards. | active | FR34, FR55 |
//! | UC7 | A developer with many repositories keeps shared best practices as a set and changes only the level or the on and off state of a policy per project. | withdrawn -> UC27 | |
//! | UC8 | A developer wants a stronger rule while fixing a bug and a weaker one while exploring, by switching the kind of work, from the next judgment on. | active | FR11 |
//! | UC9 | A developer wants a recommendation to stay within the guard that binds it: it is never stronger than that guard, goes when the guard is off, and not following it is not a failure. | active | FR13 |
//! | UC10 | A developer wants a policy that nothing can change during a run, whatever the layer, mode or exemption. | active | FR14 |
//! | UC11 | A developer who uses several platforms wants a rule that a platform cannot enforce to be lowered to what it can do, and to see what was lowered. | active | FR40 |
//! | UC12 | A developer wants a stopping rule never to take effect without examples of what it stops and what it lets through, all checked when the rule is accepted. | active | FR2 |
//! | UC13 | A developer wants the agent advised to read a design document before editing an area, and not stopped if it does not, with following the advice recorded. | withdrawn -> UC28 | |
//! | UC14 | A developer wants a rule that holds only inside one role, such as a reviewer sub agent that must not edit, and that stops when the role is unknown. | active | FR1, FR38 |
//! | UC15 | A developer wants a procedure recommended in order, such as test then lint then commit, with only the key step enforced, starting afresh for each task. | active | FR1, FR13 |
//! | UC16 | A developer running an improvement loop wants the turn held until the last measured score is high enough, and not passed because an earlier score was. | active | FR1, FR41 |
//! | UC17 | A tool that builds hooks and instructions wants the list of policies in effect with their levels, telling off apart from in effect but not matching the current event. | active | FR12, FR40 |
//! | UC18 | An adapter wants to learn from one place in a judgment whether it stops before the action or at the end of the turn. | withdrawn -> UC24 | |
//! | UC19 | An agent working on a long task adds a rule of its own from what it has learned, which tightens only, needs no approval, and is gone when the task ends. | active | FR16 |
//! | UC20 | An agent removes or weakens a rule it added itself, but never ends up looser than the developer's rules. | active | FR18 |
//! | UC21 | An agent tightens the mode of work on its own, while loosening it stays with the developer. | active | FR11 |
//! | UC22 | An improvement loop proposes level adjustments from the record of judgments: tightening ones enter on their own and loosening ones are only proposed to the developer. | active | FR24 |
//! | UC23 | A developer wants a rule that code cannot express, such as a commit message that explains its reason, judged by a classifier whose answers are recorded and replayable. | active | FR26, FR36 |
//! | UC24 | An adapter decides which platform mechanism stops a rule from the rule's level and from the event it judges, an action or the end of a period, and not from a timing the policy carries. | active | FR40, FR31 |
//! | UC25 | A developer wants nothing written by one below them to loosen the developer's rules: a mode switch, an exemption or a record a rule reads (a judgment, a score) that loosens a rule takes effect only from one who covers the rule's author; one that only tightens takes effect from anyone. | active | FR11, FR34, FR41, FR55 |
//! | UC26 | A developer wants limits on the agent, such as at most N pushes since the last review or per task, that the agent cannot start over by its own acts. | active | FR54, FR45, FR47 |
//! | UC27 | A developer with many repositories keeps shared best practices as a set and strengthens them per project with the project's own set; a shared rule is weakened for one project only by a version of the shared set that its owner gives that project. | active | FR42, FR48, FR49 |
//! | UC28 | A developer wants the agent warned, and not stopped, when it edits a file of an area without having read the area's design document within the task, with the warning recorded; the document itself reaches the agent's context through the platform. | active | FR1, FR51 |
//!
//! # Principles
//!
//! | ID | Principle | Status |
//! |---|---|---|
//! | P1 | A tightening operation needs no approval from anyone, the agent included: leaning to the stopping side costs only a stopped task, which returns to the user. The exception is a rule whose judgment is uncertain, such as a classifier: it becomes Force only with a calibration record of its false stops, because an uncertain rule that keeps stopping keeps returning the task to the user. | active |
//! | P2 | A loosening operation is decided by who wrote what it loosens: only one who covers the author, the author itself or one above it, may loosen it. What came from the user, the root of the hierarchy, is loosened only by an approver who covers it; the agent, below the user, loosens only what it added itself, never below the rules of those above it, and for those it only proposes. | active |
//! | P3 | A Meta policy does not change during a run, by any operation. | active |
//! | P4 | A temporary change always has a period and reverts when it ends. What is meant to last is made with a permanent operation, a permanent binding. | active |
//! | P5 | The domain holds the rules, their judgment, and whether an operation tightens or loosens, read from the difference before and after. Storage, history, import, the approval procedure and records belong to the application; reading a platform belongs to an adapter. | active |
//! | P6 | The policy store and the approval records cannot be rewritten directly by the agent. The rule that stops the rewriting is itself a Meta policy, which P3 keeps in place. | withdrawn -> P21 |
//! | P7 | An approval enters only through a door the agent cannot make, such as a command the user runs by hand. An approval written in the agent's transcript is not one. | withdrawn -> P22 |
//! | P8 | When one operation both tightens and loosens, as a mode switch, a swap of a set, an import or a cancellation does, the domain judges by the difference before and after, and one loosening difference makes the whole a loosening operation. | active |
//! | P9 | How much the agent is trusted with a rule is called Trust, and is expressed by a level (Force, Advise, Inform). When a check happens is not a value of the policy: it follows from the event the policy judges, an action itself or the end of a period. Which mechanism stops it is the adapter's to choose. | withdrawn -> P17 |
//! | P10 | What changes Trust is called an adjustment. A permanent one is an override in the catalog; a temporary one is an adjustment in the evidence (an exemption, a level change with a period). Both are judged by the difference before and after as tightening or loosening (P8), a loosening one by P2, a temporary one reverting with its period (P4). A Meta policy is the target of no adjustment (P3). | withdrawn -> P18 |
//! | P11 | A period that restarts at an opening event (a turn, an agent, a task, a session, a mode) is one vocabulary, the scope, shared by the period a rule speaks of and the lifetime of a temporary adjustment (as long as that scope lasts). The end of a scope is derived from the sequence of events. The next judgment and until a time belong to lifetimes only, and cannot be the scope of a rule. | withdrawn -> P20 |
//! | P12 | A period that restarts at an opening event (a turn, an agent, a task, a session, a mode) or after the last event matching a given kind of event (since the last X) is one vocabulary, the scope, shared by the period a rule speaks of and the lifetime of a temporary adjustment (as long as that scope lasts). The end of a scope is derived from the sequence of events. The next judgment and until a time belong to lifetimes only, and cannot be the scope of a rule. | withdrawn -> P20 |
//! | P13 | The fold history holds only events that happened. An act judged before it runs is judged on a copy of the state with the act folded over it, and it enters the history when it is read back from the transcript. | active |
//! | P14 | What changes how a rule takes effect is an adjustment: permanent, as a permanent binding in the catalog, or temporary, as a claim in the evidence (an exemption, a mode switch, a level change with a period, or a record a rule reads, such as a judgment or a score). A claim is a transaction: it is applied to a copy of the state, judged by the difference it makes from each point of view, and takes effect as a whole or not at all (P8). When any point of view finds that it loosens, or cannot read its direction, it takes effect only from one who covers the authors of what it loosens (P2), whatever else is combined; when it only tightens it is open to anyone (P1). A temporary one reverts with its period (P4); a Meta policy is the target of none (P3). An act observed on the platform, such as a tool use, is not an adjustment: it is what rules judge. A record of a judgment is written in the name of the author of the judged rule, and a rule reads the judgments only of rules whose authors cover its own. | withdrawn -> P18 |
//! | P15 | Who acts is read from the event, and where the actor sits from a hierarchy of actors: the authority hierarchy and the leaves that spawns add to it. A spawn is a claim: where it places its child is judged as a transaction (P18), against a place directly under its spawner (the child's work is its spawner's), by how the rules read the actor (a rule that applies inside a principal tightens when a child joins it; one that exempts it, or reads it in a way whose direction cannot be read, loosens), so only one who covers those rules' authors may place a child where it loosens. A leaf is added once and never moved. Who may loosen a rule is still the authority hierarchy's to say (P2). | active |
//! | P16 | A period that restarts at an opening event (a turn, a task, a session, a mode) or after the last event matching a given kind of event (since the last X) is one vocabulary, the scope, shared by the period a rule speaks of and the lifetime of a temporary adjustment (as long as that scope lasts). The end of a scope is derived from the sequence of events. The next judgment and until a time belong to lifetimes only, and cannot be the scope of a rule. | withdrawn -> P20 |
//! | P17 | How much the agent is trusted with a rule is called Trust, and is held by the bindings of the rule, not by the rule: a binding applies the rule, in the context of a mode, at a level (Force, Advise, Inform), and has an author. The strength a rule takes effect at is the strongest level among its bindings that hold, and with none it is off, so adding a binding never weakens a rule. When a check happens is not a value of the policy: it follows from the event the policy judges, an action itself or the end of a period. Which mechanism stops it is the adapter's to choose. | active |
//! | P18 | What changes how a rule takes effect is an adjustment: permanent, as a permanent binding in the catalog, or temporary, as a claim in the evidence (adding and suspending bindings, an exemption, a mode switch, or a record a rule reads, such as a judgment or a score). A claim is a transaction: it is applied to a copy of the state, judged by the difference it makes from each point of view, and takes effect as a whole or not at all (P8). When any point of view finds that it loosens, or cannot read its direction, it takes effect only from one who covers the authors of what it loosens (P2), whatever else is combined; when it only tightens it is open to anyone (P1). A temporary one reverts with its period (P4); a Meta policy is the target of none (P3). An act observed on the platform, such as a tool use, is not an adjustment: it is what rules judge. A record of a judgment is written in the name of the author of the judged rule, and a rule reads the judgments only of rules whose authors cover its own. | active |
//! | P19 | A period is one vocabulary, the scope, shared by the period a rule speaks of and the lifetime of a temporary adjustment (as long as that scope lasts). A scope starts again at an event boundary, an opening event (a turn, a task, a session, a mode) or after the last event matching a given kind of event (since the last X), with who may start it again stated; or at a time boundary, a window of fixed length. Time advances only by the time of acts, never by a claim's. A session starts again every scope bounded by events and no scope bounded by time. The next judgment and until a time belong to lifetimes only, and cannot be the scope of a rule. | withdrawn -> P20 |
//! | P20 | A period is one vocabulary, the scope, shared by the period a rule speaks of and the lifetime of a temporary adjustment. Every rule sees a history that has already begun: the outermost places (user-global, project, worktree) never start again within a fold, and a fold says whether it holds the history from the catalog's first acceptance or starts in its middle, where what has not been seen since is unknown until its period starts again and an adjustment made before it may only strengthen a rule, for as long as such an adjustment may still be in effect. The spans opened by events nest: a session holds tasks and turns, which are siblings. The start of a span starts again that span and each span inside it, each only when its starter, always stated, chooses the one who started it; it starts nothing outside, no since scope and no mode's scope. A record that could not be read and may have been the start of a span leaves that span and those inside it unknown. A scope may also start again after the last event matching a given kind of event (since the last X), with who may start it stated; or at a time boundary, a window of fixed length. Time advances only by the time of acts, never by a claim's. The next judgment and until a time belong to lifetimes only, and cannot be the scope of a rule. | active |
//! | P21 | What a principal keeps, such as the policy store and the approval records, is written only by that principal or one above it: an act of one below it that writes there is stopped. The domain knows no store and no agent; the keeper is a principal of the hierarchy, those below it are the actors the hierarchy places under it, and which acts write to what it keeps is the caller's to tell. The rule is a Meta policy by the keeper, which P3 keeps in place. | active |
//! | P22 | An approval takes effect only as a claim by the approver, the principal who covers what it loosens, whose actor the hierarchy places as that principal. A record of an approval written by one below the approver is not an approval, and the way an approver's claim reaches the record is the caller's to keep out of the reach of those below. | active |
//!
//! # Requirements
//!
//! | ID | Requirement | Decision | Layer | Issues |
//! |---|---|---|---|---|
//! | FR1 | Write one policy and put it into effect, for example NetAccess, which stops outgoing network use. | supported | Domain, Adapter | |
//! | FR2 | Check a policy against examples before it is used: an accepted policy has shown what it stops and what it lets through. | supported | Domain | #11 |
//! | FR3 | Use policies as a set, such as a safety set: put it in and take it out. Putting it in needs no approval. Taking it out is a loosening under P2: an approver for the user's set, nobody for the agent's. | withdrawn -> FR49 | Domain | #16 |
//! | FR4 | Combine sets, for example a shared set with the set of this repository. P8 applies: an approver is needed when the repository side weakens the shared side. | withdrawn -> FR48 | Application, Domain | #7 |
//! | FR5 | Change the level of a policy permanently, as a permanent adjustment (an override in the catalog, P18). Raising it needs no approval; lowering it is a loosening under P2. | withdrawn -> FR42 | Domain, Application | #14 |
//! | FR6 | Turn a policy off permanently, and turn it on again, as a permanent adjustment (an override in the catalog, P18). Turning it off is a loosening under P2; turning it on needs no approval. | withdrawn -> FR42 | Domain, Application | #14 |
//! | FR7 | Delete a policy. This is a loosening under P2. A Meta policy cannot be deleted, by P3. | supported | Application, Domain | #14 |
//! | FR8 | Lower a level for a bounded time, for example NetAccess to a warning for this task only. A loosening under P2, with a period under P4. | withdrawn -> FR55 | Domain | #15 |
//! | FR9 | Switch a policy off once or for a bounded time, as an exemption. Only one that comes from the user takes effect, under P2 and P4. | withdrawn -> FR34 | Domain | |
//! | FR10 | Raise a level for a bounded time, for example NetAccess to Force for this task only. The tightening counterpart of lowering for a bounded time, under P1 and P4. | withdrawn -> FR55 | Domain | #15 |
//! | FR11 | Switch by the kind of work, as a mode. A mode switch selects which bindings hold, and is judged by the difference it makes (P8): an approver is needed when any difference loosens. | supported | Domain | #17 |
//! | FR12 | See which policies are in effect and at which level, off told apart from in effect but not matching. | supported | Domain | #6 |
//! | FR13 | Write a recommendation that does not stop anything. It neither tightens nor loosens, and it stays within the guard that binds it. | supported | Domain | |
//! | FR14 | Place a policy that cannot be changed, as a Meta policy. Only the root of the hierarchy, the user, can place one (P3). | supported | Domain | |
//! | FR15 | Change a Meta policy during a run. A Meta policy changes only as a change to the code of the repository (P3). | not supported | ? | |
//! | FR16 | The agent adds a policy for itself during a task. Only a policy that is not Meta and that tightens may be added, written by the agent or one below it, never a Meta policy or an exemption, and it is removed when the task ends (P1). | supported | Domain, Application | #14, #19 |
//! | FR17 | The agent loosens a policy of the user. The agent only proposes; an approver makes the change as an ordinary operation (P2). | not supported | Application | #14 |
//! | FR18 | The agent removes or weakens a policy or a set that it added itself. This holds only for what the agent covers, what it or one below it wrote (P2). | supported | Domain | #14 |
//! | FR19 | The agent creates an exemption (P2). | withdrawn -> FR34 | ? | |
//! | FR20 | When something cannot be seen, fall back to the stopping side: not being able to read never loosens a rule. | supported | Domain | |
//! | FR21 | See and cancel temporary changes and exemptions. Cancelling is judged by its result (P8): no approval when it tightens, a loosening under P2 when it loosens, as when the user's raise is cancelled. | withdrawn -> FR55 | Domain, Application | #14, #15 |
//! | FR22 | See who changed a policy and when. | supported | Application, Domain | #19 |
//! | FR23 | See and count the records of judgments, for example which policy stopped most often. | supported | Application | #19 |
//! | FR24 | Propose a level adjustment from the records. A tightening proposal enters without approval; a loosening one is a loosening under P2. | supported | Application | #19 |
//! | FR25 | Share policies with others by exporting and importing them. An import follows P8, as combining sets does. | withdrawn -> FR50 | Adapter, Application | #19 |
//! | FR26 | Judge with a classifier a rule that code cannot express: the classifier's answer comes as a recorded claim (Classified) that an ordinary rule reads, counted as any record a rule reads is (FR41). A guard that reads a classifier takes effect at Force only while the calibration record of the classifier's declaration meets the bound the declaration gives; otherwise it is lowered to Advise and reported (the exception of P1). The calibration lives in the catalog, so a lost transcript does not lower it (FR20 does not apply), and it changes only by a permanent change from one who covers the declaration's author. | supported | Domain, Application, Adapter | #1 |
//! | FR27 | Protect the policy store and the approval records from direct rewriting by the agent (P21), always. | withdrawn -> FR57 | Domain, Adapter | #18 |
//! | FR28 | Cap levels by what a platform can carry (Support): given, per event kind, the highest level a platform can enforce, a policy above it is lowered to it and reported as degraded, and a reward bound to a lowered guard follows. The cap is a core domain value supplied by the adapter. | withdrawn -> FR40 | Domain, Adapter | #8 |
//! | FR29 | When several guards judge one event, the strongest result decides (deny over warn over allow), whatever the order of the policies; recommendations are each reported and never combined. | supported | Domain | |
//! | FR30 | Change the level of a policy for a bounded time, up or down: a temporary adjustment (P18), given as evidence with its origin and its period, that reverts when the period ends (P4). Tightening is open to anyone (P1); loosening is a loosening under P2. Raising to Force needs the policy's fixtures (FR2). A Meta policy is out of reach (P3). | withdrawn -> FR55 | Domain | #15 |
//! | FR31 | Write a period of work in a rule: the scope of a temporal operator (P20), and the end of a period as the event a policy judges (a turn, a task, a session), which says when the check happens (P17). The end of a period is derived from the sequence of events. Only an end the platform can hold, the end of a turn, can stop; a rule that would stop at another end is lowered by the platform's capabilities (FR40) and reported as lowered. | supported | Domain, Adapter | #10 |
//! | FR32 | See which temporary adjustments are in effect (exemptions and level changes with a period, P18), and cancel them. Cancelling is judged by its result (P8): no approval when it tightens, a loosening under P2 when it loosens, as when the user's raise is cancelled. | withdrawn -> FR55 | Domain, Application | #15 |
//! | FR33 | Write a period as since the last event matching X: the scope `Since` of a temporal operator or of an exemption's lifetime (P20). The matching event that happened belongs to the interval it closes and is judged with it, and the interval starts again before the next event. When it cannot be told whether the interval started again, fall back to the stopping side (FR20). | withdrawn -> FR53 | Domain | #10 |
//! | FR34 | Switch a guard off once or for a bounded time, as an exemption: a temporary adjustment (P18) that takes effect only from one who covers the guard's author, reverts with its lifetime, and never reaches a Meta policy. | supported | Domain | |
//! | FR35 | A record a rule reads, a judgment or a measured score, is a temporary adjustment (P18): it counts only from one who covers the authors of the rules it would move. The record of a judgment is written in the name of the judged rule's author, and a rule may read the judgments only of rules whose authors cover its own (checked when the catalog is accepted), so a genuine record of a judgment always counts. Where an oracle that records a score sits in the hierarchy is the caller's arrangement. | withdrawn -> FR41 | Domain | |
//! | FR36 | Judge a claim from several points of view and combine them by a policy given from outside (all must agree, or a weighted or probabilistic merge), with a fixed floor: a point of view that finds a loosening not covered by the claim's author stops the claim, whatever the combination says (P2, P8). | supported | Domain, Application | |
//! | FR37 | A record a rule reads, a judgment or a measured score, is a temporary adjustment (P18): it counts only from one who covers the authors of the rules it would move. The record of a judgment is written in the name of the judged rule's author, and a rule reads the judgments only of rules whose authors cover its own: a filter of judgments that does not narrow to named rules sees the judgments of those rules in the catalog only; one that names a rule below is not accepted; a `last` of a judgment's field reads every rule and is not accepted beside a rule below; and a Meta rule reads judgments only by naming the rules. So a genuine record of a judgment always counts. Where an oracle that records a score sits in the hierarchy is the caller's arrangement. | withdrawn -> FR41 | Domain | |
//! | FR38 | Write a rule for a role as a condition on the acting principal: the event's actor is under a given principal of the hierarchy. An actor the hierarchy does not know, or one placed after a lost record, reads as unknown, so a stopping rule stops. No event needs to end a role. | supported | Domain | |
//! | FR39 | Write a temporal rule over the events of one actor only (since this actor was spawned). Withdrawn: a spawned actor has no name a rule can use, since its name is new at every start, so events are chosen by the principal of the hierarchy they sit under (FR44). | withdrawn -> FR54 | Domain | #25 |
//! | FR40 | Cap levels by what a platform can carry (its capabilities): given, per event filter, the highest level a platform can enforce, a policy above it is lowered to it and reported as lowered, and a reward bound to a lowered guard follows. The capabilities are a core domain value, written as event filters, that the adapter supplies with each judgment; the catalog stays the same on every platform. Each judgment records the level a policy was written with and the level it was enforced at, and a catalog can be checked against the capabilities before use. | supported | Domain, Adapter | #8 |
//! | FR41 | A record a rule reads, a judgment or a measured score, is a temporary adjustment (P18): it counts only from one who covers the authors of the rules it would move. The record of a judgment is written in the name of the judged rule's author, and a rule reads the judgments only of rules whose authors cover its own: a filter of judgments that does not narrow to named rules sees the judgments of those rules in the catalog only; one that names a rule below is not accepted; and a Meta rule reads judgments only by naming the rules. A `last` reads the last event that matches its filter, and is scoped and checked as any other read of judgments, a rule named in its test as one named in its filter. So a genuine record of a judgment always counts. Where an oracle that records a score sits in the hierarchy is the caller's arrangement. | supported | Domain | |
//! | FR42 | Change the level of a policy, and turn it off or on, permanently, by the bindings in the catalog (P17), each a permanent adjustment (P18). A change is judged by its result (P8): when the strength a policy takes effect at goes down, under any mode, it is a loosening under P2 of the authors of the bindings that carried the strength it lost; raising it, or turning it on, needs no approval. | supported | Domain, Application | #14, #39 |
//! | FR43 | Adjust the rules for a bounded time, as a temporary adjustment (P18) given as evidence with its origin and its lifetime, that reverts when the lifetime ends (P4): add bindings, each under every mode, and suspend bindings of the catalog, as when a policy is raised to Force, or lowered to Advise by suspending its Force binding, for one task. The adjustments in effect are seen, each with who made it, and are cancelled by their id. An adjustment and a cancel are each judged by their result (P8): when the strength a policy takes effect at goes down, it is a loosening under P2 of the authors of the bindings that carried what it lost, a temporary binding by the one who made it; suspending a binding is a loosening as to that binding's author, whether or not the strength goes down; raising, and cancelling a lowering or an exemption, are open to anyone (P1). A temporary binding at Force needs the policy's fixtures (FR2), a reward is never at Force, a temporary binding is made only by the policy's author or one below it, as a permanent one is, and a Meta policy is out of reach (P3); an adjustment or a cancel that cannot take effect is refused with its reason. When a record that may have been an adjustment or a cancel is lost, no suspension is taken to hold and each rule takes effect as strongly as a temporary binding could make it (FR20). | withdrawn -> FR55 | Domain, Application | #15, #39 |
//! | FR44 | Choose by who acted the events a temporal operator counts, the events that close a since scope, and the start events of task and turn scopes: of anyone, of the actors whose place in the hierarchy of actors is under a given principal (Under), or of one principal of the hierarchy alone (Only). Who may start a scope again is always stated, never defaulted. The one a limit is about sits under whoever set the limit, so a limit that only one principal may start again is written with Only, which no spawn can move, since a spawned actor is never that principal. A principal named this way, in a rule or in the lifetime of a temporary adjustment, is one of the hierarchy. An actor whose place is not known makes a choice by Under unknown, and a stopping rule stops (FR20); an unknown start or close leaves what it may have ended read in the tightening direction: a temporary adjustment that lasts within the scope is kept as possibly ended, its exemption covers nothing, its added bindings still hold and its suspensions no longer hold, until a known start or close ends it. A spawn that places a child where a rule chooses events by actor is a loosening under P2 of that rule's author (P15), and one that changes who ends a temporary adjustment in effect is a loosening of the one who made it. | withdrawn -> FR54 | Domain | #25, #42 |
//! | FR45 | Write a period as a window of time: the scope Every of a temporal operator or of a temporary adjustment's lifetime, a window of fixed length aligned to the Unix epoch in UTC, which starts again when the time crosses its boundary (P20). The time is a clock advanced only by acts, to the latest time an act carried: a claim's time never moves it, and an act dated earlier never moves it back; before the first act nothing has ended by time. A record that could not be read advances the clock only when it may have been an act; one that may have been only claims carries a claim's time. A claim's time never ends what loosens when it ends (a raise, a suspension, a window, an adjustment refused as expired), and may end an exemption's cover, which is read at the later of the clock and the judged event's time. So a raise or a suspension past its until lasts until the next act's time. A session does not start a window again, and a window spans sessions only as far as the caller folds. | supported | Domain | #42 |
//! | FR46 | Adjust the rules for a bounded time, as a temporary adjustment (P18) given as evidence with its origin and its lifetime, that reverts when the lifetime ends (P4), a lifetime that ends by time read by the clock that only acts advance, never by a claim's time (FR45): add bindings, each under every mode, and suspend bindings of the catalog, as when a policy is raised to Force, or lowered to Advise by suspending its Force binding, for one task. The adjustments in effect are seen, each with who made it, and are cancelled by their id. An adjustment and a cancel are each judged by their result (P8): when the strength a policy takes effect at goes down, it is a loosening under P2 of the authors of the bindings that carried what it lost, a temporary binding by the one who made it; suspending a binding is a loosening as to that binding's author, whether or not the strength goes down; raising, and cancelling a lowering or an exemption, are open to anyone (P1). A temporary binding at Force needs the policy's fixtures (FR2), a reward is never at Force, a temporary binding is made only by the policy's author or one below it, as a permanent one is, and a Meta policy is out of reach (P3); an adjustment or a cancel that cannot take effect is refused with its reason, one whose lifetime has run out by the clock among them. When a record that may have been an adjustment or a cancel is lost, no suspension is taken to hold and each rule takes effect as strongly as a temporary binding could make it (FR20). | withdrawn -> FR55 | Domain, Application | #15, #39, #42 |
//! | FR47 | Write a limit on the sum of an amount used, per meter (such as tokens), within a scope (P20), of the uses chosen by who acted (FR54), compared with a bound on one side of it. The amount is carried by an act, what the platform measured as used, and a sum is always chosen by place, of anyone or of the actors under a principal (Under): what is delegated counts toward the one who delegates, so a sub agent's use counts toward the principal it is spawned under, and Only, which would let a principal escape its budget by delegating, is not offered for a sum. An amount is finite and not negative, and a sum of amounts only grows and starts again with its scope. A use whose amount was measured but could not be read makes the sum unknown, and a stopping rule stops (FR20). An amount is known after the use, so a sum can pass its bound by one event, and the next act is the one stopped. An amount that goes down, a gauge, cannot be written. | supported | Domain | #42 |
//! | FR48 | Combine sets of policies, such as a shared set with the set of a project, by adding only: the policies and bindings of the sets are joined by id, an item that two sets hold the same is one item, and two different items under one id, or two policies of one name, are a conflict that refuses the catalog; no set overrides or replaces an item of another, whatever their order. The catalog keeps the sets it was composed of, and when it is accepted every item of a set is checked to be by the set's owner or one below it. A lower set only adds to the upper rules and strengthens them, which needs no approval (P1). An upper rule is weakened only by a version of the upper set, which is a loosening under P2: the upper owner or one who covers it makes it. | supported | Domain, Application | #7, #47 |
//! | FR49 | Add, remove and replace a set of policies, a new version included, as an operation on the sets the catalog keeps, judged as one change by its result (P8), so a swap of a set is one difference. Adding a set by its owner or one above it needs no approval (P1). Adding, removing, replacing or renaming a set whose owner the one who changes does not cover, or changing the owner of a set, is a loosening under P2 and needs an approver who covers that owner, even when the new version would only tighten: a set is a value its owner keeps, and one who wants to tighten adds to a set of its own, which needs no approval (P1). Removing one's own set is judged by the loosening its result makes (P8, P2). A set has no on and off flag: it is stopped for a while by suspending its bindings. A set that holds a Meta policy enters only when the catalog is first accepted (P3). | supported | Domain | #16, #47 |
//! | FR50 | Share policies with others by exporting and importing them. An import adds a set of policies, or replaces one, and follows FR48 and FR49. | supported | Adapter, Application | #19 |
//! | FR51 | Put knowledge, a document meant for the agent's context such as a design standard, into that context as one of the forms a platform injects context in (an instruction file, a rule scoped to paths, a skill, the context a hook adds). Knowledge is not a part of the Core domain: it is not a rule and is not judged. What can be observed of it, such as an edit without the read, is an ordinary policy. | ? | Adapter | #12 |
//! | FR52 | Declare a classifier, by name and version, with its author, the calibration bound and the last calibration record, as an item of the policy graph, composed as the sets are (FR48): the same declaration in two sets is one item, and two different declarations under one name are a conflict. A policy reads a classifier only by its name, and only a declaration of its own author or of one above it; a Meta policy reads none. | supported | Domain | #1 |
//! | FR53 | Write a period as since the last event matching X: the scope `Since` of a temporal operator or of an exemption's lifetime (P20). The matching event that happened belongs to the interval it closes and is judged with it, and the interval starts again before the next event. A session's start does not start a since scope again, nor does the start of any span. When it cannot be told whether the interval started again, fall back to the stopping side (FR20). | supported | Domain | #10 |
//! | FR54 | Choose by who acted the events a temporal operator counts, the events that close a since scope, and the start events of every span (session, task, turn): of anyone, of the actors whose place in the hierarchy of actors is under a given principal (Under), or of one principal of the hierarchy alone (Only). Who may start a scope again is always stated, never defaulted. The one a limit is about sits under whoever set the limit, so a limit that only one principal may start again is written with Only, which no spawn can move, since a spawned actor is never that principal. A principal named this way, in a rule or in the lifetime of a temporary adjustment, is one of the hierarchy. An actor whose place is not known makes a choice by Under unknown, and a stopping rule stops (FR20); an unknown start or close leaves what it may have ended read in the tightening direction: a temporary adjustment that lasts within the scope is kept as possibly ended, its exemption covers nothing, its added bindings still hold and its suspensions no longer hold, until a known start or close ends it. A spawn that places a child where a rule chooses events by actor is a loosening under P2 of that rule's author (P15), and one that changes who ends a temporary adjustment in effect is a loosening of the one who made it. | supported | Domain | #25, #42 |
//! | FR55 | Adjust the rules for a bounded time, as a temporary adjustment (P18) given as evidence with its origin, its lifetime and the time it ends by, that reverts when the first of them comes (P4): its lifetime may end by an event (the next judgment, a scope starting again) or by nothing but that time, and time is read by the clock that only acts advance, never by a claim's time (FR45). A root declares, in a set it owns, the longest period a temporary adjustment may have; every root that owns a set declares it with the same value, a declaration in a set no root owns is not accepted, and a catalog with none is not accepted; changing it is a change of the roots' sets (FR49), so with several roots it changes only when the catalog is accepted again. An adjustment whose end lies further ahead of the clock than the bound, or whose window is longer, is refused; one made before the first act is checked at the first act and ends there if it lies too far ahead. An adjustment may add bindings, each under every mode, and suspend bindings of the catalog, as when a policy is raised to Force, or lowered to Advise by suspending its Force binding, for one task. The adjustments in effect are seen, each with who made it, and are cancelled by their id. An adjustment and a cancel are each judged by their result (P8): when the strength a policy takes effect at goes down, it is a loosening under P2 of the authors of the bindings that carried what it lost, a temporary binding by the one who made it; suspending a binding is a loosening as to that binding's author, whether or not the strength goes down; raising, and cancelling a lowering or an exemption, are open to anyone (P1). A temporary binding at Force needs the policy's fixtures (FR2), a reward is never at Force, a temporary binding is made only by the policy's author or one below it, as a permanent one is, and a Meta policy is out of reach (P3); an adjustment or a cancel that cannot take effect is refused with its reason, one whose end has passed by the clock or lies too far ahead among them. When a record that may have been an adjustment or a cancel is lost, no suspension is taken to hold and each rule takes effect as strongly as a temporary binding could make it (FR20); a fold that starts in the middle of a history does so for adjustments made before it until the bound has passed since its first act. | supported | Domain, Application | #15, #39, #42, #56 |
//! | FR56 | A judgment state is used only with the catalog generation that made it. Accepting a catalog starts a lineage, named by the caller, at generation 0, and each change raises the generation by one; judging, applying an event, admitting a claim or reading what is in effect with a state of another lineage or generation is refused with both generations and what the difference is: a state behind the catalog is folded again under it, a state ahead of it means the catalog is the old one, and another lineage means the wrong catalog. The domain compares positions only; keeping a lineage a single line, one change from the current generation, is the store's (two changes made from the same parent both carry the next generation). | supported | Domain, Application | #55 |
//! | FR57 | Keep what a principal keeps, such as the policy store and the approval records, from being written by those below it (P21), always: an ordinary Meta policy by the keeper stops an act that writes there unless its actor is the keeper or above, whatever the layer, mode or exemption, and a child spawned below the keeper is below it too. Which tools, paths and commands write to what the keeper keeps is the adapter's to tell from its configuration. | supported | Domain, Adapter | #18 |
//! | FR58 | Write a path pattern that reaches any depth: a `**` that is a whole segment matches zero or more directories (`a/**/b` matches `a/b` and `a/x/y/b`), a `**` that ends the pattern matches the rest of the path whatever it holds (`a/**` matches everything under `a/` but not `a` itself), and `**` alone every path. A `**` inside a segment cannot be written: the pattern is refused when it is made, so it never means silently less than it reads. A pattern is compiled once when it is made; matching does not fail and stays linear, with no backtracking. | supported | Domain | #51 |
//! | FR59 | Keep a record of a judgment only in the name of the judged policy's author: a record in another's name, or of a policy the catalog does not hold, is no judgment any of its rules made, and is not admitted, whether or not a rule reads it, so nothing that keeps or counts the records takes it in. | supported | Domain | #63 |
//! | FR60 | Leave the state as it was when a claim is aborted: a history folded without its aborted claims gives the same state as one folded with them, to the last event, so a store may keep only the claims that took effect. | supported | Domain | #64 |
//! | FR61 | Encode the catalog's records and the events behind a `serde` feature so that decoding a value with a checking constructor goes only through that constructor, and the stored form is versioned: a change of its shape changes the golden form and its version. | supported | Domain | #65 |
//! | FR62 | A store keeps the catalog as an append-only line of records, written only when the line is as long as when it was read (compare and swap). An acceptance starts a lineage only in an empty line, by a root of its hierarchy; each later change, proposal, approval or rejection is written from the line as read, so one made from an older generation is refused and judged again. A change is recorded in the name it was judged under, so replaying it judges it the same way. The catalog is the replay of the records from the last acceptance; each record keeps the version of the core that wrote it. When the records cannot be replayed under the running version, every act judged ahead is stopped, and a root of the last acceptance's hierarchy, checked from that record without replaying, may start a new lineage; this is also how the hierarchy changes, and it is not judged. Until the line has an acceptance, every act judged ahead is stopped, except what the adapter says need not be, such as the end of a turn. | supported | Application | #66 |
//! | FR63 | Every record of the evidence has an id that a retry, or a second writer of the same request, does not write twice, and a position in its stream that the store gives without gaps. A request whose result was recorded is answered again with that result, which names the record and carries no generation of its own, whatever the catalog has become since; a refused request leaves no result and is judged again. An act is told from a claim by the kind of record, and a claim keeps whether its transaction took effect; each keeps the generation it was judged under and where it came from, an act from the platform or a command and its request, a claim from the platform or the judge. A record of a judgment, a classifier's answer, a measurement or the start of a task is not taken from the platform: a record of a judgment enters only as the judge's own, and the start of a task only from a request to start one. A request to write is recorded apart from what the rules fold, and a record the store cannot read back is folded as one that could not be read. A claim that did not take effect is not folded again. Records of one stream may be written at once: one written from a stale read is refused, and its writer takes in only the records after its read and judges again, without waiting, and stops with an error when the store reports no progress. An act judged ahead is stopped when a bounded number of tries runs out; an act read back is tried until it is written or its caller gives up. A change of the catalog between reading it and writing the evidence is not detected. | supported | Application | #66 |
//! | FR64 | An operation that writes is a claim by the principal the platform reports for the act that asked for it, and the request keeps who asked and how. From a tool call, an acceptance, a new lineage or the start of a task is refused, and a change that loosens what the caller does not cover becomes a proposal. From a prompt the platform cannot show the user typed, an approval, a new lineage (unless the catalog cannot be replayed) and the start of a task are refused, and a change or an import is taken only when the platform's agent could have made it itself, and is recorded as the agent's. A proposal is approved only from the generation it was made from, and rejected only by its maker or one who covers the maker; an approval is recorded with the proposal it settles. | supported | Application | #66 |
//! | FR65 | A path reaches the judgment in one form: relative to the worktree's root, separated by `/`, with no `.`, `..` or empty segment, read as written without resolving links, or absolute in the same form outside the root. A tool use whose path is not in that form is judged as a record that could not be read. | supported | Application | #66 |
//! | FR66 | Encode how a change loosens (`Loosening` and what it holds) behind the `serde` feature by the same rules as the catalog's records (FR61), so a store keeps a proposal with the answer it was given; a slot's id is stored as it is, read only as a fact of the record that names it. | supported | Domain | #78 |

use std::fmt;
use std::str::FromStr;

/// A word that is not one of the values of the enum it was read as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownWord {
    /// The kind of value that was expected.
    pub expected: &'static str,
    /// The text that was read.
    pub found: String,
}

impl fmt::Display for UnknownWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` is not a {}", self.found, self.expected)
    }
}

impl std::error::Error for UnknownWord {}

/// What the project decided about a requirement. Parsed from the whole word; a successor of a
/// withdrawn row, written `-> <ID>` after the word, is not part of this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// `supported`: agent-caps is to do this. This is a decision, not a statement that it is
    /// built.
    Supported,
    /// `not supported`: agent-caps does not do this, and the row says why.
    NotSupported,
    /// `?`: not decided yet. The cell is not filled by guessing.
    Undecided,
    /// `withdrawn`: the row no longer holds. It stays, and may name its successor as
    /// `-> <ID>`.
    Withdrawn,
}

impl FromStr for Decision {
    type Err = UnknownWord;

    fn from_str(word: &str) -> Result<Self, Self::Err> {
        match word {
            "supported" => Ok(Self::Supported),
            "not supported" => Ok(Self::NotSupported),
            "?" => Ok(Self::Undecided),
            "withdrawn" => Ok(Self::Withdrawn),
            other => Err(UnknownWord {
                expected: "decision",
                found: other.to_owned(),
            }),
        }
    }
}

/// Whether a use case or a principle still holds. Parsed from the whole word; a successor of a
/// withdrawn row, written `-> <ID>` after the word, is not part of this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// `active`: the row holds.
    Active,
    /// `withdrawn`: the row no longer holds. It stays, and may name its successor as
    /// `-> <ID>`.
    Withdrawn,
}

impl FromStr for Status {
    type Err = UnknownWord;

    fn from_str(word: &str) -> Result<Self, Self::Err> {
        match word {
            "active" => Ok(Self::Active),
            "withdrawn" => Ok(Self::Withdrawn),
            other => Err(UnknownWord {
                expected: "status",
                found: other.to_owned(),
            }),
        }
    }
}

/// The layer that owns a requirement. A requirement may be owned by several, listed with `,`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// `Domain`: the pure model, which holds the rules and their judgment.
    Domain,
    /// `Application`: storage, history, records and the procedures around the model.
    Application,
    /// `Adapter`: reading and talking to a platform.
    Adapter,
    /// `?`: not decided yet, or no layer applies.
    Unknown,
}

impl FromStr for Layer {
    type Err = UnknownWord;

    fn from_str(word: &str) -> Result<Self, Self::Err> {
        match word {
            "Domain" => Ok(Self::Domain),
            "Application" => Ok(Self::Application),
            "Adapter" => Ok(Self::Adapter),
            "?" => Ok(Self::Unknown),
            other => Err(UnknownWord {
                expected: "layer",
                found: other.to_owned(),
            }),
        }
    }
}
