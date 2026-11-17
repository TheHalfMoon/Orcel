//! The hold rule: whether the resources a human holds refuse one agent
//! operation. Pure, with no clock of its own: the caller has already
//! brought every session up to the instant it asks about, so the decided
//! table is a unit test.
//!
//! Adapted from BrowserOS (browseros-ai/BrowserOS) at commit
//! bd725831, `packages/browseros-agent/crates/neo-sdk/neo-takeover/src/lock_decision.rs`
//! (blob 4796bbc388b0986fdc84979637fea00913350b84): `refuses` and
//! `oldest_refusal`, and their decided tables. AGPL-3.0-or-later upstream;
//! copied and renamed under the owner-asserted authorization recorded in
//! `docs/orcel/grants/2026-11-17-founder-attestation.md`; notice:
//! `docs/orcel/notices/browseros-AGPL-3.0.txt`; provenance:
//! `docs/orcel/browseros_provenance.json`.
//!
//! Orcel's changes: a lock with a TTL becomes a [`Hold`], the refusing
//! state of one resource's human-intervention session, so there is no
//! deadline filter here (the session ends its own hold when its quiet
//! period passes) and no past-instant check (`decide_at`); a resource has
//! at most one hold, so holds never add up; the refusal carries the
//! session's [`Reason`] and names the hold that began first, where the donor
//! names the oldest lock id; tab ids become opaque [`ResourceId`]s and the
//! donor's `NoPage` / `Tab` / `UnmappedPage` targets keep their meaning,
//! including failing closed for an unmapped page.

use crate::{Effect, Millis, Reads, Reason, Refusal, ResourceId, Target};

/// One resource whose session holds the agent off it, as the session stood
/// when the caller asked.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Hold<'a> {
    pub(crate) resource: &'a ResourceId,
    pub(crate) reads: Reads,
    pub(crate) since: Millis,
    pub(crate) reason: Reason,
}

/// Whether a hold with `reads` refuses an operation with `effect`: a write
/// always, a read only under `Block`.
pub(crate) const fn refuses(reads: Reads, effect: Effect) -> bool {
    matches!(
        (effect, reads),
        (Effect::Write, _) | (Effect::Read, Reads::Block)
    )
}

/// The rule over every hold in force.
///
/// `NoPage` is never refused. `UnmappedPage` is refused as if it were on
/// every held resource: the caller could not say which resource the page
/// is, and letting it pass as "no page" would let a mapping gap skip the
/// hold (fail closed). The refusal names the hold that began first,
/// whatever order the holds come in.
pub(crate) fn decide<'a>(
    holds: impl IntoIterator<Item = Hold<'a>>,
    target: &Target,
    effect: Effect,
) -> Result<(), Refusal> {
    let covers = |hold: &Hold<'_>| match target {
        Target::NoPage => false,
        Target::Resource(resource) => hold.resource == resource,
        Target::UnmappedPage => true,
    };
    match holds
        .into_iter()
        .filter(|hold| covers(hold) && refuses(hold.reads, effect))
        .min_by_key(|hold| (hold.since, hold.resource))
    {
        Some(hold) => Err(Refusal {
            resource: hold.resource.clone(),
            reason: hold.reason,
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    // Ported from the donor's decided tables: one hold refuses by effect
    // and reads on its own resource only; an unmapped page is refused while
    // any hold would refuse it; the first hold is named whatever the order.
    use super::*;

    fn hold(resource: &ResourceId, reads: Reads, since: u64) -> Hold<'_> {
        Hold {
            resource,
            reads,
            since: Millis(since),
            reason: Reason::HumanOverride,
        }
    }

    #[test]
    fn one_hold_refuses_by_effect_and_reads_on_its_own_resource_only() {
        let held = ResourceId::new("12");
        let other = ResourceId::new("13");
        let on_held = Target::Resource(held.clone());
        let on_other = Target::Resource(other);
        let cases = [
            (
                Reads::Block,
                &on_held,
                Effect::Write,
                false,
                "a write is refused",
            ),
            (
                Reads::Block,
                &on_held,
                Effect::Read,
                false,
                "block refuses reads",
            ),
            (
                Reads::Allow,
                &on_held,
                Effect::Write,
                false,
                "allow still refuses writes",
            ),
            (
                Reads::Allow,
                &on_held,
                Effect::Read,
                true,
                "allow lets reads through",
            ),
            (
                Reads::Block,
                &on_other,
                Effect::Write,
                true,
                "another resource runs",
            ),
            (
                Reads::Block,
                &Target::NoPage,
                Effect::Write,
                true,
                "no page runs",
            ),
        ];
        for (reads, target, effect, passes, case) in cases {
            let decided = decide([hold(&held, reads, 1)], target, effect);
            let expected = if passes {
                Ok(())
            } else {
                Err(Refusal {
                    resource: held.clone(),
                    reason: Reason::HumanOverride,
                })
            };
            assert_eq!(decided, expected, "{case}");
        }
    }

    #[test]
    fn no_hold_refuses_nothing() {
        for target in [
            Target::NoPage,
            Target::UnmappedPage,
            Target::Resource(ResourceId::new("12")),
        ] {
            assert_eq!(decide([], &target, Effect::Write), Ok(()));
        }
    }

    #[test]
    fn an_unmapped_page_is_refused_while_any_hold_would_refuse_it() {
        let allow_on = ResourceId::new("12");
        let block_on = ResourceId::new("40");
        let allow = hold(&allow_on, Reads::Allow, 1);
        assert!(decide([allow], &Target::UnmappedPage, Effect::Write).is_err());
        assert_eq!(
            decide([allow], &Target::UnmappedPage, Effect::Read),
            Ok(()),
            "the read would pass on the held resource too"
        );
        let block = hold(&block_on, Reads::Block, 2);
        assert_eq!(
            decide([allow, block], &Target::UnmappedPage, Effect::Read),
            Err(Refusal {
                resource: block_on.clone(),
                reason: Reason::HumanOverride,
            }),
            "any held resource may be the page's"
        );
    }

    #[test]
    fn the_first_hold_is_named_whatever_the_order() {
        let older_on = ResourceId::new("b");
        let newer_on = ResourceId::new("a");
        let older = Hold {
            reason: Reason::Paused,
            ..hold(&older_on, Reads::Block, 5)
        };
        let newer = hold(&newer_on, Reads::Block, 9);
        assert_eq!(
            decide([newer, older], &Target::UnmappedPage, Effect::Write),
            Err(Refusal {
                resource: older_on.clone(),
                reason: Reason::Paused,
            }),
            "the older hold comes second and is still named"
        );
    }
}
