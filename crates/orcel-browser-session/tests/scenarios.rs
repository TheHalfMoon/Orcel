//! The Shadow Mode collaboration scenarios (SHADOW_MODE_AND_COLLABORATION_SPEC,
//! "Human intervention recognition and three-second re-evaluation" and
//! "Login, credentials and challenge handoff"), on a manual clock.
//!
//! The test marked "Ported from the donor" carries over a case of
//! BrowserOS's `packages/browseros-agent/crates/neo-sdk/neo-takeover/tests/locks.rs`
//! (blob b6bd7ff1ea702a3487d902ee4903740cce08bba7, commit bd725831,
//! AGPL-3.0-or-later upstream; notice:
//! `docs/orcel/notices/browseros-AGPL-3.0.txt`).

mod common;

use common::{page, Scene};
use orcel_browser_session::{
    ActionClass, AgentMarker, ChallengeKind, ChallengeOrigin, Effect, InputKind, InputPhase,
    InputVerdict, ObservedInput, Reason, State, Target, TaskId, WriteFate, WriteOutcome, QUIET_MS,
};

#[test]
fn a_human_click_edit_navigation_or_typing_each_suspend_the_agent_on_that_page() {
    for kind in [
        InputKind::Pointer,
        InputKind::Edit,
        InputKind::Navigation,
        InputKind::Key,
        InputKind::Text,
        InputKind::Scroll,
        InputKind::Focus,
    ] {
        let mut scene = Scene::new(&["a"]);
        assert_eq!(
            scene.human("a", kind, InputPhase::Instant),
            InputVerdict::Human
        );
        assert_eq!(
            scene.write("a", "fill", 0).err(),
            Some(Reason::HumanOverride),
            "{kind:?}"
        );
    }
}

#[test]
fn every_event_of_a_burst_resets_the_quiet_timer() {
    let mut scene = Scene::new(&["a"]);
    for at in [0, 1_000, 2_000, 2_900, 4_000] {
        scene.at(at);
        scene.click("a");
        assert_ne!(scene.state("a"), State::Reobserve, "t={at}");
    }
    scene.at(4_000 + QUIET_MS - 1);
    assert_eq!(scene.state("a"), State::Quiet);
    scene.at(4_000 + QUIET_MS);
    assert_eq!(scene.state("a"), State::Reobserve);
}

#[test]
fn a_user_who_stays_active_is_never_interrupted_for_ten_minutes() {
    let mut scene = Scene::new(&["a"]);
    let mut at = 0;
    while at <= 10 * 60 * 1_000 {
        scene.at(at);
        scene.human("a", InputKind::Key, InputPhase::Instant);
        scene.at(at + 2_500);
        assert_ne!(scene.state("a"), State::Reobserve, "t={at}");
        assert!(
            scene.write("a", "fill", scene.epoch("a")).is_err(),
            "t={at}"
        );
        at += 2_500;
    }
}

#[test]
fn ongoing_input_is_never_interrupted_however_long_it_lasts() {
    let mut scene = Scene::new(&["a"]);
    scene.human("a", InputKind::Pointer, InputPhase::Begin);
    scene.advance(5 * 60 * 1_000);
    assert_eq!(scene.state("a"), State::HumanOverride, "a five-minute drag");
    scene.human("a", InputKind::Pointer, InputPhase::End);
    scene.advance(QUIET_MS - 1);
    assert_eq!(scene.state("a"), State::Quiet);
    scene.advance(1);
    assert_eq!(scene.state("a"), State::Reobserve);
}

#[test]
fn a_write_planned_before_the_human_acted_is_refused_as_stale_after_the_quiet() {
    let mut scene = Scene::new(&["a"]);
    let planned_on = scene.epoch("a");
    scene.click("a");
    let fresh = scene.settle_and_reobserve("a");
    assert_eq!(
        scene.write("a", "fill", planned_on).err(),
        Some(Reason::TargetStale)
    );
    assert!(scene.write("a", "fill", fresh).is_ok());
}

#[test]
fn a_pending_write_is_invalidated_by_the_first_human_event() {
    // Ported from the donor's "a lock refuses from the moment it is taken":
    // a write the agent has not sent yet is refused at its dispatch check.
    let mut scene = Scene::new(&["a"]);
    let Ok(ticket) = scene.write("a", "fill", 0) else {
        panic!("running admits the write");
    };
    scene.click("a");
    let refused = scene.gate.confirm_dispatch(&ticket).map_err(|r| r.reason);
    assert_eq!(refused, Err(Reason::HumanOverride));
    scene.settle_and_reobserve("a");
    assert_eq!(
        scene.gate.confirm_dispatch(&ticket).map_err(|r| r.reason),
        Err(Reason::TargetStale),
        "still invalid after the quiet period"
    );
    assert_eq!(
        scene.gate.finish_write(&ticket, WriteOutcome::Done),
        WriteFate::NotPending
    );
}

#[test]
fn the_humans_edit_is_never_overwritten() {
    let mut scene = Scene::new(&["a"]);
    // The agent planned a fill of a field on the first observation.
    let basis = scene.observe("a").unwrap_or(u64::MAX);
    let Ok(ticket) = scene.write("a", "fill:email", basis) else {
        panic!("running admits the write");
    };
    // The approval prompt is up; meanwhile the human edits that field.
    scene.human("a", InputKind::Edit, InputPhase::Instant);
    assert!(
        scene.gate.confirm_dispatch(&ticket).is_err(),
        "the fill is never sent"
    );
    // Re-planning on a fresh observation is the only way to write again.
    let fresh = scene.settle_and_reobserve("a");
    assert_eq!(
        scene.write("a", "fill:email", basis).err(),
        Some(Reason::TargetStale)
    );
    assert!(scene.write("a", "fill:email", fresh).is_ok());
}

#[test]
fn a_write_in_flight_when_the_human_acts_is_reported_superseded() {
    let mut scene = Scene::new(&["a"]);
    let Ok(ticket) = scene.write("a", "click", 0) else {
        panic!("running admits the write");
    };
    assert_eq!(scene.gate.confirm_dispatch(&ticket), Ok(()));
    scene.click("a");
    assert_eq!(
        scene.gate.finish_write(&ticket, WriteOutcome::Done),
        WriteFate::Superseded
    );
}

#[test]
fn two_resources_are_independent() {
    let mut scene = Scene::new(&["a", "b"]);
    scene.human("a", InputKind::Text, InputPhase::Begin);
    for step in 0..20 {
        scene.advance(1_000);
        assert!(
            scene.write("a", "fill", scene.epoch("a")).is_err(),
            "step {step}"
        );
        let Ok(ticket) = scene.write("b", &format!("fill-{step}"), 0) else {
            panic!("the other page keeps running at step {step}");
        };
        assert_eq!(scene.gate.confirm_dispatch(&ticket), Ok(()));
        assert_eq!(
            scene.gate.finish_write(&ticket, WriteOutcome::Done),
            WriteFate::Recorded
        );
    }
    assert_eq!(scene.state("b"), State::Running);
    assert_eq!(scene.gate.check(&Target::NoPage, Effect::Write), Ok(()));
    let unmapped = scene.gate.check(&Target::UnmappedPage, Effect::Write);
    assert_eq!(
        unmapped.map_err(|r| (r.resource, r.reason)),
        Err((page("a"), Reason::HumanOverride)),
        "an operation whose page is unknown fails closed"
    );
}

#[test]
fn two_tasks_on_their_own_pages_are_independent() {
    let mut scene = Scene::new(&[]);
    let _ = scene.gate.claim(page("mission-1"), TaskId::new("one"));
    let _ = scene.gate.claim(page("mission-2"), TaskId::new("two"));
    let _ = scene.gate.challenge(
        &page("mission-1"),
        ChallengeKind::Mfa,
        ChallengeOrigin::Detected,
    );
    assert!(scene.write("mission-2", "fill", 0).is_ok());
    assert_eq!(scene.gate.needs_you(), vec![page("mission-1")]);
}

#[test]
fn human_input_on_a_page_no_task_owns_stops_nothing() {
    let mut scene = Scene::new(&["a"]);
    assert_eq!(scene.click("personal-tab"), InputVerdict::Unowned);
    assert!(scene.write("a", "fill", 0).is_ok());
}

#[test]
fn an_uncertain_submit_is_never_repeated() {
    let mut scene = Scene::new(&["a"]);
    let Ok(submit) = scene.write_as("a", "submit:order", ActionClass::Consequential, 0) else {
        panic!("running admits the submit");
    };
    assert_eq!(scene.gate.confirm_dispatch(&submit), Ok(()));
    assert_eq!(
        scene.gate.finish_write(&submit, WriteOutcome::Uncertain),
        WriteFate::Recorded
    );
    assert_eq!(
        scene
            .write_as("a", "submit:order", ActionClass::Consequential, 0)
            .err(),
        Some(Reason::OutcomeUncertain)
    );
    // Not even after a human intervention and a fresh plan.
    scene.click("a");
    let fresh = scene.settle_and_reobserve("a");
    assert_eq!(
        scene
            .write_as("a", "submit:order", ActionClass::Consequential, fresh)
            .err(),
        Some(Reason::OutcomeUncertain)
    );
    // Other actions go on.
    assert!(scene.write("a", "fill", fresh).is_ok());
    // Once its outcome is established, it may be sent again.
    assert!(scene
        .gate
        .reconcile(&page("a"), &common::key("submit:order")));
    assert!(scene
        .write_as("a", "submit:order", ActionClass::Consequential, fresh)
        .is_ok());
}

#[test]
fn a_consequential_action_in_flight_cannot_be_sent_twice() {
    let mut scene = Scene::new(&["a"]);
    let first = scene.write_as("a", "publish", ActionClass::Consequential, 0);
    assert!(first.is_ok());
    assert_eq!(
        scene
            .write_as("a", "publish", ActionClass::Consequential, 0)
            .err(),
        Some(Reason::OutcomeUncertain)
    );
}

#[test]
fn a_repeatable_action_with_an_uncertain_outcome_may_be_sent_again() {
    let mut scene = Scene::new(&["a"]);
    let Ok(fill) = scene.write("a", "fill", 0) else {
        panic!("running admits the fill");
    };
    let _ = scene.gate.confirm_dispatch(&fill);
    let _ = scene.gate.finish_write(&fill, WriteOutcome::Uncertain);
    assert!(scene.write("a", "fill", 0).is_ok());
}

#[test]
fn the_agents_own_input_is_told_from_the_humans() {
    let mut scene = Scene::new(&["a", "b"]);
    let marker = scene.gate.issue_marker(&page("a"));
    let agent_event = |marker: Option<AgentMarker>, resource: &str| ObservedInput {
        resource: page(resource),
        kind: InputKind::Pointer,
        phase: InputPhase::Instant,
        marker,
    };
    for _ in 0..3 {
        assert_eq!(
            scene
                .gate
                .observe_input(&agent_event(Some(marker.clone()), "a")),
            InputVerdict::Agent
        );
    }
    assert_eq!(
        scene.state("a"),
        State::Running,
        "injected input never pauses the agent"
    );
    assert_eq!(
        scene
            .gate
            .observe_input(&agent_event(Some(marker.clone()), "b")),
        InputVerdict::Human,
        "a marker issued for another page vouches for nothing there"
    );
    assert_eq!(scene.state("b"), State::HumanOverride);
    let mut tag = marker.tag;
    tag[31] ^= 0x80;
    let forged = AgentMarker {
        tag,
        ..marker.clone()
    };
    assert_eq!(
        scene.gate.observe_input(&agent_event(Some(forged), "a")),
        InputVerdict::Human
    );
    assert_eq!(scene.state("a"), State::HumanOverride);
}

#[test]
fn a_retired_marker_replayed_counts_as_human() {
    let mut scene = Scene::new(&["a"]);
    let marker = scene.gate.issue_marker(&page("a"));
    scene.gate.retire_marker(&marker);
    let replay = ObservedInput {
        resource: page("a"),
        kind: InputKind::Key,
        phase: InputPhase::Instant,
        marker: Some(marker),
    };
    assert_eq!(scene.gate.observe_input(&replay), InputVerdict::Human);
    assert_eq!(scene.state("a"), State::HumanOverride);
}

#[test]
fn a_challenge_is_handed_to_the_human_and_the_task_resumes_after_they_finish() {
    let mut scene = Scene::new(&["login", "other"]);
    // The engine detects an MFA prompt on the login page.
    let _ = scene.gate.challenge(
        &page("login"),
        ChallengeKind::Mfa,
        ChallengeOrigin::Detected,
    );
    assert_eq!(scene.gate.needs_you(), vec![page("login")]);
    // The agent can do nothing on that page, reads included.
    assert_eq!(
        scene.write("login", "fill:code", 1).err(),
        Some(Reason::AwaitingHumanVerification)
    );
    assert!(scene.gate.begin_read(&page("login")).is_err());
    // The other page keeps going.
    assert!(scene.write("other", "fill", 0).is_ok());
    // The human types the code and submits.
    scene.advance(5_000);
    scene.human("login", InputKind::Text, InputPhase::Begin);
    scene.advance(4_000);
    scene.human("login", InputKind::Text, InputPhase::End);
    scene.advance(200);
    scene.click("login");
    assert_eq!(
        scene.state("login"),
        State::AwaitHumanVerification(ChallengeKind::Mfa)
    );
    // The detector no longer sees the MFA prompt.
    assert_eq!(scene.gate.challenge_cleared(&page("login")), Ok(true));
    // Three quiet seconds later the agent observes again and resumes.
    let basis = scene.settle_and_reobserve("login");
    assert!(scene.write("login", "click:continue", basis).is_ok());
    assert_eq!(scene.state("login"), State::Running);
    assert!(scene.gate.needs_you().is_empty());
}
