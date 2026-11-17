//! Every transition of one resource's state machine, driven through the
//! gate on a manual clock.
//!
//! The tests marked "Ported from the donor" carry over cases of BrowserOS's
//! `packages/browseros-agent/crates/neo-sdk/neo-takeover/tests/locks.rs`
//! (blob b6bd7ff1ea702a3487d902ee4903740cce08bba7, commit bd725831,
//! AGPL-3.0-or-later upstream; notice:
//! `docs/orcel/notices/browseros-AGPL-3.0.txt`), rewritten for the state
//! machine and the manual clock.

mod common;

use common::{key, page, Scene};
use orcel_browser_session::{
    ChallengeKind, ChallengeOrigin, ControlError, Effect, InputKind, InputPhase, InputVerdict,
    Reason, State, Target, TaskId, WriteFate, WriteOutcome, QUIET_MS,
};

#[test]
fn a_claimed_resource_starts_running_at_epoch_zero_and_admits_reads_and_writes() {
    let mut scene = Scene::new(&["a"]);
    assert_eq!(scene.state("a"), State::Running);
    assert_eq!(scene.epoch("a"), 0);
    assert_eq!(
        scene.gate.check(&Target::Resource(page("a")), Effect::Read),
        Ok(())
    );
    assert!(scene.write("a", "fill", 0).is_ok());
}

#[test]
fn running_to_human_override_on_the_first_human_event() {
    let mut scene = Scene::new(&["a"]);
    scene.at(100);
    assert_eq!(scene.click("a"), InputVerdict::Human);
    assert_eq!(scene.state("a"), State::HumanOverride);
    assert_eq!(scene.epoch("a"), 1, "a new intervention bumps the epoch");
    assert_eq!(
        scene.write("a", "fill", 0).err(),
        Some(Reason::HumanOverride)
    );
    let read = scene.gate.check(&Target::Resource(page("a")), Effect::Read);
    assert_eq!(
        read.map_err(|r| r.reason),
        Err(Reason::HumanOverride),
        "reads are blocked by default"
    );
}

#[test]
fn human_override_to_quiet_once_the_input_stops() {
    let mut scene = Scene::new(&["a"]);
    scene.at(100);
    scene.click("a");
    assert_eq!(scene.state("a"), State::HumanOverride);
    scene.at(101);
    assert_eq!(scene.state("a"), State::Quiet);
    assert_eq!(scene.write("a", "fill", 1).err(), Some(Reason::Quiet));
}

#[test]
fn quiet_to_reobserve_exactly_three_seconds_after_the_last_human_event() {
    let mut scene = Scene::new(&["a"]);
    scene.at(1_000);
    scene.click("a");
    scene.at(1_000 + QUIET_MS - 1);
    assert_eq!(scene.state("a"), State::Quiet);
    scene.at(1_000 + QUIET_MS);
    assert_eq!(scene.state("a"), State::Reobserve);
}

#[test]
fn reobserve_admits_reads_and_refuses_writes() {
    let mut scene = Scene::new(&["a"]);
    scene.click("a");
    scene.advance(QUIET_MS);
    assert_eq!(scene.state("a"), State::Reobserve);
    assert_eq!(
        scene.gate.check(&Target::Resource(page("a")), Effect::Read),
        Ok(())
    );
    assert_eq!(
        scene.write("a", "fill", 1).err(),
        Some(Reason::ReobserveRequired)
    );
}

#[test]
fn reobserve_to_replan_on_a_fresh_observation_and_replan_to_running_on_a_write_planned_on_it() {
    let mut scene = Scene::new(&["a"]);
    scene.click("a");
    let basis = scene.settle_and_reobserve("a");
    assert_eq!(basis, 1);
    let replan = scene
        .gate
        .check(&Target::Resource(page("a")), Effect::Write);
    assert_eq!(replan.map_err(|r| r.reason), Err(Reason::ReplanRequired));
    assert!(scene.write("a", "fill", basis).is_ok());
    assert_eq!(scene.state("a"), State::Running);
}

#[test]
fn replan_refuses_a_write_planned_before_the_intervention() {
    let mut scene = Scene::new(&["a"]);
    scene.click("a");
    scene.settle_and_reobserve("a");
    assert_eq!(scene.write("a", "fill", 0).err(), Some(Reason::TargetStale));
    assert_eq!(
        scene.state("a"),
        State::Replan,
        "a stale write does not end the replan"
    );
}

#[test]
fn quiet_back_to_human_override_on_any_human_event() {
    let mut scene = Scene::new(&["a"]);
    scene.click("a");
    scene.advance(1_500);
    assert_eq!(scene.state("a"), State::Quiet);
    scene.human("a", InputKind::Scroll, InputPhase::Instant);
    assert_eq!(scene.state("a"), State::HumanOverride);
    assert_eq!(scene.epoch("a"), 1, "the same intervention continues");
}

#[test]
fn a_human_event_during_reobserve_starts_a_new_intervention_and_stales_the_observation() {
    let mut scene = Scene::new(&["a"]);
    scene.click("a");
    scene.advance(QUIET_MS);
    let ticket = scene.gate.begin_read(&page("a")).ok().flatten();
    let Some(ticket) = ticket else {
        panic!("reobserve admits a read");
    };
    scene.click("a");
    assert_eq!(scene.epoch("a"), 2);
    assert_eq!(scene.gate.observation_completed(&ticket), None);
    assert_eq!(scene.state("a"), State::HumanOverride);
}

#[test]
fn a_human_event_during_replan_starts_a_new_intervention() {
    let mut scene = Scene::new(&["a"]);
    scene.click("a");
    let basis = scene.settle_and_reobserve("a");
    scene.click("a");
    assert_eq!(scene.state("a"), State::HumanOverride);
    assert_eq!(scene.epoch("a"), basis + 1);
}

#[test]
fn running_to_await_human_verification_when_a_challenge_is_detected_or_requested() {
    for origin in [ChallengeOrigin::Detected, ChallengeOrigin::Requested] {
        let mut scene = Scene::new(&["a"]);
        assert_eq!(
            scene.gate.challenge(&page("a"), ChallengeKind::Mfa, origin),
            Ok(())
        );
        assert_eq!(
            scene.state("a"),
            State::AwaitHumanVerification(ChallengeKind::Mfa)
        );
        assert_eq!(scene.epoch("a"), 1);
        assert_eq!(scene.gate.needs_you(), vec![page("a")]);
        assert_eq!(
            scene.write("a", "fill", 1).err(),
            Some(Reason::AwaitingHumanVerification)
        );
        let read = scene.gate.check(&Target::Resource(page("a")), Effect::Read);
        assert_eq!(
            read.map_err(|r| r.reason),
            Err(Reason::AwaitingHumanVerification)
        );
    }
}

#[test]
fn await_never_resumes_on_its_own_without_the_human_or_the_detector() {
    let mut scene = Scene::new(&["a"]);
    let _ = scene.gate.challenge(
        &page("a"),
        ChallengeKind::Captcha,
        ChallengeOrigin::Detected,
    );
    scene.advance(60 * 60 * 1_000);
    assert_eq!(
        scene.state("a"),
        State::AwaitHumanVerification(ChallengeKind::Captcha)
    );
}

#[test]
fn await_resumes_only_after_the_detector_clears_it_and_the_human_is_quiet() {
    let mut scene = Scene::new(&["a"]);
    let _ = scene.gate.challenge(
        &page("a"),
        ChallengeKind::Passkey,
        ChallengeOrigin::Detected,
    );
    scene.at(500);
    scene.click("a");
    scene.at(60 * 60 * 1_000);
    assert_eq!(
        scene.state("a"),
        State::AwaitHumanVerification(ChallengeKind::Passkey),
        "the human's activity alone never ends the wait: the challenge may still be up"
    );
    scene.at(60 * 60 * 1_000 + 10);
    scene.click("a");
    assert_eq!(scene.gate.challenge_cleared(&page("a")), Ok(true));
    scene.advance(QUIET_MS - 1);
    assert_eq!(
        scene.state("a"),
        State::AwaitHumanVerification(ChallengeKind::Passkey)
    );
    scene.advance(1);
    assert_eq!(scene.state("a"), State::Reobserve);
    assert!(scene.gate.needs_you().is_empty());
}

#[test]
fn a_human_event_after_the_detector_cleared_pushes_the_resume_back() {
    let mut scene = Scene::new(&["a"]);
    let _ = scene
        .gate
        .challenge(&page("a"), ChallengeKind::Mfa, ChallengeOrigin::Detected);
    let _ = scene.gate.challenge_cleared(&page("a"));
    scene.advance(2_000);
    scene.click("a");
    scene.advance(QUIET_MS - 1);
    assert_eq!(
        scene.state("a"),
        State::AwaitHumanVerification(ChallengeKind::Mfa)
    );
    scene.advance(1);
    assert_eq!(scene.state("a"), State::Reobserve);
}

#[test]
fn a_takeover_of_a_paused_challenge_keeps_the_challenge() {
    let mut scene = Scene::new(&["a"]);
    let _ = scene.gate.challenge(
        &page("a"),
        ChallengeKind::Captcha,
        ChallengeOrigin::Detected,
    );
    let _ = scene.gate.pause(&page("a"));
    assert_eq!(scene.gate.take_over(&page("a")), Ok(()));
    assert_eq!(
        scene.state("a"),
        State::AwaitHumanVerification(ChallengeKind::Captcha)
    );
    let _ = scene.gate.return_control(&page("a"));
    scene.advance(10 * QUIET_MS);
    assert_eq!(
        scene.state("a"),
        State::AwaitHumanVerification(ChallengeKind::Captcha),
        "handing back without the detector's report does not end the wait"
    );
    let _ = scene.gate.challenge_cleared(&page("a"));
    scene.advance(QUIET_MS);
    assert_eq!(scene.state("a"), State::Reobserve);
}

#[test]
fn await_resumes_after_the_detector_clears_it_but_never_under_ongoing_input() {
    let mut scene = Scene::new(&["a"]);
    let _ = scene
        .gate
        .challenge(&page("a"), ChallengeKind::Mfa, ChallengeOrigin::Detected);
    scene.human("a", InputKind::Text, InputPhase::Begin);
    scene.advance(100);
    assert_eq!(scene.gate.challenge_cleared(&page("a")), Ok(true));
    scene.advance(10 * QUIET_MS);
    assert_eq!(
        scene.state("a"),
        State::AwaitHumanVerification(ChallengeKind::Mfa),
        "the human is still typing"
    );
    scene.human("a", InputKind::Text, InputPhase::End);
    scene.advance(QUIET_MS - 1);
    assert_eq!(
        scene.state("a"),
        State::AwaitHumanVerification(ChallengeKind::Mfa)
    );
    scene.advance(1);
    assert_eq!(scene.state("a"), State::Reobserve);
}

#[test]
fn a_repeated_challenge_reattaches_without_restarting_the_wait() {
    let mut scene = Scene::new(&["a"]);
    let _ = scene.gate.challenge(
        &page("a"),
        ChallengeKind::SignIn,
        ChallengeOrigin::Requested,
    );
    scene.click("a");
    let _ = scene.gate.challenge(
        &page("a"),
        ChallengeKind::Captcha,
        ChallengeOrigin::Detected,
    );
    assert_eq!(
        scene.state("a"),
        State::AwaitHumanVerification(ChallengeKind::SignIn),
        "the open request is kept as it was"
    );
    assert_eq!(scene.epoch("a"), 1);
    let _ = scene.gate.challenge_cleared(&page("a"));
    let _ = scene.gate.challenge(
        &page("a"),
        ChallengeKind::Captcha,
        ChallengeOrigin::Detected,
    );
    scene.advance(QUIET_MS);
    assert_eq!(
        scene.state("a"),
        State::Reobserve,
        "a repeated request does not undo the detector's report"
    );
}

#[test]
fn pause_refuses_everything_and_resume_goes_through_reobserve() {
    let mut scene = Scene::new(&["a"]);
    assert_eq!(scene.gate.pause(&page("a")), Ok(()));
    assert_eq!(scene.state("a"), State::Paused);
    assert_eq!(scene.epoch("a"), 1);
    assert_eq!(scene.write("a", "fill", 0).err(), Some(Reason::Paused));
    let read = scene.gate.check(&Target::Resource(page("a")), Effect::Read);
    assert_eq!(read.map_err(|r| r.reason), Err(Reason::Paused));
    assert_eq!(scene.gate.pause(&page("a")), Ok(()), "pause is idempotent");
    scene.advance(10_000);
    assert_eq!(scene.gate.resume(&page("a")), Ok(()));
    assert_eq!(
        scene.state("a"),
        State::Reobserve,
        "no human activity: observe again at once"
    );
}

#[test]
fn resume_waits_out_the_quiet_period_after_recent_human_activity() {
    let mut scene = Scene::new(&["a"]);
    let _ = scene.gate.pause(&page("a"));
    scene.at(1_000);
    scene.click("a");
    assert_eq!(scene.state("a"), State::Paused);
    scene.at(2_000);
    assert_eq!(scene.gate.resume(&page("a")), Ok(()));
    assert_eq!(scene.state("a"), State::Quiet);
    scene.at(1_000 + QUIET_MS);
    assert_eq!(scene.state("a"), State::Reobserve);
}

#[test]
fn a_paused_challenge_is_waited_on_again_after_resume() {
    let mut scene = Scene::new(&["a"]);
    let _ = scene
        .gate
        .challenge(&page("a"), ChallengeKind::Mfa, ChallengeOrigin::Detected);
    let _ = scene.gate.pause(&page("a"));
    assert_eq!(scene.gate.needs_you(), vec![page("a")]);
    let _ = scene.gate.resume(&page("a"));
    assert_eq!(
        scene.state("a"),
        State::AwaitHumanVerification(ChallengeKind::Mfa)
    );

    let mut scene = Scene::new(&["b"]);
    let _ = scene.gate.pause(&page("b"));
    let _ = scene.gate.challenge(
        &page("b"),
        ChallengeKind::Captcha,
        ChallengeOrigin::Detected,
    );
    assert_eq!(scene.state("b"), State::Paused);
    let _ = scene.gate.resume(&page("b"));
    assert_eq!(
        scene.state("b"),
        State::AwaitHumanVerification(ChallengeKind::Captcha)
    );
}

#[test]
fn resume_of_a_resource_that_is_not_paused_is_refused() {
    let mut scene = Scene::new(&["a"]);
    assert_eq!(scene.gate.resume(&page("a")), Err(ControlError::NotPaused));
    assert_eq!(
        scene.gate.resume(&page("zz")),
        Err(ControlError::UnknownResource)
    );
}

#[test]
fn cancel_is_terminal() {
    let mut scene = Scene::new(&["a"]);
    let pending = scene.write("a", "submit", 0);
    assert_eq!(scene.gate.cancel(&page("a")), Ok(()));
    assert_eq!(scene.state("a"), State::Cancelled);
    assert_eq!(scene.write("a", "fill", 0).err(), Some(Reason::Cancelled));
    let read = scene.gate.check(&Target::Resource(page("a")), Effect::Read);
    assert_eq!(read.map_err(|r| r.reason), Err(Reason::Cancelled));
    assert_eq!(scene.click("a"), InputVerdict::Human);
    assert_eq!(
        scene.state("a"),
        State::Cancelled,
        "human input does not revive it"
    );
    for control in [
        scene.gate.pause(&page("a")),
        scene.gate.resume(&page("a")),
        scene.gate.take_over(&page("a")),
        scene.gate.return_control(&page("a")),
        scene
            .gate
            .challenge(&page("a"), ChallengeKind::Other, ChallengeOrigin::Requested),
    ] {
        assert_eq!(control, Err(ControlError::Cancelled));
    }
    if let Ok(ticket) = pending {
        assert!(
            scene.gate.confirm_dispatch(&ticket).is_err(),
            "pending writes are dropped"
        );
        assert_eq!(
            scene.gate.finish_write(&ticket, WriteOutcome::Done),
            WriteFate::NotPending
        );
    }
}

#[test]
fn an_explicit_takeover_holds_until_the_human_gives_it_back() {
    let mut scene = Scene::new(&["a"]);
    assert_eq!(scene.gate.take_over(&page("a")), Ok(()));
    assert_eq!(scene.state("a"), State::HumanOverride);
    scene.advance(10 * 60 * 1_000);
    assert_eq!(
        scene.state("a"),
        State::HumanOverride,
        "ten idle minutes do not end it"
    );
    assert_eq!(scene.gate.return_control(&page("a")), Ok(()));
    scene.advance(1);
    assert_eq!(scene.state("a"), State::Quiet);
    scene.advance(QUIET_MS);
    assert_eq!(scene.state("a"), State::Reobserve);
}

#[test]
fn a_takeover_is_not_ended_by_pause_and_resume() {
    // Ported from the donor's "the host ends its own locks but never a
    // takeover's": only the human's own hand-back ends an explicit takeover.
    let mut scene = Scene::new(&["a"]);
    let _ = scene.gate.take_over(&page("a"));
    let _ = scene.gate.pause(&page("a"));
    let _ = scene.gate.resume(&page("a"));
    scene.advance(60_000);
    assert_eq!(scene.state("a"), State::HumanOverride);
}

#[test]
fn a_takeover_of_a_paused_resource_hands_it_to_the_human() {
    let mut scene = Scene::new(&["a"]);
    let _ = scene.gate.pause(&page("a"));
    let _ = scene.gate.take_over(&page("a"));
    assert_eq!(scene.state("a"), State::HumanOverride);
    let _ = scene.gate.return_control(&page("a"));
    scene.advance(QUIET_MS);
    assert_eq!(scene.state("a"), State::Reobserve);
}

#[test]
fn the_quiet_period_is_judged_when_asked_so_a_late_tick_never_extends_it() {
    // Ported from the donor's rule that deadlines, not timers, end a lock.
    let mut scene = Scene::new(&["a"]);
    scene.click("a");
    scene.advance(3 * QUIET_MS);
    assert_eq!(scene.state("a"), State::Reobserve, "no tick ran in between");
}

#[test]
fn releasing_a_resource_ends_its_session_and_a_reused_id_starts_fresh() {
    // Ported from the donor's "closing a tab ends every lock on it".
    let mut scene = Scene::new(&["a"]);
    scene.click("a");
    assert_eq!(scene.gate.release(&page("a")), Some(TaskId::new("task")));
    assert_eq!(scene.gate.state(&page("a")), None);
    assert_eq!(scene.click("a"), InputVerdict::Unowned);
    assert_eq!(scene.gate.claim(page("a"), TaskId::new("task")), Ok(()));
    assert_eq!(scene.state("a"), State::Running);
    assert_eq!(scene.epoch("a"), 0);
}

#[test]
fn a_resource_owned_by_one_task_cannot_be_claimed_by_another() {
    let mut scene = Scene::new(&["a"]);
    assert_eq!(scene.gate.claim(page("a"), TaskId::new("task")), Ok(()));
    assert_eq!(
        scene.gate.claim(page("a"), TaskId::new("other")),
        Err(ControlError::OwnedByAnotherTask)
    );
    assert_eq!(scene.gate.owner(&page("a")), Some(&TaskId::new("task")));
}

#[test]
fn agent_calls_never_end_a_human_hold() {
    let mut scene = Scene::new(&["a"]);
    scene.human("a", InputKind::Key, InputPhase::Begin);
    for _ in 0..5 {
        let _ = scene.write("a", "fill", 1);
        let _ = scene.gate.begin_read(&page("a"));
        let _ = scene.gate.check(&Target::UnmappedPage, Effect::Write);
        let _ = scene.gate.reconcile(&page("a"), &key("fill"));
        scene.advance(QUIET_MS);
    }
    assert_eq!(scene.state("a"), State::HumanOverride);
}
