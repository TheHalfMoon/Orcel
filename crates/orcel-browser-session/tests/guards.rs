//! The idempotency guard across page close and host restart, stable keys,
//! the caps that fail closed, ticket expiry and marker expiry.

mod common;

use common::{key, page, Scene};
use orcel_browser_session::{
    ActionClass, ControlError, InputKind, InputPhase, InputVerdict, ManualClock, ObservedInput,
    Reason, SessionGate, TaskId, UncertainLedger, WriteFate, WriteOutcome, MARKER_TTL_MS,
    MAX_LEDGER_ACTIONS, MAX_PENDING_WRITES, MAX_RESOURCES, MAX_UNCERTAIN_ACTIONS, PENDING_TTL_MS,
    UNSENT_TTL_MS,
};

/// The stable key of "press Enter in the textbox named Search on
/// https://shop.test/checkout", whatever the page or node is numbered.
const ENTER_SEARCH: &str = "https://shop.test|/checkout|enter|textbox|Search|1/1";

#[test]
fn a_lost_consequential_write_stays_refused_after_its_page_closes() {
    let mut scene = Scene::new(&["p1"]);
    let Ok(ticket) = scene.write_as("p1", "enter:n7", ActionClass::Consequential, 0) else {
        panic!("running admits the write");
    };
    assert_eq!(scene.gate.rekey(&ticket, key(ENTER_SEARCH)), Ok(()));
    assert_eq!(scene.gate.confirm_dispatch(&ticket), Ok(()));
    // The reply is lost; the host ends and the page closes before anyone
    // settles the ticket.
    assert_eq!(scene.gate.release(&page("p1")), Some(TaskId::new("task")));
    assert_eq!(
        scene.gate.finish_write(&ticket, WriteOutcome::Done),
        WriteFate::NotPending
    );
    // A new page, renumbered nodes: the same action is still refused.
    let _ = scene.gate.claim(page("p2"), TaskId::new("task"));
    let Ok(again) = scene.write_as("p2", "enter:n99", ActionClass::Consequential, 0) else {
        panic!("the provisional key is new");
    };
    assert_eq!(
        scene
            .gate
            .rekey(&again, key(ENTER_SEARCH))
            .map_err(|r| r.reason),
        Err(Reason::OutcomeUncertain)
    );
    assert_eq!(
        scene.gate.confirm_dispatch(&again).map_err(|r| r.reason),
        Err(Reason::TargetStale),
        "the refused ticket was invalidated"
    );
    // Until its outcome is reconciled.
    assert!(scene
        .gate
        .reconcile_task(&TaskId::new("task"), &key(ENTER_SEARCH)));
    assert!(scene
        .write_as("p2", ENTER_SEARCH, ActionClass::Consequential, 0)
        .is_ok());
}

#[test]
fn a_settled_uncertain_write_survives_a_host_restart_through_the_shared_ledger() {
    let ledger = UncertainLedger::shared();
    let clock = ManualClock::at(0);
    let task = TaskId::new("live");
    {
        let mut first = SessionGate::with_ledger(
            clock.clone(),
            orcel_browser_session::Reads::Block,
            ledger.clone(),
        );
        let _ = first.claim(page("p1"), task.clone());
        let ticket = first
            .begin_write(
                &page("p1"),
                key("download:n3"),
                ActionClass::Consequential,
                0,
            )
            .ok()
            .flatten();
        let Some(ticket) = ticket else {
            panic!("running admits the download");
        };
        let stable = key("https://files.test|/reports|download|https://files.test/a.pdf|a.pdf");
        assert_eq!(first.rekey(&ticket, stable), Ok(()));
        assert_eq!(first.confirm_dispatch(&ticket), Ok(()));
        assert_eq!(
            first.finish_write(&ticket, WriteOutcome::Uncertain),
            WriteFate::Recorded
        );
    }
    // The host restarts: a new gate, a new page, the same process ledger.
    let mut second =
        SessionGate::with_ledger(clock, orcel_browser_session::Reads::Block, ledger.clone());
    let _ = second.claim(page("p9"), task.clone());
    let stable = key("https://files.test|/reports|download|https://files.test/a.pdf|a.pdf");
    let refused = second.begin_write(&page("p9"), stable.clone(), ActionClass::Consequential, 0);
    assert_eq!(refused.map_err(|r| r.reason), Err(Reason::OutcomeUncertain));
    assert!(second.reconcile_task(&task, &stable));
    assert!(matches!(
        second.begin_write(&page("p9"), stable, ActionClass::Consequential, 0),
        Ok(Some(_))
    ));
}

#[test]
fn another_tasks_uncertain_action_does_not_block_this_task() {
    let mut scene = Scene::new(&[]);
    let _ = scene.gate.claim(page("a"), TaskId::new("one"));
    let _ = scene.gate.claim(page("b"), TaskId::new("two"));
    let Ok(ticket) = scene.write_as("a", "submit", ActionClass::Consequential, 0) else {
        panic!("running admits the write");
    };
    let _ = scene.gate.confirm_dispatch(&ticket);
    let _ = scene.gate.finish_write(&ticket, WriteOutcome::Uncertain);
    assert!(scene
        .write_as("b", "submit", ActionClass::Consequential, 0)
        .is_ok());
}

#[test]
fn rekey_refuses_a_duplicate_of_a_consequential_action_in_flight() {
    let mut scene = Scene::new(&["a"]);
    let first = scene.write_as("a", "enter:n1", ActionClass::Consequential, 0);
    let second = scene.write_as("a", "enter:n2", ActionClass::Consequential, 0);
    let (Ok(first), Ok(second)) = (first, second) else {
        panic!("two different provisional keys are admitted");
    };
    assert_eq!(scene.gate.rekey(&first, key(ENTER_SEARCH)), Ok(()));
    assert_eq!(
        scene
            .gate
            .rekey(&second, key(ENTER_SEARCH))
            .map_err(|r| r.reason),
        Err(Reason::OutcomeUncertain)
    );
}

#[test]
fn an_unsent_ticket_expires_and_a_sent_one_becomes_uncertain() {
    let mut scene = Scene::new(&["a"]);
    let Ok(unsent) = scene.write_as("a", "enter:unsent", ActionClass::Consequential, 0) else {
        panic!("running admits the write");
    };
    let Ok(sent) = scene.write_as("a", "enter:sent", ActionClass::Consequential, 0) else {
        panic!("running admits the write");
    };
    assert_eq!(scene.gate.confirm_dispatch(&sent), Ok(()));
    scene.advance(PENDING_TTL_MS);
    // The unsent ticket waits for its approval much longer.
    scene.advance(UNSENT_TTL_MS - PENDING_TTL_MS);
    assert_eq!(
        scene.gate.confirm_dispatch(&unsent).map_err(|r| r.reason),
        Err(Reason::TargetStale)
    );
    assert_eq!(
        scene.gate.finish_write(&sent, WriteOutcome::Done),
        WriteFate::NotPending
    );
    assert_eq!(
        scene
            .write_as("a", "enter:sent", ActionClass::Consequential, 0)
            .err(),
        Some(Reason::OutcomeUncertain),
        "a sent write whose outcome never came back is uncertain"
    );
    assert!(scene
        .write_as("a", "enter:unsent", ActionClass::Consequential, 0)
        .is_ok());
}

#[test]
fn a_slow_approval_does_not_age_the_sent_write() {
    let mut scene = Scene::new(&["a"]);
    let Ok(ticket) = scene.write_as("a", "enter:slow", ActionClass::Consequential, 0) else {
        panic!("running admits the write");
    };
    // The person takes ten minutes over the approval prompt.
    scene.advance(10 * 60 * 1_000);
    assert_eq!(scene.gate.confirm_dispatch(&ticket), Ok(()));
    // The outcome timer started at the confirmation.
    scene.advance(PENDING_TTL_MS - 1);
    assert_eq!(
        scene.gate.finish_write(&ticket, WriteOutcome::Done),
        WriteFate::Recorded
    );
    assert!(scene
        .write_as("a", "enter:slow", ActionClass::Consequential, 0)
        .is_ok());
}

#[test]
fn an_uncertain_action_lost_to_a_full_ledger_stays_refused_until_reconciled() {
    let ledger = UncertainLedger::shared();
    if let Ok(mut held) = ledger.lock() {
        for index in 0..MAX_LEDGER_ACTIONS - 1 {
            let _ = held.record(&TaskId::new("elsewhere"), key(&index.to_string()));
        }
    }
    let mut gate = SessionGate::with_ledger(
        ManualClock::at(0),
        orcel_browser_session::Reads::Block,
        ledger.clone(),
    );
    let task = TaskId::new("task");
    let _ = gate.claim(page("a"), task.clone());
    // Two submits are sent; the first fills the ledger, the second is lost
    // to it (it overflows) when its page closes.
    let tickets: Vec<_> = ["submit:1", "submit:2"]
        .iter()
        .filter_map(|action| {
            gate.begin_write(&page("a"), key(action), ActionClass::Consequential, 0)
                .ok()
                .flatten()
        })
        .collect();
    assert_eq!(tickets.len(), 2);
    for ticket in &tickets {
        assert_eq!(gate.confirm_dispatch(ticket), Ok(()));
    }
    let _ = gate.release(&page("a"));
    // Room frees up elsewhere; the lost submit is still not admitted.
    if let Ok(mut held) = ledger.lock() {
        assert!(held.reconcile(&TaskId::new("elsewhere"), &key("0")));
        assert!(held.reconcile(&TaskId::new("elsewhere"), &key("1")));
    }
    let _ = gate.claim(page("b"), task.clone());
    let refused = gate.begin_write(&page("b"), key("submit:2"), ActionClass::Consequential, 0);
    assert_eq!(refused.map_err(|r| r.reason), Err(Reason::OutcomeUncertain));
    let other = gate.begin_write(&page("b"), key("submit:3"), ActionClass::Consequential, 0);
    assert_eq!(
        other.map_err(|r| r.reason),
        Err(Reason::OutcomeUncertain),
        "the task cannot know which action was lost"
    );
    assert!(matches!(
        gate.begin_write(&page("b"), key("fill"), ActionClass::Repeatable, 0),
        Ok(Some(_))
    ));
    assert!(gate.reconcile_overflow(&task));
    assert!(matches!(
        gate.begin_write(&page("b"), key("submit:3"), ActionClass::Consequential, 0),
        Ok(Some(_))
    ));
}

#[test]
fn pending_writes_are_capped() {
    let mut scene = Scene::new(&["a"]);
    for index in 0..MAX_PENDING_WRITES {
        assert!(scene.write("a", &format!("fill-{index}"), 0).is_ok());
    }
    assert_eq!(
        scene.write("a", "fill-one-more", 0).err(),
        Some(Reason::TargetStale)
    );
}

#[test]
fn a_full_session_uncertain_set_refuses_every_consequential_write() {
    let mut scene = Scene::new(&["a"]);
    for index in 0..MAX_UNCERTAIN_ACTIONS {
        let action = format!("submit-{index}");
        let Ok(ticket) = scene.write_as("a", &action, ActionClass::Consequential, 0) else {
            panic!("admitted until full");
        };
        let _ = scene.gate.confirm_dispatch(&ticket);
        let _ = scene.gate.finish_write(&ticket, WriteOutcome::Uncertain);
    }
    assert_eq!(
        scene
            .write_as("a", "a-new-submit", ActionClass::Consequential, 0)
            .err(),
        Some(Reason::OutcomeUncertain)
    );
    assert!(
        scene.write("a", "fill", 0).is_ok(),
        "repeatable writes go on"
    );
}

#[test]
fn a_full_shared_ledger_refuses_every_consequential_write() {
    let ledger = UncertainLedger::shared();
    if let Ok(mut held) = ledger.lock() {
        for index in 0..MAX_LEDGER_ACTIONS {
            let _ = held.record(&TaskId::new("elsewhere"), key(&index.to_string()));
        }
    }
    let mut gate = SessionGate::with_ledger(
        ManualClock::at(0),
        orcel_browser_session::Reads::Block,
        ledger,
    );
    let _ = gate.claim(page("a"), TaskId::new("task"));
    let refused = gate.begin_write(&page("a"), key("submit"), ActionClass::Consequential, 0);
    assert_eq!(refused.map_err(|r| r.reason), Err(Reason::OutcomeUncertain));
}

#[test]
fn the_resource_map_is_capped() {
    let mut scene = Scene::new(&[]);
    for index in 0..MAX_RESOURCES {
        assert_eq!(
            scene
                .gate
                .claim(page(&format!("p{index}")), TaskId::new("task")),
            Ok(())
        );
    }
    assert_eq!(
        scene.gate.claim(page("one-more"), TaskId::new("task")),
        Err(ControlError::Full)
    );
}

#[test]
fn an_expired_marker_counts_as_human() {
    let mut scene = Scene::new(&["a"]);
    let marker = scene.gate.issue_marker(&page("a"));
    scene.advance(MARKER_TTL_MS);
    let late = ObservedInput {
        resource: page("a"),
        kind: InputKind::Pointer,
        phase: InputPhase::Instant,
        marker: Some(marker),
    };
    assert_eq!(scene.gate.observe_input(&late), InputVerdict::Human);
}
