//! SG-000120 RJ-03: the resume summary's classification.
//!
//! Ported from BuilderIO/agent-native at commit
//! 9c277b79cb87eb27da538e572dd710986e2fa06d,
//! `packages/core/src/agent/tool-call-journal.ts` (blob
//! be77f428f557b2e777665bfacd0d6dd51a58ff1d), MIT, Copyright (c) Builder.io;
//! notice: `docs/orcel/notices/agent-native-MIT.txt`. What is kept: steps
//! are paired start-to-finish in order; a finished step whose side effect
//! happened is completed (never to be re-run); a step that never ran is
//! dropped; a step that started without a recorded result, or whose result
//! is unknown, is interrupted and must be verified, never assumed done or
//! not done; and the resume note's wording. Orcel's changes: steps carry
//! a keyed input fingerprint the caller computes (never the input itself:
//! no input signature, display text or result text is kept), finishes are
//! typed instead of inferred from result strings, each unknown step names
//! the check that settles it, and the note is bounded.

/// How a started step ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    /// The side effect happened (or the step only read): never re-run it.
    Completed,
    /// The step never acted (refused, denied, nothing written).
    NotRun,
    /// It may or may not have acted.
    Unknown,
}

/// One event of a task, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeEvent {
    Started {
        /// Unique within the task.
        key: String,
        kind: String,
        /// A keyed hash of the step's identifying inputs; `None` when the
        /// input must not be fingerprinted (clipboard, secret-typed).
        fingerprint: Option<String>,
        /// What would settle this step if its outcome is unknown.
        verification: String,
    },
    Finished {
        key: String,
        finish: Finish,
        /// The recorded outcome (an identifier such as `verified`).
        outcome: String,
    },
}

/// One classified step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeEntry {
    pub key: String,
    pub kind: String,
    pub fingerprint: Option<String>,
    /// The recorded outcome, or `None` when none was recorded.
    pub outcome: Option<String>,
    pub verification: String,
}

/// Completed and interrupted-or-unknown steps, each in start order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResumeSummary {
    pub completed: Vec<ResumeEntry>,
    pub unknown: Vec<ResumeEntry>,
}

/// Pairs each finish with its start. A finish without a matching open
/// start is ignored; a start without a finish is interrupted (unknown).
pub fn classify(events: &[ResumeEvent]) -> ResumeSummary {
    let mut open: Vec<ResumeEntry> = Vec::new();
    let mut summary = ResumeSummary::default();
    for event in events {
        match event {
            ResumeEvent::Started {
                key,
                kind,
                fingerprint,
                verification,
            } => {
                // A repeated key restarts the step: the earlier start is
                // still open and stays interrupted.
                open.push(ResumeEntry {
                    key: key.clone(),
                    kind: kind.clone(),
                    fingerprint: fingerprint.clone(),
                    outcome: None,
                    verification: verification.clone(),
                });
            }
            ResumeEvent::Finished {
                key,
                finish,
                outcome,
            } => {
                let Some(position) = open.iter().rposition(|entry| &entry.key == key) else {
                    continue;
                };
                let mut entry = open.remove(position);
                entry.outcome = Some(outcome.clone());
                match finish {
                    Finish::Completed => summary.completed.push(entry),
                    Finish::NotRun => {}
                    Finish::Unknown => summary.unknown.push(entry),
                }
            }
        }
    }
    summary.unknown.extend(open);
    summary
}

/// The checks that settle the unknown steps, without repeats.
pub fn next_verification(summary: &ResumeSummary) -> Vec<String> {
    let mut checks: Vec<String> = Vec::new();
    for entry in &summary.unknown {
        if !checks.contains(&entry.verification) {
            checks.push(entry.verification.clone());
        }
    }
    checks
}

/// Longest resume note, in bytes.
pub const MAX_NOTE_BYTES: usize = 4096;

/// The resume note for a reconnecting client: what is done and must not be
/// repeated, and what is unknown and must be verified first. `None` when
/// nothing was recorded.
pub fn note(summary: &ResumeSummary) -> Option<String> {
    if summary.completed.is_empty() && summary.unknown.is_empty() {
        return None;
    }
    let mut lines =
        vec!["Steps of the interrupted task (from orceld's durable journal):".to_owned()];
    if !summary.completed.is_empty() {
        lines.push(String::new());
        lines.push(
            "Already completed (do NOT re-run these; their side effects already happened):"
                .to_owned(),
        );
        for entry in &summary.completed {
            lines.push(format!(
                "- {} -> {}",
                entry.kind,
                entry.outcome.as_deref().unwrap_or("no result recorded")
            ));
        }
    }
    if !summary.unknown.is_empty() {
        lines.push(String::new());
        lines.push(
            "Interrupted / unknown outcome (do not assume they succeeded OR failed; verify the \
             state before anything that could repeat a side effect):"
                .to_owned(),
        );
        for entry in &summary.unknown {
            lines.push(format!(
                "- {} -> {}; verify: {}",
                entry.kind,
                entry.outcome.as_deref().unwrap_or("no result recorded"),
                entry.verification
            ));
        }
    }
    let mut note = lines.join("\n");
    if note.len() > MAX_NOTE_BYTES {
        let mut end = MAX_NOTE_BYTES - 3;
        while !note.is_char_boundary(end) {
            end -= 1;
        }
        note.truncate(end);
        note.push_str("...");
    }
    Some(note)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(key: &str, kind: &str) -> ResumeEvent {
        ResumeEvent::Started {
            key: key.into(),
            kind: kind.into(),
            fingerprint: Some(format!("fp-{key}")),
            verification: format!("check {key}"),
        }
    }

    fn finish(key: &str, finish: Finish, outcome: &str) -> ResumeEvent {
        ResumeEvent::Finished {
            key: key.into(),
            finish,
            outcome: outcome.into(),
        }
    }

    #[test]
    fn completed_unknown_and_not_run_are_told_apart() {
        let summary = classify(&[
            start("s1", "observe"),
            finish("s1", Finish::Completed, "ok"),
            start("s2", "commit"),
            finish("s2", Finish::NotRun, "approval_denied"),
            start("s3", "commit"),
            finish("s3", Finish::Unknown, "write_failed"),
            start("s4", "commit"),
        ]);
        let keys = |entries: &[ResumeEntry]| {
            entries
                .iter()
                .map(|entry| entry.key.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(&summary.completed), ["s1"]);
        assert_eq!(
            keys(&summary.unknown),
            ["s3", "s4"],
            "an interrupted step is unknown, never completed"
        );
        assert_eq!(summary.unknown[1].outcome, None);
        assert_eq!(next_verification(&summary), ["check s3", "check s4"]);
    }

    #[test]
    fn a_finish_without_a_start_proves_nothing() {
        let summary = classify(&[finish("ghost", Finish::Completed, "verified")]);
        assert!(summary.completed.is_empty() && summary.unknown.is_empty());
        assert_eq!(note(&summary), None);
    }

    #[test]
    fn the_note_says_what_not_to_repeat_and_what_to_verify_and_is_bounded() {
        let summary = classify(&[
            start("s1", "preview"),
            finish("s1", Finish::Completed, "ok"),
            start("s2", "commit"),
        ]);
        let text = note(&summary).unwrap();
        assert!(text.contains("do NOT re-run"));
        assert!(text.contains("do not assume they succeeded OR failed"));
        assert!(text.contains("verify: check s2"));
        let many: Vec<ResumeEvent> = (0..500)
            .map(|n| start(&format!("k{n}"), "commit"))
            .collect();
        let long = note(&classify(&many)).unwrap();
        assert!(long.len() <= MAX_NOTE_BYTES);
    }
}
