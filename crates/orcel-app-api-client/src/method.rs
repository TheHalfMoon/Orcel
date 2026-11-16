//! The closed set of methods the Control Room sends. A method is an enum
//! variant, never a string: there is no way to build a request for any name
//! outside [`Method::NAMES`], so `task.stop`, `approval.history`,
//! `clients.list` and every name orceld answers `UNKNOWN_METHOD` cannot be
//! serialized, let alone sent.

use crate::cursor::Cursor;
use crate::sanitize::rules;
use serde_json::{json, Value};

/// The protocol every frame carries in `v`.
pub const PROTOCOL: &str = "orcel-app-api/1";

/// A task id under the identifier rule (1 to 128 of `[A-Za-z0-9_-]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskId(String);

impl TaskId {
    pub fn parse(value: &str) -> Option<Self> {
        rules::identifier(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One request the Control Room can make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    StatusGet,
    CapabilitiesGet,
    /// From the start of orceld's ring (`None`), or after a cursor of a
    /// known epoch.
    EventsSubscribe(Option<Cursor>),
    TaskList,
    TaskGet(TaskId),
}

impl Method {
    /// Every name this client can send.
    pub const NAMES: [&'static str; 5] = [
        "status.get",
        "capabilities.get",
        "events.subscribe",
        "task.list",
        "task.get",
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Method::StatusGet => Self::NAMES[0],
            Method::CapabilitiesGet => Self::NAMES[1],
            Method::EventsSubscribe(_) => Self::NAMES[2],
            Method::TaskList => Self::NAMES[3],
            Method::TaskGet(_) => Self::NAMES[4],
        }
    }

    fn params(&self) -> Value {
        match self {
            Method::StatusGet | Method::CapabilitiesGet | Method::TaskList => json!({}),
            Method::EventsSubscribe(None) => json!({ "after_seq": 0 }),
            Method::EventsSubscribe(Some(cursor)) => {
                json!({ "after_seq": cursor.after_seq(), "epoch": cursor.epoch() })
            }
            Method::TaskGet(task_id) => json!({ "task_id": task_id.as_str() }),
        }
    }

    /// The request frame's JSON, with a numeric `id`.
    pub(crate) fn request(&self, id: u64) -> Value {
        json!({
            "v": PROTOCOL,
            "id": id,
            "method": self.name(),
            "params": self.params(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant, matched exhaustively: a new variant fails to compile
    /// here until it is added to this list and to [`Method::NAMES`].
    fn every_method() -> Vec<Method> {
        let all = vec![
            Method::StatusGet,
            Method::CapabilitiesGet,
            Method::EventsSubscribe(None),
            Method::TaskList,
            Method::TaskGet(TaskId::parse("t1").unwrap()),
        ];
        for method in &all {
            match method {
                Method::StatusGet
                | Method::CapabilitiesGet
                | Method::EventsSubscribe(_)
                | Method::TaskList
                | Method::TaskGet(_) => {}
            }
        }
        all
    }

    #[test]
    fn only_the_five_read_methods_can_be_built() {
        let names: Vec<&str> = every_method().iter().map(Method::name).collect();
        assert_eq!(names, Method::NAMES);
        assert_eq!(
            Method::NAMES,
            [
                "status.get",
                "capabilities.get",
                "events.subscribe",
                "task.list",
                "task.get"
            ]
        );
    }

    #[test]
    fn no_other_method_name_is_in_the_crates_code() {
        // Code lines only (comments may name what is excluded), outside
        // test modules.
        let sources = [
            ("method.rs", include_str!("method.rs")),
            ("client.rs", include_str!("client.rs")),
            ("subscription.rs", include_str!("subscription.rs")),
            ("transport.rs", include_str!("transport.rs")),
            ("frame.rs", include_str!("frame.rs")),
        ];
        for (file, source) in sources {
            // "\nmod tests {" also matches a CRLF checkout.
            let code = source.split("\nmod tests {").next().unwrap();
            for line in code.lines().filter(|l| !l.trim_start().starts_with("//")) {
                for name in [
                    "task.stop",
                    "approval.history",
                    "clients.list",
                    "devices.list",
                    "task.submit",
                    "approval.grant",
                ] {
                    assert!(!line.contains(name), "{file} names {name}: {line}");
                }
            }
        }
    }

    #[test]
    fn requests_carry_exactly_their_typed_parameters() {
        assert_eq!(
            Method::StatusGet.request(1),
            json!({"v": PROTOCOL, "id": 1, "method": "status.get", "params": {}})
        );
        let cursor = Cursor::new("1a-2b", 9).unwrap();
        assert_eq!(
            Method::EventsSubscribe(Some(cursor)).request(2)["params"],
            json!({"after_seq": 9, "epoch": "1a-2b"})
        );
        assert_eq!(
            Method::EventsSubscribe(None).request(3)["params"],
            json!({"after_seq": 0})
        );
        assert_eq!(
            Method::TaskGet(TaskId::parse("r-1").unwrap()).request(4)["params"],
            json!({"task_id": "r-1"})
        );
        assert!(TaskId::parse("../x").is_none());
        assert!(TaskId::parse("").is_none());
        assert!(TaskId::parse(&"a".repeat(129)).is_none());
    }
}
