//! Framing: UTF-8 JSON, one object per line, at most 65,536 bytes per frame
//! with its newline, in both directions (protocol section 3). The reader
//! never holds more than one frame of unread input and refuses a longer one.

use crate::error::{error_code, ClientError};
use crate::method::PROTOCOL;
use serde_json::Value;
use std::io::{self, Read, Write};

/// The largest frame either side may send, newline included.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Reads newline-terminated frames.
#[derive(Debug, Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// The next frame without its newline (and a `\r` before it), or `None`
    /// at the end of the stream.
    pub fn next(&mut self, source: &mut impl Read) -> Result<Option<Vec<u8>>, ClientError> {
        loop {
            if let Some(end) = self.buf.iter().position(|byte| *byte == b'\n') {
                if end + 1 > MAX_FRAME_BYTES {
                    return Err(ClientError::FrameTooLarge);
                }
                let mut frame: Vec<u8> = self.buf.drain(..=end).collect();
                frame.pop();
                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                return Ok(Some(frame));
            }
            if self.buf.len() >= MAX_FRAME_BYTES {
                return Err(ClientError::FrameTooLarge);
            }
            let mut chunk = [0u8; 8192];
            let room = (MAX_FRAME_BYTES - self.buf.len()).min(chunk.len());
            match source.read(&mut chunk[..room]) {
                Ok(0) => return Ok(None),
                Ok(read) => self.buf.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(ClientError::io(&error)),
            }
        }
    }
}

/// Writes one frame, refusing one over [`MAX_FRAME_BYTES`] before any byte
/// of it is written.
pub fn write_frame(sink: &mut impl Write, frame: &Value) -> Result<(), ClientError> {
    let mut bytes =
        serde_json::to_vec(frame).map_err(|_| ClientError::Protocol("unserializable request"))?;
    if bytes.len() + 1 > MAX_FRAME_BYTES {
        return Err(ClientError::FrameTooLarge);
    }
    bytes.push(b'\n');
    sink.write_all(&bytes)
        .map_err(|error| ClientError::io(&error))?;
    sink.flush().map_err(|error| ClientError::io(&error))
}

/// One frame from orceld.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    /// A response. `id` is the echoed id (`None` for orceld's null id, as in
    /// `BUSY` and `FRAME_TOO_LARGE`), `result` the answer or the error code.
    Reply {
        id: Option<u64>,
        result: Result<Value, String>,
    },
    /// One event of a subscription.
    Event(Value),
    /// A subscription's keep-alive.
    Heartbeat,
}

/// Parses one frame. A frame that is not JSON, not an object, of another
/// protocol version, or none of the shapes above is a protocol error.
pub fn parse(bytes: &[u8]) -> Result<Incoming, ClientError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ClientError::Protocol("frame is not JSON"))?;
    let object = value
        .as_object()
        .ok_or(ClientError::Protocol("frame is not an object"))?;
    if object.get("v").and_then(Value::as_str) != Some(PROTOCOL) {
        return Err(ClientError::Protocol("frame is not orcel-app-api/1"));
    }
    let id = match object.get("id") {
        None | Some(Value::Null) => None,
        Some(id) => Some(id.as_u64().ok_or(ClientError::Protocol("unexpected id"))?),
    };
    if let Some(event) = object.get("event") {
        return Ok(Incoming::Event(event.clone()));
    }
    if object.contains_key("heartbeat") {
        return Ok(Incoming::Heartbeat);
    }
    match object.get("ok") {
        Some(Value::Bool(true)) => Ok(Incoming::Reply {
            id,
            result: Ok(object.get("result").cloned().unwrap_or(Value::Null)),
        }),
        Some(Value::Bool(false)) => Ok(Incoming::Reply {
            id,
            result: Err(error_code(
                object
                    .get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(Value::as_str),
            )),
        }),
        _ => Err(ClientError::Protocol(
            "frame is neither a reply nor an event",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_frame_at_the_bound_is_read_and_one_byte_more_is_refused() {
        let at_bound = {
            let mut frame = vec![b'a'; MAX_FRAME_BYTES - 1];
            frame.push(b'\n');
            frame
        };
        let mut reader = FrameReader::default();
        let frame = reader.next(&mut at_bound.as_slice()).unwrap().unwrap();
        assert_eq!(frame.len(), MAX_FRAME_BYTES - 1);

        let over = {
            let mut frame = vec![b'a'; MAX_FRAME_BYTES];
            frame.push(b'\n');
            frame
        };
        let mut reader = FrameReader::default();
        assert_eq!(
            reader.next(&mut over.as_slice()),
            Err(ClientError::FrameTooLarge)
        );
        // No newline at all: refused once the bound is reached, without
        // reading the rest.
        let endless = vec![b'a'; MAX_FRAME_BYTES * 3];
        let mut reader = FrameReader::default();
        assert_eq!(
            reader.next(&mut endless.as_slice()),
            Err(ClientError::FrameTooLarge)
        );
    }

    #[test]
    fn frames_split_at_newlines_and_drop_a_carriage_return() {
        let input = b"{\"a\":1}\r\n{\"b\":2}\n";
        let mut reader = FrameReader::default();
        let mut source = &input[..];
        assert_eq!(reader.next(&mut source).unwrap().unwrap(), b"{\"a\":1}");
        assert_eq!(reader.next(&mut source).unwrap().unwrap(), b"{\"b\":2}");
        assert_eq!(reader.next(&mut source).unwrap(), None);
    }

    #[test]
    fn an_over_cap_request_is_refused_before_any_byte_is_written() {
        let mut sink = Vec::new();
        let frame = json!({ "v": PROTOCOL, "pad": "x".repeat(MAX_FRAME_BYTES) });
        assert_eq!(
            write_frame(&mut sink, &frame),
            Err(ClientError::FrameTooLarge)
        );
        assert!(sink.is_empty());
    }

    #[test]
    fn orcelds_frames_parse() {
        // As `ok_frame`, `error_frame`, `event_frame` and `heartbeat_frame`
        // in crates/orceld/src/app_api.rs write them.
        let ok = br#"{"v":"orcel-app-api/1","id":7,"ok":true,"result":{"x":1}}"#;
        assert_eq!(
            parse(ok).unwrap(),
            Incoming::Reply {
                id: Some(7),
                result: Ok(json!({"x": 1}))
            }
        );
        let busy = br#"{"v":"orcel-app-api/1","id":null,"ok":false,"error":{"code":"BUSY","message":"free text never kept"}}"#;
        assert_eq!(
            parse(busy).unwrap(),
            Incoming::Reply {
                id: None,
                result: Err("BUSY".into())
            }
        );
        let odd = br#"{"v":"orcel-app-api/1","id":1,"ok":false,"error":{"code":"Lower\u202e","message":""}}"#;
        assert_eq!(
            parse(odd).unwrap(),
            Incoming::Reply {
                id: Some(1),
                result: Err("INVALID".into())
            }
        );
        let heartbeat = br#"{"v":"orcel-app-api/1","id":3,"heartbeat":{"head_seq":4}}"#;
        assert_eq!(parse(heartbeat).unwrap(), Incoming::Heartbeat);
        let other = br#"{"v":"orcel-app-api/2","id":3,"ok":true,"result":{}}"#;
        assert!(matches!(parse(other), Err(ClientError::Protocol(_))));
    }
}
