//! `orcel-search`: an Exa-compatible local search engine, as a pure library.
//!
//! REA packet P-1. Ported from the founder's REA proof of concept
//! (`D:\Orcel-REA\orcel-poc`, TypeScript, Orcel-authored; module map
//! "INDEPENDENT") and extended with the P-1 items. See
//! `docs/orcel/implementation-readiness/prep/REA_EXA_TINYFISH_INTEGRATION.md`.
//!
//! The crate is inert: no network, no listener, no process, no file access
//! and no `orceld` wiring. Pages arrive through [`ingest`] from a response
//! the governed fetch in `orceld` produced; the Exa-shaped route table in
//! [`surface`] is data that a later packet mounts on an `orceld` loopback
//! route. Retrieval is lexical (BM25 + phrase + proximity) and every
//! response says so: [`surface::capabilities`] reports `semantic: false`.
//! Every call costs $0.

pub mod bm25;
pub mod engine;
pub mod extract;
pub mod formats;
pub mod highlights;
pub mod html;
pub mod ingest;
pub mod provenance;
pub mod surface;
pub mod tokenize;
pub mod types;
pub mod url;

pub use engine::{EngineInputError, EngineOptions, LocalSearchEngine};
pub use ingest::{FetchErrorKind, IngestError, IngestOutcome, IngestRecord};
pub use types::{
    AnswerRequest, AnswerResponse, ContentsRequest, ContentsResponse, CorpusDoc,
    FindSimilarRequest, SearchRequest, SearchResponse,
};
