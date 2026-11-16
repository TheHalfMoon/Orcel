//! Loads the fixture corpus (ported from `orcel-poc/test/helpers.ts`).
#![allow(dead_code)]

use std::path::PathBuf;

use orcel_search::ingest::ingest_html;
use orcel_search::{CorpusDoc, LocalSearchEngine};

pub const FIXED_NOW_MS: u64 = 1_789_000_000_000;

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

pub fn read_fixture(name: &str) -> String {
    std::fs::read_to_string(fixtures_dir().join(name)).expect("fixture is readable")
}

pub fn load_fixtures() -> Vec<CorpusDoc> {
    let manifest: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&read_fixture("manifest.json")).expect("manifest is JSON");
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .expect("fixtures directory")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".html"))
        .collect();
    names.sort();
    names
        .iter()
        .map(|name| {
            let url = manifest
                .get(name)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("https://fixtures.orcel.local/{name}"));
            ingest_html(&url, &read_fixture(name), "local-corpus", FIXED_NOW_MS)
        })
        .collect()
}

pub fn build_engine() -> LocalSearchEngine {
    let mut engine = LocalSearchEngine::default();
    engine.add_many(load_fixtures());
    engine
}

pub fn find_by_url<'a>(docs: &'a [CorpusDoc], fragment: &str) -> &'a CorpusDoc {
    docs.iter()
        .find(|d| d.url.contains(fragment))
        .expect("fixture present")
}

pub fn search(query: &str) -> orcel_search::SearchRequest {
    orcel_search::SearchRequest {
        query: query.to_string(),
        ..Default::default()
    }
}

pub fn host(url: &str) -> String {
    orcel_search::url::parse(url).expect("url").host
}
