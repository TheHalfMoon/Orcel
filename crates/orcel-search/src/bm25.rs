//! BM25 (Okapi) inverted index over the local corpus.
//!
//! Ported from `orcel-poc/src/engine/bm25.ts` (Orcel-authored). Field
//! weighting: a title term counts as [`TITLE_BOOST`] occurrences and a
//! markdown heading term as [`HEADING_BOOST`]. This is the only ranking
//! signal; the engine has no embeddings and is never described as semantic.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::tokenize::{bigrams, index_terms};

/// Occurrences a title term counts for.
pub const TITLE_BOOST: usize = 3;
/// Occurrences a markdown heading term counts for.
pub const HEADING_BOOST: usize = 2;

#[derive(Debug, Clone)]
struct IndexedDoc {
    terms: Vec<String>,
    term_freq: HashMap<String, u32>,
    bigrams: HashSet<String>,
    length: usize,
}

/// One ranked hit.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub id: String,
    pub score: f64,
}

/// In-memory BM25 index.
#[derive(Debug, Clone)]
pub struct Bm25Index {
    docs: HashMap<String, IndexedDoc>,
    postings: HashMap<String, HashMap<String, u32>>,
    total_length: usize,
    k1: f64,
    b: f64,
}

impl Default for Bm25Index {
    fn default() -> Self {
        Self::new(1.2, 0.75)
    }
}

impl Bm25Index {
    /// An empty index with explicit `k1` and `b`.
    pub fn new(k1: f64, b: f64) -> Self {
        Self {
            docs: HashMap::new(),
            postings: HashMap::new(),
            total_length: 0,
            k1,
            b,
        }
    }

    /// Number of indexed documents.
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// True when nothing is indexed.
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// Mean weighted document length.
    pub fn average_length(&self) -> f64 {
        if self.docs.is_empty() {
            0.0
        } else {
            self.total_length as f64 / self.docs.len() as f64
        }
    }

    /// Indexes (or re-indexes) one document.
    pub fn add(&mut self, id: &str, title: &str, text: &str) {
        if self.docs.contains_key(id) {
            self.remove(id);
        }
        let title_terms = index_terms(title);
        let mut weighted = index_terms(text);
        for term in &title_terms {
            for _ in 0..TITLE_BOOST {
                weighted.push(term.clone());
            }
        }
        for term in extract_headings(text) {
            for _ in 0..HEADING_BOOST {
                weighted.push(term.clone());
            }
        }

        let mut term_freq: HashMap<String, u32> = HashMap::new();
        let mut terms = Vec::new();
        for term in &weighted {
            let entry = term_freq.entry(term.clone()).or_insert(0);
            if *entry == 0 {
                terms.push(term.clone());
            }
            *entry += 1;
        }
        for (term, freq) in &term_freq {
            self.postings
                .entry(term.clone())
                .or_default()
                .insert(id.to_string(), *freq);
        }
        let record = IndexedDoc {
            terms,
            term_freq,
            bigrams: bigrams(&title_terms).into_iter().collect(),
            length: weighted.len(),
        };
        self.total_length += record.length;
        self.docs.insert(id.to_string(), record);
    }

    /// Removes a document and its postings.
    pub fn remove(&mut self, id: &str) {
        let Some(doc) = self.docs.remove(id) else {
            return;
        };
        self.total_length -= doc.length;
        for term in &doc.terms {
            if let Some(posting) = self.postings.get_mut(term) {
                posting.remove(id);
                if posting.is_empty() {
                    self.postings.remove(term);
                }
            }
        }
    }

    /// BM25 inverse document frequency with the +0.5 floor; 0 for unseen terms.
    pub fn idf(&self, term: &str) -> f64 {
        let df = self.postings.get(term).map_or(0, HashMap::len);
        if df == 0 {
            return 0.0;
        }
        let n = self.docs.len() as f64;
        let df = df as f64;
        (1.0 + (n - df + 0.5) / (df + 0.5)).ln()
    }

    /// BM25 score with coverage weighting and an exact title-phrase bonus.
    pub fn score(&self, query: &str, doc_id: &str) -> f64 {
        let Some(doc) = self.docs.get(doc_id) else {
            return 0.0;
        };
        let unique = unique_terms(&index_terms(query));
        if unique.is_empty() {
            return 0.0;
        }
        let avg = if self.average_length() == 0.0 {
            1.0
        } else {
            self.average_length()
        };
        let mut score = 0.0;
        let mut matched = 0usize;
        for term in &unique {
            let tf = f64::from(doc.term_freq.get(term).copied().unwrap_or(0));
            if tf == 0.0 {
                continue;
            }
            matched += 1;
            let numerator = tf * (self.k1 + 1.0);
            let denominator = tf + self.k1 * (1.0 - self.b + (self.b * doc.length as f64) / avg);
            score += self.idf(term) * (numerator / denominator);
        }
        score *= 1.0 + (matched as f64 / unique.len() as f64) * 0.5;

        if unique
            .iter()
            .all(|t| doc.bigrams.contains(t) || doc.term_freq.contains_key(t))
        {
            for pair in bigrams(&unique) {
                if doc.bigrams.contains(&pair) {
                    score += 0.75;
                }
            }
        }
        score
    }

    /// All documents with a positive score, best first; ties by id.
    pub fn search(&self, query: &str) -> Vec<Hit> {
        let mut candidates: HashSet<&str> = HashSet::new();
        for term in unique_terms(&index_terms(query)) {
            if let Some(posting) = self.postings.get(&term) {
                candidates.extend(posting.keys().map(String::as_str));
            }
        }
        let mut hits: Vec<Hit> = candidates
            .into_iter()
            .map(|id| Hit {
                id: id.to_string(),
                score: self.score(query, id),
            })
            .filter(|hit| hit.score > 0.0)
            .collect();
        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
        hits
    }

    /// BM25-weighted term vector (tf times idf), used by `find_similar`.
    pub fn term_vector(&self, doc_id: &str) -> BTreeMap<String, f64> {
        let mut vector = BTreeMap::new();
        if let Some(doc) = self.docs.get(doc_id) {
            for (term, tf) in &doc.term_freq {
                vector.insert(term.clone(), f64::from(*tf) * self.idf(term));
            }
        }
        vector
    }
}

fn unique_terms(terms: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    terms
        .iter()
        .filter(|t| seen.insert(t.as_str()))
        .cloned()
        .collect()
}

/// Terms of markdown heading lines (`#` to `######` followed by a space).
fn extract_headings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if (1..=6).contains(&hashes) && line[hashes..].starts_with(' ') && line.len() > hashes + 1 {
            out.extend(index_terms(line[hashes..].trim_start()));
        }
    }
    out
}

/// Cosine similarity clamped to `[0, 1]` and rounded to 12 decimals.
pub fn cosine_similarity(a: &BTreeMap<String, f64>, b: &BTreeMap<String, f64>) -> f64 {
    let mut dot = 0.0;
    let mut norm_a = 0.0;
    for (term, weight) in a {
        norm_a += weight * weight;
        if let Some(other) = b.get(term) {
            dot += weight * other;
        }
    }
    let norm_b: f64 = b.values().map(|w| w * w).sum();
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    let similarity = dot / (norm_a.sqrt() * norm_b.sqrt());
    (similarity.clamp(0.0, 1.0) * 1e12).round() / 1e12
}
