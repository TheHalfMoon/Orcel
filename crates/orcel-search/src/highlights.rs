//! Extractive highlights: the local stand-in for Exa's `contents.highlights`.
//!
//! Ported from `orcel-poc/src/text/highlights.ts` (Orcel-authored). Returns
//! the sentences that best answer the query, in document order, within a
//! character budget, each with a relevance score. No model is involved.
//! Lengths are counted in Unicode scalar values (the proof of concept counts
//! UTF-16 units; the two agree for the Basic Multilingual Plane).

use std::collections::{HashMap, HashSet};

use crate::tokenize::{fold_diacritics, index_terms, MAX_QUERY_BYTES, MAX_QUERY_TERMS};

const ABBREVIATIONS: [&str; 19] = [
    "mr", "mrs", "ms", "dr", "prof", "sr", "jr", "inc", "ltd", "co", "corp", "vs", "etc", "e.g",
    "i.e", "fig", "no", "st", "approx",
];

/// One sentence with its position in the cleaned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sentence {
    pub index: usize,
    pub text: String,
    /// Offset in characters into the whitespace-collapsed text.
    pub start: usize,
}

/// Collapses every whitespace run to one space and trims.
pub fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Splits prose into sentences without a tokenizer model. Does not split on
/// known abbreviations, single capital initials or after a digit.
pub fn split_sentences(text: &str) -> Vec<Sentence> {
    let mut sentences = Vec::new();
    let cleaned: Vec<char> = collapse_whitespace(text).chars().collect();
    if cleaned.is_empty() {
        return sentences;
    }
    let mut start = 0usize;
    for i in 0..cleaned.len() {
        let c = cleaned[i];
        if c != '.' && c != '!' && c != '?' {
            continue;
        }
        let boundary = cleaned.get(i + 1).is_none_or(|next| *next == ' ');
        if !boundary {
            continue;
        }
        // The last word runs back to the previous space. Every boundary is
        // followed by a space, so these backward scans never overlap and the
        // whole split stays linear; the sentence string is built only when
        // the split is taken.
        let mut word_start = i;
        while word_start > start && cleaned[word_start - 1] != ' ' {
            word_start -= 1;
        }
        let raw_last: String = cleaned[word_start..=i].iter().collect();
        let raw_last = raw_last.strip_suffix('.').unwrap_or(&raw_last);
        if ABBREVIATIONS.contains(&raw_last.to_lowercase().as_str()) {
            continue;
        }
        let mut last_chars = raw_last.chars();
        if let (Some(only), None) = (last_chars.next(), last_chars.next()) {
            if only.is_uppercase() {
                continue;
            }
        }
        if i > 0 && cleaned[i - 1].is_ascii_digit() {
            continue;
        }
        let candidate: String = cleaned[start..=i]
            .iter()
            .collect::<String>()
            .trim()
            .to_string();
        if !candidate.is_empty() {
            sentences.push(Sentence {
                index: sentences.len(),
                text: candidate,
                start,
            });
        }
        start = i + 1;
    }
    if start < cleaned.len() {
        let tail: String = cleaned[start..]
            .iter()
            .collect::<String>()
            .trim()
            .to_string();
        if !tail.is_empty() {
            sentences.push(Sentence {
                index: sentences.len(),
                text: tail,
                start,
            });
        }
    }
    sentences
}

fn idf_of(term: &str, sentence_terms: &[Vec<String>]) -> f64 {
    let df = sentence_terms
        .iter()
        .filter(|terms| terms.iter().any(|t| t == term))
        .count();
    if df == 0 {
        return 0.0;
    }
    (1.0 + sentence_terms.len() as f64 / df as f64).ln()
}

/// The first `count` sentences joined with a space: the local summary.
pub fn lead_sentences(text: &str, count: usize) -> String {
    split_sentences(text)
        .into_iter()
        .take(count.max(1))
        .map(|s| s.text)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Highlight selection options.
#[derive(Debug, Clone, Default)]
pub struct HighlightOptions {
    pub query: String,
    /// Defaults to 5.
    pub num_sentences: Option<usize>,
    /// Character budget; `None` is unlimited.
    pub max_characters: Option<usize>,
}

/// One highlight with its score rounded to four decimals.
#[derive(Debug, Clone, PartialEq)]
pub struct Highlight {
    pub text: String,
    pub score: f64,
}

/// Rounds to `places` decimals.
pub fn round_to(value: f64, places: i32) -> f64 {
    let factor = 10f64.powi(places);
    (value * factor).round() / factor
}

/// Ranks sentences against the query and returns the best ones in document
/// order. With no matching sentence it falls back to the lead sentences with
/// score 0.
pub fn extract_highlights(text: &str, options: &HighlightOptions) -> Vec<Highlight> {
    let sentences = split_sentences(text);
    if sentences.is_empty() {
        return Vec::new();
    }
    // The query is bounded here too (the engine also refuses long queries),
    // so per-sentence scoring costs at most MAX_QUERY_TERMS passes.
    let mut query = options.query.trim();
    if query.len() > MAX_QUERY_BYTES {
        let mut end = MAX_QUERY_BYTES;
        while !query.is_char_boundary(end) {
            end -= 1;
        }
        query = &query[..end];
    }
    let mut seen = HashSet::new();
    let terms: Vec<String> = index_terms(query)
        .into_iter()
        .filter(|t| seen.insert(t.clone()))
        .take(MAX_QUERY_TERMS)
        .collect();
    let num_sentences = options.num_sentences.unwrap_or(5);
    let max_characters = options.max_characters.unwrap_or(usize::MAX);
    let sentence_terms: Vec<Vec<String>> = sentences.iter().map(|s| index_terms(&s.text)).collect();

    let ranked: Vec<(usize, f64)> = if terms.is_empty() {
        sentences
            .iter()
            .map(|s| (s.index, 1.0 / (1.0 + s.index as f64)))
            .collect()
    } else {
        let idf: HashMap<&str, f64> = terms
            .iter()
            .map(|t| (t.as_str(), idf_of(t, &sentence_terms)))
            .collect();
        let max_idf = idf.values().copied().fold(1.0f64, f64::max);
        let phrase = format!(" {} ", query.to_lowercase());
        sentences
            .iter()
            .map(|sentence| {
                let own = &sentence_terms[sentence.index];
                let set: HashSet<&str> = own.iter().map(String::as_str).collect();
                let mut score = 0.0;
                for term in &terms {
                    if set.contains(term.as_str()) {
                        score += idf.get(term.as_str()).copied().unwrap_or(0.0) / max_idf;
                    }
                }
                if score == 0.0 {
                    return (sentence.index, 0.0);
                }
                score /= (own.len().max(1) as f64).sqrt();
                let mut positions: Vec<usize> = terms
                    .iter()
                    .filter_map(|term| own.iter().position(|t| t == term))
                    .collect();
                positions.sort_unstable();
                if positions.len() > 1 && positions[positions.len() - 1] - positions[0] <= 12 {
                    score *= 1.25;
                }
                let haystack = format!(" {} ", fold_diacritics(&sentence.text.to_lowercase()));
                if !query.is_empty() && haystack.contains(&phrase) {
                    score *= 1.4;
                }
                (sentence.index, score)
            })
            .collect()
    };

    let mut positive: Vec<(usize, f64)> = ranked.into_iter().filter(|(_, s)| *s > 0.0).collect();
    let mut chosen: Vec<(usize, f64)> = Vec::new();
    if positive.is_empty() {
        for sentence in sentences.iter().take(num_sentences) {
            chosen.push((sentence.index, 0.0));
        }
    } else {
        positive.sort_by(|a, b| b.1.total_cmp(&a.1));
        let mut used = 0usize;
        for (index, score) in positive {
            if chosen.len() >= num_sentences {
                break;
            }
            let cost = sentences[index].text.chars().count() + 1;
            if used.saturating_add(cost) > max_characters && !chosen.is_empty() {
                continue;
            }
            used = used.saturating_add(cost);
            chosen.push((index, score));
        }
    }
    chosen.sort_by_key(|(index, _)| *index);

    let mut highlights = Vec::new();
    let mut budget = max_characters;
    for (index, score) in chosen {
        let text = &sentences[index].text;
        let length = text.chars().count();
        if length > budget {
            continue;
        }
        budget = budget.saturating_sub(length + 1);
        highlights.push(Highlight {
            text: text.clone(),
            score: round_to(score, 4),
        });
    }
    highlights
}
