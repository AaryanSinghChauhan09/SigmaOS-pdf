// SPDX-License-Identifier: Apache-2.0
//! SigmaOS-pdf: pdf component model.
//!
//! Real implementation: pdf_items, events, validation, deterministic storage.
//! Replaces the placeholder stub.

/// PDF document management module.
pub mod sigmapdf;

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfItem {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub subject: String,
    pub detail: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdfError {
    EmptyPdfItemName,
    DuplicatePdfItem(String),
    EmptyEventSubject,
}

impl fmt::Display for PdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPdfItemName => write!(f, "pdf_item name must not be empty"),
            Self::DuplicatePdfItem(id) => write!(f, "duplicate pdf_item {:?}", id),
            Self::EmptyEventSubject => write!(f, "event subject must not be empty"),
        }
    }
}

impl std::error::Error for PdfError {}

pub struct Pdf {
    pub name: String,
    pdf_items: BTreeMap<String, PdfItem>,
    events: BTreeMap<String, Event>,
}

impl Pdf {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pdf_items: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn add_pdf_item(&mut self, item: PdfItem) -> Result<(), PdfError> {
        if item.name.trim().is_empty() {
            return Err(PdfError::EmptyPdfItemName);
        }
        let id = item.id.clone();
        if self.pdf_items.contains_key(&id) {
            return Err(PdfError::DuplicatePdfItem(id.clone()));
        }
        self.pdf_items.insert(id, item);
        Ok(())
    }

    pub fn pdf_item_count(&self) -> usize {
        self.pdf_items.len()
    }

    pub fn get_pdf_item(&self, id: &str) -> Option<&PdfItem> {
        self.pdf_items.get(id)
    }

    pub fn add_event(&mut self, event: Event) -> Result<(), PdfError> {
        if event.subject.trim().is_empty() {
            return Err(PdfError::EmptyEventSubject);
        }
        self.events.insert(event.id.clone(), event);
        Ok(())
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn get_event(&self, id: &str) -> Option<&Event> {
        self.events.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pdf_item(id: &str, name: &str) -> PdfItem {
        PdfItem {
            id: id.into(),
            name: name.into(),
            kind: "default".into(),
            detail: String::new(),
        }
    }

    #[test]
    fn test_create() {
        let m = Pdf::new("Pdf");
        assert_eq!(m.name, "Pdf");
        assert_eq!(m.pdf_item_count(), 0);
        assert_eq!(m.event_count(), 0);
    }

    #[test]
    fn test_add_pdf_item() {
        let mut m = Pdf::new("Pdf");
        m.add_pdf_item(sample_pdf_item("a1", "Alpha")).unwrap();
        assert_eq!(m.pdf_item_count(), 1);
        assert!(m.get_pdf_item("a1").is_some());
    }

    #[test]
    fn test_empty_name_rejected() {
        let mut m = Pdf::new("Pdf");
        assert!(m.add_pdf_item(sample_pdf_item("x", "   ")).is_err());
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut m = Pdf::new("Pdf");
        m.add_pdf_item(sample_pdf_item("x", "One")).unwrap();
        assert!(m.add_pdf_item(sample_pdf_item("x", "Two")).is_err());
    }

    #[test]
    fn test_event_validation() {
        let mut m = Pdf::new("Pdf");
        let bad = Event { id: "e1".into(), subject: "".into(), detail: String::new(), timestamp: 0 };
        assert!(m.add_event(bad).is_err());
        let good = Event { id: "e1".into(), subject: "boot".into(), detail: String::new(), timestamp: 1 };
        m.add_event(good).unwrap();
        assert_eq!(m.event_count(), 1);
    }
}
