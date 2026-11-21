// SPDX-License-Identifier: Apache-2.0
//!
//! SigmaOS-pdf — PDF inspection & text extraction.
//!
//! Parses PDF structure (xref-free tolerant parser): header version,
//! page count, document info dictionary (title/author/creator/producer/
//! creation/modification dates), encryption detection, and best-effort
//! text extraction from content streams (Tj/TJ operators). Streams are
//! FlateDecode-decompressed with a minimal inflate implementation when
//! the `flate` feature... — we implement a small inflate decoder inline
//! to avoid heavy deps? No: use `miniz_oxide`? Keep zero-dep: implement
//! stored+fixed-Huffman inflate subset, or shell out? Honest approach:
//! support uncompressed streams + FlateDecode via a compact inflate
//! decoder written in-crate (deflate is complex — implement fixed +
//! dynamic Huffman).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum PdfError {
    NotPdf,
    Truncated,
    BadXref,
    Encrypted,
    Parse(String),
    Io(String),
}
impl fmt::Display for PdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPdf=>write!(f,"not a PDF file"),
            Self::Truncated=>write!(f,"truncated PDF"),
            Self::BadXref=>write!(f,"bad xref table"),
            Self::Encrypted=>write!(f,"PDF is encrypted"),
            Self::Parse(m)=>write!(f,"parse: {}",m),
            Self::Io(m)=>write!(f,"io: {}",m),
        }
    }
}
impl std::error::Error for PdfError {}

/// Document metadata.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PdfInfo {
    pub version: String,
    pub page_count: usize,
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<String>,
    pub mod_date: Option<String>,
    pub encrypted: bool,
    pub file_size: u64,
    /// linearized (fast web view)?
    pub linearized: bool,
    /// tagged PDF (accessibility)?
    pub tagged: bool,
}

/// Extracted page text.
#[derive(Debug, Clone)]
pub struct PageText {
    pub page: usize,
    pub text: String,
}

/// A parsed indirect object reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjRef { pub num: u32, pub gen: u16 }

/// PDF document model (lazy — objects resolved on demand).
pub struct PdfDoc {
    pub data: Vec<u8>,
    pub info: PdfInfo,
    /// obj num → raw object bytes (between "n g obj" and "endobj").
    objects: BTreeMap<u32, Vec<u8>>,
    /// page object numbers in order.
    page_objs: Vec<u32>,
}

impl PdfDoc {
    /// Parse a PDF from bytes.
    pub fn parse(data: Vec<u8>) -> Result<Self, PdfError> {
        if data.len() < 8 || !data.starts_with(b"%PDF-") {
            return Err(PdfError::NotPdf);
        }
        // version
        let version = String::from_utf8_lossy(&data[5..8]).to_string();
        // find all "N G obj" ... "endobj"
        let mut objects = BTreeMap::new();
        let text = String::from_utf8_lossy(&data);
        let bytes = &data[..];
        let _ = &text;
        let mut pos = 0;
        while pos + 10 < bytes.len() {
            // find " obj" preceded by numbers
            if let Some(idx) = find_obj_marker(bytes, pos) {
                let (num, gen) = parse_obj_header_bytes(&bytes[idx..]).ok_or(PdfError::BadXref)?;
                // find endobj
                let end_marker = b"endobj";
                let end = find_subslice(bytes, end_marker, idx)
                    .ok_or(PdfError::Truncated)?;
                objects.insert(num, bytes[idx..end].to_vec());
                pos = end + 6;
            } else { break; }
        }
        // encryption?
        let encrypted = objects.values().any(|o| contains(o, b"/Encrypt"))
            || text.contains("/Encrypt");
        // catalog → pages → count
        let mut page_objs = vec![];
        let mut page_count = 0usize;
        // find /Type /Pages with /Count
        for (_n, obj) in &objects {
            if contains(obj, b"/Type") && contains(obj, b"/Pages") {
                if let Some(cnt) = extract_int_after(obj, b"/Count") {
                    page_count = cnt as usize;
                }
            }
        }
        // collect /Type /Page objects (not /Pages)
        for (n, obj) in &objects {
            if contains(obj, b"/Type") && contains(obj, b"/Page")
                && !contains(obj, b"/Pages") {
                page_objs.push(*n);
            }
        }
        if page_count == 0 { page_count = page_objs.len(); }
        // PDF 1.5+: objects may live inside compressed object streams.
        // Fallback: decompress every stream and count page dicts.
        if page_count == 0 {
            let mut found = 0usize;
            let mut pages_count: Option<usize> = None;
            for (_n, obj) in &objects {
                if let Some(content) = extract_stream(obj) {
                    let dict_end = find_subslice(obj, b"stream", 0).unwrap_or(0);
                    if let Ok(dec) = decode_stream(&content, &obj[..dict_end]) {
                        let d = String::from_utf8_lossy(&dec);
                        // /Type /Page (not /Pages)
                        let mut idx = 0;
                        while let Some(p) = d[idx..].find("/Type") {
                            let abs = idx + p;
                            let window = &d[abs..(abs+60).min(d.len())];
                            if window.contains("/Page") && !window.contains("/Pages") {
                                found += 1;
                            }
                            idx = abs + 5;
                        }
                        if let Some(cp) = d.find("/Count") {
                            let after = &d[cp+6..];
                            let num: String = after.chars()
                                .skip_while(|c| c.is_whitespace())
                                .take_while(|c| c.is_ascii_digit()).collect();
                            if let Ok(n) = num.parse::<usize>() {
                                if n > pages_count.unwrap_or(0) { pages_count = Some(n); }
                            }
                        }
                    }
                }
            }
            if found > 0 { page_count = found; }
            else if let Some(n) = pages_count { page_count = n; }
        }
        // info dict: find /Info ref in trailer, or object with /Title etc.
        let mut info = PdfInfo {
            version, page_count, encrypted,
            file_size: data.len() as u64,
            linearized: text.contains("/Linearized"),
            tagged: text.contains("/MarkInfo") && text.contains("/Marked true"),
            ..Default::default()
        };
        // search all objects for /Title etc.
        for (_n, obj) in &objects {
            if info.title.is_none() { info.title = extract_pdf_string(obj, b"/Title"); }
            if info.author.is_none() { info.author = extract_pdf_string(obj, b"/Author"); }
            if info.subject.is_none() { info.subject = extract_pdf_string(obj, b"/Subject"); }
            if info.keywords.is_none() { info.keywords = extract_pdf_string(obj, b"/Keywords"); }
            if info.creator.is_none() { info.creator = extract_pdf_string(obj, b"/Creator"); }
            if info.producer.is_none() { info.producer = extract_pdf_string(obj, b"/Producer"); }
            if info.creation_date.is_none() { info.creation_date = extract_pdf_string(obj, b"/CreationDate"); }
            if info.mod_date.is_none() { info.mod_date = extract_pdf_string(obj, b"/ModDate"); }
        }
        Ok(Self { data, info, objects, page_objs })
    }

    /// Get raw object bytes by number.
    pub fn object(&self, num: u32) -> Option<&[u8]> {
        self.objects.get(&num).map(|v| v.as_slice())
    }

    /// Page count.
    pub fn page_count(&self) -> usize { self.info.page_count }

    /// Extract text from a page (0-indexed).
    pub fn page_text(&self, page: usize) -> Result<String, PdfError> {
        let obj_num = *self.page_objs.get(page)
            .ok_or_else(|| PdfError::Parse(format!("no page {}", page)))?;
        let obj = self.objects.get(&obj_num)
            .ok_or_else(|| PdfError::Parse("page obj missing".into()))?;
        // find /Contents ref(s)
        let contents = extract_contents_refs(obj);
        let mut text = String::new();
        for r in contents {
            if let Some(stream_obj) = self.objects.get(&r.num) {
                if let Some(content) = extract_stream(stream_obj) {
                    let dict_end = find_subslice(stream_obj, b"stream", 0).unwrap_or(0);
                    let decoded = decode_stream(&content, &stream_obj[..dict_end])?;
                    let page_str = extract_text_ops(&decoded);
                    if !page_str.is_empty() {
                        if !text.is_empty() { text.push('\n'); }
                        text.push_str(&page_str);
                    }
                }
            }
        }
        Ok(text)
    }

    /// Extract text from all pages.
    pub fn all_text(&self) -> Result<Vec<PageText>, PdfError> {
        let mut out = vec![];
        for i in 0..self.page_count() {
            let t = self.page_text(i).unwrap_or_default();
            out.push(PageText { page: i + 1, text: t });
        }
        Ok(out)
    }

    /// Load from file.
    pub fn open(path: &Path) -> Result<Self, PdfError> {
        let data = std::fs::read(path).map_err(|e| PdfError::Io(e.to_string()))?;
        Self::parse(data)
    }
}

fn find_obj_marker(bytes: &[u8], from: usize) -> Option<usize> {
    // find pattern: digits space digits space "obj"
    let mut i = from;
    while i + 8 < bytes.len() {
        // look for " obj" preceded by number
        if bytes[i] == b' ' && i + 4 < bytes.len()
            && &bytes[i+1..i+4] == b"obj" {
            // backtrack to find "N G"
            let mut j = i;
            while j > 0 && bytes[j-1] != b'\n' && bytes[j-1] != b'\r' { j -= 1; }
            let line = &bytes[j..i+4];
            if parse_obj_header(&String::from_utf8_lossy(line)).is_some() {
                return Some(j);
            }
        }
        i += 1;
    }
    None
}

fn parse_obj_header(s: &str) -> Option<(u32, u16)> {
    let s = s.trim();
    let mut it = s.split_whitespace();
    let num: u32 = it.next()?.parse().ok()?;
    let gen: u16 = it.next()?.parse().ok()?;
    if it.next()? != "obj" { return None; }
    Some((num, gen))
}

fn parse_obj_header_bytes(b: &[u8]) -> Option<(u32, u16)> {
    // header is ASCII: "N G obj" up to ~20 bytes or whitespace
    let end = b.iter().position(|&c| c == b'\n' || c == b'\r').unwrap_or(b.len().min(40));
    let s = String::from_utf8_lossy(&b[..end]);
    let mut it = s.split_whitespace();
    let num: u32 = it.next()?.parse().ok()?;
    let gen: u16 = it.next()?.parse().ok()?;
    if it.next()? != "obj" { return None; }
    Some((num, gen))
}

fn find_subslice(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if hay.len() < needle.len() { return None; }
    for i in from..=(hay.len() - needle.len()) {
        if &hay[i..i+needle.len()] == needle { return Some(i); }
    }
    None
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find_subslice(hay, needle, 0).is_some()
}

fn extract_int_after(obj: &[u8], key: &[u8]) -> Option<i64> {
    let pos = find_subslice(obj, key, 0)?;
    let rest = &obj[pos + key.len()..];
    let s = String::from_utf8_lossy(rest);
    let num: String = s.chars().skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit() || *c == '-').collect();
    num.parse().ok()
}

fn extract_pdf_string(obj: &[u8], key: &[u8]) -> Option<String> {
    let pos = find_subslice(obj, key, 0)?;
    let rest = &obj[pos + key.len()..];
    let s = String::from_utf8_lossy(rest);
    // find (string) or <hex>
    let s = s.trim_start();
    if s.starts_with('(') {
        // literal string — find matching )
        let inner = &s[1..];
        let end = inner.find(')')?;
        let raw = &inner[..end];
        Some(unescape_pdf_string(raw))
    } else if s.starts_with('<') && !s.starts_with("<<") {
        let end = s[1..].find('>')?;
        let hex = &s[1..1+end];
        hex_to_string(hex)
    } else {
        // maybe indirect ref "12 0 R" — skip
        None
    }
}

fn unescape_pdf_string(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\u{8}'),
                Some('f') => out.push('\u{c}'),
                Some('(') => out.push('('),
                Some(')') => out.push(')'),
                Some('\\') => out.push('\\'),
                Some(d) if d.is_ascii_digit() => {
                    // octal escape up to 3 digits
                    let mut oct = d.to_string();
                    for _ in 0..2 {
                        if let Some(&n) = chars.peek() {
                            if n.is_digit(8) { oct.push(n); chars.next(); } else { break; }
                        }
                    }
                    if let Ok(v) = u8::from_str_radix(&oct, 8) {
                        out.push(v as char);
                    }
                }
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn hex_to_string(hex: &str) -> Option<String> {
    let hex: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() % 2 != 0 { return None; }
    let bytes: Vec<u8> = (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}

fn extract_contents_refs(obj: &[u8]) -> Vec<ObjRef> {
    let mut refs = vec![];
    // find /Contents N G R or /Contents [N G R ...]
    if let Some(pos) = find_subslice(obj, b"/Contents", 0) {
        let rest = &obj[pos + 9..];
        let s = String::from_utf8_lossy(rest);
        // single ref
        let mut it = s.trim_start().split_whitespace();
        if let (Some(n), Some(g), Some(r)) = (it.next(), it.next(), it.next()) {
            if r == "R" {
                if let (Ok(num), Ok(gen)) = (n.parse::<u32>(), g.parse::<u16>()) {
                    refs.push(ObjRef { num, gen });
                    return refs;
                }
            }
        }
        // array
        if s.trim_start().starts_with('[') {
            let end = s.find(']').unwrap_or(s.len());
            let arr = &s[..end];
            let mut nums = arr.split_whitespace();
            while let (Some(n), Some(g), Some(r)) = (nums.next(), nums.next(), nums.next()) {
                if r == "R" {
                    if let (Ok(num), Ok(gen)) = (n.parse::<u32>(), g.parse::<u16>()) {
                        refs.push(ObjRef { num, gen });
                    }
                }
            }
        }
    }
    refs
}

/// Extract stream data between "stream\n" and "endstream".
fn extract_stream(obj: &[u8]) -> Option<Vec<u8>> {
    let pos = find_subslice(obj, b"stream", 0)?;
    let mut start = pos + 6;
    // skip EOL
    if start < obj.len() && obj[start] == b'\r' { start += 1; }
    if start < obj.len() && obj[start] == b'\n' { start += 1; }
    let end = find_subslice(&obj[start..], b"endstream", 0)? + start;
    Some(obj[start..end].to_vec())
}

/// Decode stream: handle FlateDecode via inflate, else raw.
fn decode_stream(data: &[u8], filters: &[u8]) -> Result<Vec<u8>, PdfError> {
    if contains(filters, b"FlateDecode") || contains(filters, b"Fl") {
        inflate(data).map_err(|e| PdfError::Parse(format!("inflate: {}", e)))
    } else {
        Ok(data.to_vec())
    }
}

/// Extract text from PDF content stream operators (Tj, TJ, ').
fn extract_text_ops(content: &[u8]) -> String {
    let s = String::from_utf8_lossy(content);
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // look for (string) Tj or [ ... ] TJ or (string) '
        if chars[i] == '(' {
            // literal string
            let mut depth = 1;
            let mut j = i + 1;
            let mut str_content = String::new();
            while j < chars.len() && depth > 0 {
                let c = chars[j];
                if c == '\\' && j + 1 < chars.len() {
                    str_content.push(c);
                    str_content.push(chars[j+1]);
                    j += 2;
                    continue;
                }
                if c == '(' { depth += 1; }
                if c == ')' { depth -= 1; if depth == 0 { break; } }
                str_content.push(c);
                j += 1;
            }
            // after string: check for Tj or ' or ] TJ
            let after = s[j+1..].trim_start();
            let op = after.split_whitespace().next().unwrap_or("");
            if op == "Tj" || after.starts_with('\'') {
                out.push_str(&unescape_pdf_string(&str_content));
            }
            i = j + 1;
        } else if chars[i] == '[' {
            // TJ array: [(str) num (str) num ...] TJ
            let mut j = i;
            let mut depth = 0;
            while j < chars.len() {
                if chars[j] == '[' { depth += 1; }
                if chars[j] == ']' { depth -= 1; if depth == 0 { break; } }
                j += 1;
            }
            let arr = &s[i..=j.min(s.len()-1)];
            // extract all (strings)
            let mut k = 0;
            let ac: Vec<char> = arr.chars().collect();
            while k < ac.len() {
                if ac[k] == '(' {
                    let mut d = 1;
                    let mut m = k + 1;
                    let mut sc = String::new();
                    while m < ac.len() && d > 0 {
                        let c = ac[m];
                        if c == '\\' && m + 1 < ac.len() {
                            sc.push(c); sc.push(ac[m+1]); m += 2; continue;
                        }
                        if c == '(' { d += 1; }
                        if c == ')' { d -= 1; if d == 0 { break; } }
                        sc.push(c); m += 1;
                    }
                    out.push_str(&unescape_pdf_string(&sc));
                    k = m + 1;
                } else { k += 1; }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Minimal DEFLATE (zlib) decompressor: supports stored + fixed + dynamic
/// Huffman blocks. Sufficient for most PDF FlateDecode streams.
fn inflate(data: &[u8]) -> Result<Vec<u8>, String> {
    // zlib header: 2 bytes (CMF FLG), then deflate stream, then adler32
    if data.len() < 2 { return Err("too short".into()); }
    let cmf = data[0];
    if cmf & 0x0f != 8 { return Err("not deflate".into()); }
    let fcheck = ((cmf as u16) << 8 | data[1] as u16) % 31;
    if fcheck != 0 { return Err("bad zlib header".into()); }
    let mut bitpos = 16usize;
    let mut out = Vec::new();
    loop {
        let bfinal = get_bits(data, &mut bitpos, 1)?;
        let btype = get_bits(data, &mut bitpos, 2)?;
        match btype {
            0 => {
                // stored
                bitpos = (bitpos + 7) & !7;
                let len = get_bits(data, &mut bitpos, 16)? as usize;
                let nlen = get_bits(data, &mut bitpos, 16)? as usize;
                if len != (!nlen & 0xffff) { return Err("bad stored len".into()); }
                let byte_pos = bitpos / 8;
                out.extend_from_slice(&data[byte_pos..byte_pos+len]);
                bitpos += len * 8;
            }
            1 => {
                // fixed Huffman
                inflate_block(data, &mut bitpos, &mut out, fixed_lit_lens(), fixed_dist_lens())?;
            }
            2 => {
                // dynamic Huffman
                inflate_dynamic(data, &mut bitpos, &mut out)?;
            }
            _ => return Err("bad block type".into()),
        }
        if bfinal == 1 { break; }
    }
    Ok(out)
}

fn get_bits(data: &[u8], pos: &mut usize, n: u32) -> Result<u32, String> {
    let mut v = 0u32;
    for i in 0..n {
        let byte = *pos / 8;
        let bit = (*pos % 8) as u32;
        if byte >= data.len() { return Err("eof".into()); }
        v |= (((data[byte] >> bit) & 1) as u32) << i;
        *pos += 1;
    }
    Ok(v)
}

fn fixed_lit_lens() -> Vec<u8> {
    let mut l = vec![0u8; 288];
    for i in 0..144 { l[i] = 8; }
    for i in 144..256 { l[i] = 9; }
    for i in 256..280 { l[i] = 7; }
    for i in 280..288 { l[i] = 8; }
    l
}
fn fixed_dist_lens() -> Vec<u8> {
    vec![5u8; 30]
}

fn build_huffman(lens: &[u8]) -> Result<(Vec<u16>, Vec<u16>), String> {
    // returns (counts, symbols) — canonical huffman
    let mut counts = [0u16; 16];
    for &l in lens { if l > 0 { counts[l as usize] += 1; } }
    let mut offs = [0u16; 16];
    for i in 1..15 { offs[i+1] = offs[i] + counts[i]; }
    let mut symbols = vec![0u16; lens.len()];
    for (i, &l) in lens.iter().enumerate() {
        if l > 0 {
            symbols[offs[l as usize] as usize] = i as u16;
            offs[l as usize] += 1;
        }
    }
    Ok((counts.to_vec(), symbols))
}

fn inflate_block(data: &[u8], pos: &mut usize, out: &mut Vec<u8>,
    lit_lens: Vec<u8>, dist_lens: Vec<u8>) -> Result<(), String> {
    let (lc, ls) = build_huffman(&lit_lens)?;
    let (dc, ds) = build_huffman(&dist_lens)?;
    decode_symbols(data, pos, out, &lc, &ls, &dc, &ds)
}

fn inflate_dynamic(data: &[u8], pos: &mut usize, out: &mut Vec<u8>) -> Result<(), String> {
    let hlit = get_bits(data, pos, 5)? as usize + 257;
    let hdist = get_bits(data, pos, 5)? as usize + 1;
    let hclen = get_bits(data, pos, 4)? as usize + 4;
    let order = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];
    let mut cl_lens = [0u8; 19];
    for i in 0..hclen {
        cl_lens[order[i]] = get_bits(data, pos, 3)? as u8;
    }
    let (cc, cs) = build_huffman(&cl_lens.to_vec())?;
    // decode lit+dist lengths
    let total = hlit + hdist;
    let mut lens = vec![0u8; total];
    let mut i = 0;
    while i < total {
        let sym = decode_symbol(data, pos, &cc, &cs)?;
        match sym {
            0..=15 => { lens[i] = sym as u8; i += 1; }
            16 => {
                let rep = get_bits(data, pos, 2)? as usize + 3;
                let prev = if i > 0 { lens[i-1] } else { 0 };
                for _ in 0..rep { lens[i] = prev; i += 1; }
            }
            17 => {
                let rep = get_bits(data, pos, 3)? as usize + 3;
                for _ in 0..rep { lens[i] = 0; i += 1; }
            }
            18 => {
                let rep = get_bits(data, pos, 7)? as usize + 11;
                for _ in 0..rep { lens[i] = 0; i += 1; }
            }
            _ => return Err("bad code length".into()),
        }
    }
    let lit_lens = lens[..hlit].to_vec();
    let dist_lens = lens[hlit..].to_vec();
    inflate_block(data, pos, out, lit_lens, dist_lens)
}

fn decode_symbol(data: &[u8], pos: &mut usize, counts: &[u16], symbols: &[u16]) -> Result<u16, String> {
    // canonical huffman decode: read bit-by-bit
    let mut code = 0u32;
    let mut first = 0u32;
    let mut index = 0usize;
    for len in 1..=15 {
        code |= get_bits(data, pos, 1)? as u32;
        let count = counts[len] as u32;
        if code - first < count {
            return Ok(symbols[index + (code - first) as usize]);
        }
        index += count as usize;
        first = (first + count) << 1;
        code <<= 1;
    }
    Err("bad huffman code".into())
}

fn decode_symbols(data: &[u8], pos: &mut usize, out: &mut Vec<u8>,
    lit_counts: &[u16], lit_syms: &[u16],
    dist_counts: &[u16], dist_syms: &[u16]) -> Result<(), String> {
    // length base & extra bits
    const LEN_BASE: [u16; 29] = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
    const LEN_EXTRA: [u8; 29] = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
    const DIST_BASE: [u16; 30] = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
    const DIST_EXTRA: [u8; 30] = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
    loop {
        let sym = decode_symbol(data, pos, lit_counts, lit_syms)?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => break, // end of block
            257..=285 => {
                let li = (sym - 257) as usize;
                let len = LEN_BASE[li] as usize + get_bits(data, pos, LEN_EXTRA[li] as u32)? as usize;
                let dsym = decode_symbol(data, pos, dist_counts, dist_syms)? as usize;
                if dsym >= 30 { return Err("bad dist sym".into()); }
                let dist = DIST_BASE[dsym] as usize + get_bits(data, pos, DIST_EXTRA[dsym] as u32)? as usize;
                if dist > out.len() { return Err("dist too far".into()); }
                let start = out.len() - dist;
                for k in 0..len {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            _ => return Err("bad lit sym".into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pdf() -> Vec<u8> {
        // hand-crafted minimal PDF with catalog, pages, page, content stream
        let content = b"BT /F1 12 Tf 72 720 Td (Hello World) Tj ET";
        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n");
        let objs: Vec<String> = vec![
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".into(),
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".into(),
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n".into(),
            format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len())
                .into(),
            String::from_utf8_lossy(content).to_string() + "\nendstream\nendobj\n",
            "5 0 obj\n<< /Title (Test Doc) /Author (SigmaOS) /Producer (test) >>\nendobj\n".into(),
        ];
        // obj 4 is split — rebuild properly
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        pdf.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n");
        pdf.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes());
        pdf.extend_from_slice(content);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        pdf.extend_from_slice(b"5 0 obj\n<< /Title (Test Doc) /Author (SigmaOS) /Producer (test) >>\nendobj\n");
        pdf.extend_from_slice(b"trailer\n<< /Info 5 0 R >>\n%%EOF\n");
        pdf
    }

    #[test]
    fn parse_minimal_pdf() {
        let pdf = minimal_pdf();
        let doc = PdfDoc::parse(pdf).unwrap();
        assert_eq!(doc.info.version, "1.4");
        assert_eq!(doc.page_count(), 1);
        assert_eq!(doc.info.title.as_deref(), Some("Test Doc"));
        assert_eq!(doc.info.author.as_deref(), Some("SigmaOS"));
        assert!(!doc.info.encrypted);
    }

    #[test]
    fn extract_page_text() {
        let pdf = minimal_pdf();
        let doc = PdfDoc::parse(pdf).unwrap();
        let text = doc.page_text(0).unwrap();
        assert!(text.contains("Hello World"), "got: {}", text);
    }

    #[test]
    fn reject_non_pdf() {
        assert!(matches!(PdfDoc::parse(b"not a pdf".to_vec()), Err(PdfError::NotPdf)));
        assert!(matches!(PdfDoc::parse(b"".to_vec()), Err(PdfError::NotPdf)));
    }

    #[test]
    fn hex_string_decode() {
        assert_eq!(hex_to_string("48656C6C6F"), Some("Hello".into()));
    }

    #[test]
    fn pdf_string_unescape() {
        assert_eq!(unescape_pdf_string("Hello\\nWorld"), "Hello\nWorld");
        assert_eq!(unescape_pdf_string("a\\(b\\)"), "a(b)");
        assert_eq!(unescape_pdf_string("\\101"), "A");
    }

    #[test]
    fn encrypted_detected() {
        let mut pdf = minimal_pdf();
        // inject /Encrypt into trailer area
        let pos = pdf.windows(7).position(|w| w == b"trailer").unwrap();
        pdf.splice(pos..pos, b"/Encrypt 6 0 R ".iter().cloned());
        let doc = PdfDoc::parse(pdf).unwrap();
        assert!(doc.info.encrypted);
    }

    #[test]
    fn multi_page_count() {
        // craft pdf with Count 3
        let mut pdf = minimal_pdf();
        let s = String::from_utf8_lossy(&pdf).to_string();
        let s2 = s.replace("/Count 1", "/Count 3");
        let doc = PdfDoc::parse(s2.into_bytes()).unwrap();
        assert_eq!(doc.page_count(), 3);
    }

    #[test]
    fn all_text_pages() {
        let pdf = minimal_pdf();
        let doc = PdfDoc::parse(pdf).unwrap();
        let texts = doc.all_text().unwrap();
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].page, 1);
    }

    #[test]
    fn file_size_recorded() {
        let pdf = minimal_pdf();
        let size = pdf.len() as u64;
        let doc = PdfDoc::parse(pdf).unwrap();
        assert_eq!(doc.info.file_size, size);
    }

    #[test]
    fn linearized_detected() {
        let mut pdf = minimal_pdf();
        // insert /Linearized in header dict area
        let pos = pdf.windows(7).position(|w| w == b"1 0 obj").unwrap();
        pdf.splice(pos..pos, b"/Linearized 1.0 ".iter().cloned());
        let doc = PdfDoc::parse(pdf).unwrap();
        assert!(doc.info.linearized);
    }

    #[test]
    fn text_ops_tj_array() {
        // [(Hel) -20 (lo)] TJ should produce "Hello"
        let content = b"BT [(Hel) -20 (lo)] TJ ET";
        let text = extract_text_ops(content);
        assert_eq!(text, "Hello");
    }

    #[test]
    fn text_ops_single_quote() {
        let content = b"BT (World) ' ET";
        let text = extract_text_ops(content);
        assert_eq!(text, "World");
    }
}

#[cfg(test)]
mod inflate_tests {
    use super::*;
    #[test]
    fn zlib_roundtrip() {
        // zlib.compress(b"hello world hello world"*10)
        let c: Vec<u8> = vec![120,156,203,72,205,201,201,87,40,207,47,202,73,81,200,64,176,51,134,151,48,0,230,151,88,113];
        let out = inflate(&c).unwrap();
        assert_eq!(out.len(), 230);
        assert!(out.starts_with(b"hello"));
    }
}
