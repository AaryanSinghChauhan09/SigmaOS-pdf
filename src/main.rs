//! SigmaOS-pdf — PDF info/text CLI.
//!
//! Usage:
//!   sigmaos-pdf info <file.pdf>
//!   sigmaos-pdf text <file.pdf> [--page N] [--all]
//!   sigmaos-pdf pages <file.pdf>
//!
//! Tolerant parser: xref-free object scan, FlateDecode inflate, Tj/TJ text ops.

use pdf::PdfDoc;
use std::path::Path;
use std::process::exit;

fn usage() -> ! {
    eprintln!("usage: sigmaos-pdf <info|text|pages> <file.pdf> [--page N|--all]");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 { usage(); }
    let cmd = args[0].as_str();
    let file = &args[1];
    let rest = &args[2..];

    let doc = match PdfDoc::open(Path::new(file)) {
        Ok(d) => d,
        Err(e) => { eprintln!("sigmaos-pdf: {}", e); exit(1); }
    };

    match cmd {
        "info" => {
            let i = &doc.info;
            println!("file: {}", file);
            println!("size: {} bytes", i.file_size);
            println!("version: PDF-{}", i.version);
            println!("pages: {}", i.page_count);
            println!("encrypted: {}", i.encrypted);
            println!("linearized: {}", i.linearized);
            println!("tagged: {}", i.tagged);
            for (k, v) in [
                ("title", &i.title), ("author", &i.author), ("subject", &i.subject),
                ("keywords", &i.keywords), ("creator", &i.creator),
                ("producer", &i.producer), ("creation_date", &i.creation_date),
                ("mod_date", &i.mod_date),
            ] {
                if let Some(val) = v { println!("{}: {}", k, val); }
            }
        }
        "pages" => {
            println!("{}", doc.page_count());
        }
        "text" => {
            let page_arg = rest.iter().position(|s| s=="--page")
                .and_then(|i| rest.get(i+1)).and_then(|s| s.parse::<usize>().ok());
            let all = rest.iter().any(|s| s=="--all");
            if all || page_arg.is_none() {
                match doc.all_text() {
                    Ok(pages) => {
                        for p in pages {
                            println!("--- page {} ---", p.page);
                            println!("{}", p.text);
                        }
                    }
                    Err(e) => { eprintln!("sigmaos-pdf: {}", e); exit(1); }
                }
            } else {
                let n = page_arg.unwrap();
                match doc.page_text(n.saturating_sub(1)) {
                    Ok(t) => println!("{}", t),
                    Err(e) => { eprintln!("sigmaos-pdf: {}", e); exit(1); }
                }
            }
        }
        _ => usage(),
    }
}
