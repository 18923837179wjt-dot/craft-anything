//! `cargo xtask fonts`: get the craft-fonts fallbacks a local build needs.
//!
//! The desktop app embeds DM Sans and JetBrains Mono only; the CJK, Arabic, Thai, Hebrew,
//! Devanagari and symbol fallbacks live in the sibling craft-fonts repository. A build without
//! them shows boxes for those characters, so a local build needs them.
//!
//! This finds a craft-fonts checkout (or clones one) and prints the `CRAFT_FONTS_DIR` to build
//! with. Releases and CI set the variable themselves; this is for people building from source.

use std::path::{Path, PathBuf};

/// The craft-fonts commit the release and CI workflows pin. Changing it means changing those
/// workflows too, so the three builds ship the same glyphs.
const PINNED_REF: &str = "b076417b5880bd4154bd22f00695b1d28c6bea83";

const REPO: &str = "storytold/craft-fonts";

/// Where a checkout is looked for, in order: the variable that is already set, then the
/// directories next to this repository (the usual place for a sibling checkout).
pub fn candidates(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(set) = std::env::var_os("CRAFT_FONTS_DIR") {
        out.push(PathBuf::from(set));
    }
    if let Some(parent) = root.parent() {
        out.push(parent.join("craft-fonts"));
    }
    out.push(root.join("craft-fonts"));
    out
}

/// A directory is a craft-fonts checkout when its manifest is there.
pub fn is_checkout(dir: &Path) -> bool {
    dir.join("fonts").join("manifest.txt").is_file()
}

/// `cargo xtask fonts [--check]`: find or fetch the fallbacks and print the variable to set.
pub fn run(root: &Path, check: bool) -> bool {
    for dir in candidates(root) {
        if is_checkout(&dir) {
            println!("craft-fonts: {}", dir.display());
            print_env(&dir);
            return true;
        }
    }
    if check {
        eprintln!("fonts: no craft-fonts checkout found; run `cargo xtask fonts` to fetch one");
        return false;
    }
    let target = root.parent().map(|p| p.join("craft-fonts")).unwrap_or_else(|| root.join("craft-fonts"));
    match fetch(&target) {
        Ok(()) => {
            println!("craft-fonts: {}", target.display());
            print_env(&target);
            true
        }
        Err(e) => {
            eprintln!("fonts: {e}");
            eprintln!("fonts: clone {REPO} yourself and set CRAFT_FONTS_DIR to the checkout");
            false
        }
    }
}

/// The line a developer pastes into their shell (and the build reads).
fn print_env(dir: &Path) {
    println!();
    println!("Build with the fallbacks in:");
    println!("  $env:CRAFT_FONTS_DIR = \"{}\"", dir.display());
}

/// Fetch the pinned craft-fonts commit into `target` with `git`.
fn fetch(target: &Path) -> Result<(), String> {
    if target.exists() {
        return Err(format!("{} exists but has no fonts/manifest.txt", target.display()));
    }
    let git = |args: &[&str]| -> Result<(), String> {
        let out = std::process::Command::new("git").args(args).output().map_err(|e| format!("git: {e}"))?;
        if !out.status.success() {
            return Err(format!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(())
    };
    println!("fetching {REPO} at {PINNED_REF}…");
    git(&["clone", "--quiet", "https://github.com/storytold/craft-fonts.git", &target.to_string_lossy()])?;
    git(&["-C", &target.to_string_lossy(), "checkout", "--quiet", PINNED_REF])?;
    if !is_checkout(target) {
        return Err(format!("{} has no fonts/manifest.txt after checkout", target.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A directory only counts when the manifest is there: a folder with a `fonts` directory but
    /// no manifest would make the build fail later, with a much less obvious message.
    #[test]
    fn a_checkout_needs_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_checkout(dir.path()));
        std::fs::create_dir_all(dir.path().join("fonts")).unwrap();
        assert!(!is_checkout(dir.path()));
        std::fs::write(dir.path().join("fonts/manifest.txt"), "").unwrap();
        assert!(is_checkout(dir.path()));
    }

    /// The variable that is already set comes first, so a person who set it gets their own
    /// directory rather than a sibling checkout.
    #[test]
    fn the_set_variable_is_the_first_candidate() {
        let root = Path::new("/repo");
        let set = PathBuf::from("/somewhere/else");
        // SAFETY: single-threaded test; the variable is read back right after.
        unsafe { std::env::set_var("CRAFT_FONTS_DIR", &set) };
        let found = candidates(root);
        unsafe { std::env::remove_var("CRAFT_FONTS_DIR") };
        assert_eq!(found.first().map(PathBuf::as_path), Some(set.as_path()));
    }
}
