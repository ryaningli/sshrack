//! sshrack binary entry. Hosts the CLI and the SSH_ASKPASS role dispatch.

fn main() -> anyhow::Result<()> {
    // Real dispatch lands in later tasks. For now, print a stub so the
    // workspace builds end-to-end.
    println!("sshrack (skeleton)");
    Ok(())
}
