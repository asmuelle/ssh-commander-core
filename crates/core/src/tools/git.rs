//! Git deploy-state — pull a quick snapshot of a repo on a remote host:
//! current branch, HEAD sha, ahead/behind vs upstream, dirty file count,
//! and last commit summary.
//!
//! Single round-trip: `git -C <path> status --porcelain=v2 --branch` plus
//! `git log -1 --format=%H%x09%an%x09%ar%x09%s`, joined with `; ` so we
//! pay one ssh exec.

use crate::ssh::SshClient;
use crate::tools::ToolsError;

#[derive(Debug, Clone)]
pub struct GitStatus {
    pub repo_path: String,
    pub branch: Option<String>,
    pub head: Option<String>,
    pub upstream: Option<String>,
    pub ahead: u32,
    pub behind: u32,
    pub dirty_files: u32,
    pub untracked_files: u32,
    pub last_commit_sha: Option<String>,
    pub last_commit_author: Option<String>,
    pub last_commit_age: Option<String>,
    pub last_commit_subject: Option<String>,
}

/// Fetch deploy-state for `repo_path` on the given SSH connection.
pub async fn git_status(client: &SshClient, repo_path: &str) -> Result<GitStatus, ToolsError> {
    // Light shell-quoting: only single-quote the path. Reject paths with
    // single quotes outright — repository paths are user-provided so we
    // don't trust them, and `git -C` needs a literal directory anyway.
    if repo_path.contains('\'') {
        return Err(ToolsError::Parse(
            "repo path contains a single quote".into(),
        ));
    }

    let cmd = format!(
        "git -C '{path}' status --porcelain=v2 --branch 2>&1 ; \
         echo '--LOG--' ; \
         git -C '{path}' log -1 --format='%H%x09%an%x09%ar%x09%s' 2>&1",
        path = repo_path
    );

    let out = client
        .execute_command_full(&cmd)
        .await
        .map_err(|e| ToolsError::SshExec(e.to_string()))?;

    let combined = out.combined();
    parse(repo_path, &combined)
}

fn parse(repo_path: &str, output: &str) -> Result<GitStatus, ToolsError> {
    // Split the two halves at our literal sentinel.
    let (status_block, log_block) = match output.split_once("--LOG--") {
        Some((a, b)) => (a, b.trim()),
        None => (output, ""),
    };

    // If `git` produced "fatal: not a git repository", reject early so
    // the UI can show a clean message instead of zeroed fields.
    if status_block.contains("fatal: not a git repository") || status_block.contains("fatal: ") {
        let first_line = status_block.lines().next().unwrap_or("git error").trim();
        return Err(ToolsError::RemoteCommand {
            exit: None,
            message: first_line.to_string(),
        });
    }

    let mut branch: Option<String> = None;
    let mut head: Option<String> = None;
    let mut upstream: Option<String> = None;
    let mut ahead: u32 = 0;
    let mut behind: u32 = 0;
    let mut dirty_files: u32 = 0;
    let mut untracked_files: u32 = 0;

    for line in status_block.lines() {
        if let Some(rest) = line.strip_prefix("# branch.head ") {
            let v = rest.trim();
            if v != "(detached)" {
                branch = Some(v.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("# branch.oid ") {
            let v = rest.trim();
            if v != "(initial)" {
                head = Some(v.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("# branch.upstream ") {
            upstream = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("# branch.ab ") {
            // Format: "+<ahead> -<behind>"
            for part in rest.split_whitespace() {
                if let Some(n) = part.strip_prefix('+') {
                    ahead = n.parse().unwrap_or(0);
                } else if let Some(n) = part.strip_prefix('-') {
                    behind = n.parse().unwrap_or(0);
                }
            }
        } else if line.starts_with("? ") {
            untracked_files += 1;
        } else if line.starts_with("1 ") || line.starts_with("2 ") || line.starts_with("u ") {
            dirty_files += 1;
        }
    }

    let mut last_commit_sha = None;
    let mut last_commit_author = None;
    let mut last_commit_age = None;
    let mut last_commit_subject = None;
    if !log_block.is_empty() && !log_block.starts_with("fatal:") {
        let first_line = log_block.lines().next().unwrap_or("");
        let mut parts = first_line.splitn(4, '\t');
        last_commit_sha = parts
            .next()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        last_commit_author = parts
            .next()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        last_commit_age = parts
            .next()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        last_commit_subject = parts
            .next()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
    }

    Ok(GitStatus {
        repo_path: repo_path.to_string(),
        branch,
        head,
        upstream,
        ahead,
        behind,
        dirty_files,
        untracked_files,
        last_commit_sha,
        last_commit_author,
        last_commit_age,
        last_commit_subject,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clean_repo() {
        let sample = "\
# branch.oid abc123def
# branch.head main
# branch.upstream origin/main
# branch.ab +0 -0
--LOG--
abc123def\tAlice\t2 hours ago\tFix the thing
";
        let s = parse("/srv/app", sample).unwrap();
        assert_eq!(s.branch.as_deref(), Some("main"));
        assert_eq!(s.head.as_deref(), Some("abc123def"));
        assert_eq!(s.upstream.as_deref(), Some("origin/main"));
        assert_eq!(s.ahead, 0);
        assert_eq!(s.behind, 0);
        assert_eq!(s.dirty_files, 0);
        assert_eq!(s.last_commit_subject.as_deref(), Some("Fix the thing"));
    }

    #[test]
    fn parses_dirty_repo_with_ahead_behind() {
        let sample = "\
# branch.oid abc
# branch.head feat
# branch.upstream origin/feat
# branch.ab +3 -1
1 .M N... 100644 100644 100644 aaa bbb file1.txt
2 R. N... 100644 100644 100644 ccc ddd R100 file2.txt\tfile2-old.txt
? newfile.txt
? other.txt
--LOG--
deadbeef\tBob\t1 day ago\tWIP
";
        let s = parse(".", sample).unwrap();
        assert_eq!(s.ahead, 3);
        assert_eq!(s.behind, 1);
        assert_eq!(s.dirty_files, 2);
        assert_eq!(s.untracked_files, 2);
    }

    #[test]
    fn rejects_not_a_repo() {
        let sample = "fatal: not a git repository (or any of the parent directories): .git";
        assert!(parse("/tmp", sample).is_err());
    }
}
