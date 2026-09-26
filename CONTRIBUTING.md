# Contributing to Again

Start with the [README](README.md) for the current development checkout, setup
commands, and architecture and evidence links. Keep each change focused and
record the checks that apply to it. Changes to measured behavior should preserve
the original benchmark evidence and distinguish new results from earlier runs.

## Set your commit identity

Use a verified email associated with your GitHub account or copy your exact
GitHub-provided `noreply` address from
[email settings](https://github.com/settings/emails). Replace the placeholders
with your own values, then run these commands inside the repository:

```bash
git config --local user.name "Your Name"
git config --local user.email "YOUR_GITHUB_COMMIT_EMAIL"
git config --local user.useConfigOnly true
git var GIT_AUTHOR_IDENT
git var GIT_COMMITTER_IDENT
```

Check both identities before committing from an agent or a new worktree.
Repository-local configuration is shared by linked worktrees unless overridden;
environment variables can also override the effective identity.
`user.useConfigOnly` prevents Git from guessing an identity but does not validate
an explicitly configured address. The account used to push is separate from the
author recorded in a commit.

After committing, check the stored author:

```bash
git log -1 --format='%h %an <%ae>'
```

Configuration changes affect future commits only. Preserve published history and
benchmark source hashes. See GitHub's
[commit email guide](https://docs.github.com/en/account-and-profile/how-tos/email-preferences/setting-your-commit-email-address)
for account association and its
[contribution troubleshooting guide](https://docs.github.com/en/account-and-profile/how-tos/contribution-settings/troubleshooting-missing-contributions)
for default-branch requirements and profile update delays.
