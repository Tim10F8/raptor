---
name: github-forensics-schema
description: Pydantic schema for verifiable GitHub forensic evidence. Defines strict types for all evidence that can be independently verified via GitHub API, GH Archive (BigQuery), Git, or Wayback Machine. Use as the data model for GitHub security investigations.
version: 1.0
author: mbrg
tags:
  - github
  - forensics
  - schema
  - pydantic
  - osint
  - evidence
---

# GitHub Forensics Verifiable Evidence Schema

**Purpose**: Strict Pydantic schema defining all verifiable GitHub forensic evidence types. Every evidence type can be independently verified through public sources - no guesses.

## When to Use This Skill

- Building a GitHub security investigation that requires structured evidence
- Collecting IOCs from GitHub-related incidents
- Creating reproducible forensic reports with verifiable claims
- Integrating multiple evidence sources (GH Archive, Wayback, GitHub API)
- Establishing attribution and timeline with provable data

## Core Principles

**All Evidence Must Be Verifiable**:
- Every evidence type includes `VerificationInfo` with source and method
- No speculative or inferred data without explicit marking
- Evidence sources: GitHub API, GH Archive (BigQuery), Wayback Machine, Git

**Evidence Categories**:

| Category | Source | Verification Method |
|----------|--------|---------------------|
| Commits | GitHub API/Web | `GET /repos/{owner}/{repo}/commits/{sha}` |
| Deleted Commits | GH Archive | Zero-commit PushEvent `before` SHA |
| GitHub Events | GH Archive | BigQuery query on `githubarchive.day.*` |
| Archived Content | Wayback | CDX API + archive.org URLs |
| Recovered Content | Multiple | Cross-reference with source snapshots |

## Schema Structure

### Base Types

```python
from github_forensics_schema.schema import (
    EvidenceSource,      # Enum: github_api, gharchive, wayback, git_local
    EventType,           # Enum: PushEvent, IssuesEvent, etc.
    GitHubActor,         # User/bot identity
    GitHubRepository,    # Repository reference
    VerificationInfo,    # How to verify evidence
    EvidenceBase,        # Base class for all evidence
)
```

### Commit Evidence

| Type | Description | Verification |
|------|-------------|--------------|
| `CommitEvidence` | Full commit with metadata, files, signature | GitHub API or `.patch` URL |
| `DeletedCommitEvidence` | Force-pushed commit recovered from GH Archive | `before` SHA from zero-commit PushEvent |
| `CommitAuthor` | Git author/committer info | Part of commit metadata |
| `CommitSignature` | GPG/SSH verification | GitHub API `verification` field |
| `CommitFileChange` | File diff within commit | Patch content |

### GH Archive Events

| Type | GH Archive Event | Key Fields |
|------|------------------|------------|
| `PushEventEvidence` | `PushEvent` | `before_sha`, `after_sha`, `commits[]`, `is_force_push` |
| `PullRequestEvidence` | `PullRequestEvent` | `action`, `pr_number`, `pr_title`, `pr_body`, `merged` |
| `IssueEvidence` | `IssuesEvent` | `action`, `issue_number`, `issue_title`, `issue_body` |
| `IssueCommentEvidence` | `IssueCommentEvent` | `comment_id`, `comment_body` |
| `CreateDeleteEventEvidence` | `CreateEvent`/`DeleteEvent` | `ref_type`, `ref_name` |
| `ForkEventEvidence` | `ForkEvent` | `source_repository`, `fork_repository` |
| `WorkflowRunEvidence` | `WorkflowRunEvent` | `workflow_name`, `head_sha`, `conclusion` |
| `ReleaseEvidence` | `ReleaseEvent` | `tag_name`, `release_body` |
| `WatchEvidence` | `WatchEvent` | Repository starred |
| `MemberEvidence` | `MemberEvent` | Collaborator changes |

### Wayback Machine Evidence

| Type | Description | Source |
|------|-------------|--------|
| `WaybackSnapshot` | Single archive.org snapshot | CDX API |
| `WaybackEvidence` | Collection of snapshots for a URL | CDX API query |
| `RecoveredIssueContent` | Issue/PR text from archived page | Wayback HTML parsing |
| `RecoveredFileContent` | File content from archived blob page | Wayback HTML parsing |
| `RecoveredWikiContent` | Wiki page from archive | Wayback HTML parsing |
| `RecoveredForkList` | Fork list from network/members page | Wayback HTML parsing |

### Investigation Containers

| Type | Purpose |
|------|---------|
| `TimelineEntry` | Single event in chronological sequence |
| `ActorProfile` | Aggregated activity for a GitHub user |
| `IOC` | Indicator of Compromise with evidence link |
| `Investigation` | Complete investigation container |

## Evidence Type Reference

### CommitEvidence

```python
CommitEvidence(
    evidence_id="commit-001",
    observed_at=datetime.utcnow(),
    verification=VerificationInfo(
        source=EvidenceSource.GITHUB_API,
        verification_url="https://github.com/org/repo/commit/abc123..."
    ),
    repository=GitHubRepository(owner="org", name="repo", full_name="org/repo"),
    sha="abc123def456789...",  # Full 40-char SHA required
    short_sha="abc123d",
    message="Add feature X",
    author=CommitAuthor(name="Dev", email="dev@example.com", date=datetime.utcnow()),
    committer=CommitAuthor(name="Dev", email="dev@example.com", date=datetime.utcnow()),
    files=[CommitFileChange(filename="src/file.py", status="modified", additions=10, deletions=2)],
    is_dangling=True,  # Not on any branch
    was_force_pushed=True  # Recovered from force-push
)
```

### PushEventEvidence (Force Push Detection)

```python
PushEventEvidence(
    evidence_id="push-001",
    observed_at=datetime(2025, 7, 13, 20, 30, 24),
    verification=VerificationInfo(
        source=EvidenceSource.GHARCHIVE,
        bigquery_table="githubarchive.day.20250713",
        verification_query="""
            SELECT * FROM `githubarchive.day.20250713`
            WHERE type = 'PushEvent' AND repo.name = 'org/repo'
            AND JSON_EXTRACT_SCALAR(payload, '$.size') = '0'
        """
    ),
    repository=GitHubRepository(owner="org", name="repo", full_name="org/repo"),
    actor=GitHubActor(login="developer"),
    ref="refs/heads/main",
    before_sha="deleted123...",  # This SHA was force-pushed over
    after_sha="newhead456...",
    size=0,  # Zero commits = force push
    commits=[],
    is_force_push=True
)
```

### IssueEvidence (Deleted Issue Recovery)

```python
IssueEvidence(
    evidence_id="issue-001",
    observed_at=datetime(2025, 7, 13, 19, 41, 44),
    verification=VerificationInfo(
        source=EvidenceSource.GHARCHIVE,
        bigquery_table="githubarchive.day.20250713",
        verification_query="""
            SELECT JSON_EXTRACT_SCALAR(payload, '$.issue.title'),
                   JSON_EXTRACT_SCALAR(payload, '$.issue.body')
            FROM `githubarchive.day.20250713`
            WHERE type = 'IssuesEvent' AND repo.name = 'aws/aws-toolkit-vscode'
        """
    ),
    repository=GitHubRepository(owner="aws", name="aws-toolkit-vscode", full_name="aws/aws-toolkit-vscode"),
    actor=GitHubActor(login="lkmanka58"),
    action=IssueAction.OPENED,
    issue_number=123,
    issue_title="aws amazon donkey aaaaaaiii",
    issue_body="Full issue body text preserved here...",
    is_deleted=True  # Issue no longer exists on GitHub
)
```

### WorkflowRunEvidence (API Abuse Detection)

```python
# Absence of WorkflowRunEvent during suspicious commit = Direct API attack
WorkflowRunEvidence(
    evidence_id="workflow-001",
    observed_at=datetime(2025, 7, 13, 20, 48, 15),
    verification=VerificationInfo(
        source=EvidenceSource.GHARCHIVE,
        verification_query="""
            SELECT * FROM `githubarchive.day.20250713`
            WHERE type = 'WorkflowRunEvent'
            AND repo.name = 'aws/aws-toolkit-vscode'
            AND created_at BETWEEN '2025-07-13T20:25:00Z' AND '2025-07-13T20:35:00Z'
        """
    ),
    repository=GitHubRepository(owner="aws", name="aws-toolkit-vscode", full_name="aws/aws-toolkit-vscode"),
    actor=GitHubActor(login="aws-toolkit-automation", is_bot=True),
    action="completed",
    workflow_name="deploy-automation",
    workflow_path=".github/workflows/deploy.yml",
    head_sha="legitimate123...",
    conclusion=WorkflowConclusion.SUCCESS
)
```

### WaybackEvidence

```python
WaybackEvidence(
    evidence_id="wayback-001",
    observed_at=datetime.utcnow(),
    verification=VerificationInfo(
        source=EvidenceSource.WAYBACK,
        verification_url="https://web.archive.org/cdx/search/cdx?url=github.com/deleted/repo&output=json"
    ),
    repository=GitHubRepository(owner="deleted", name="repo", full_name="deleted/repo"),
    content_type="repository_homepage",
    snapshots=[
        WaybackSnapshot(
            timestamp="20230615142311",
            original_url="https://github.com/deleted/repo",
            archive_url="https://web.archive.org/web/20230615142311/https://github.com/deleted/repo",
            status_code=200
        )
    ],
    latest_snapshot=...,
    earliest_snapshot=...,
    total_snapshots=5,
    content_recovered=True
)
```

### Investigation Container

```python
Investigation(
    investigation_id="INV-2025-001",
    title="Amazon Q Supply Chain Attack Analysis",
    description="Investigation of malicious commit to aws-toolkit-vscode",
    created_at=datetime.utcnow(),
    updated_at=datetime.utcnow(),
    status="active",
    target_repositories=[
        GitHubRepository(owner="aws", name="aws-toolkit-vscode", full_name="aws/aws-toolkit-vscode")
    ],
    target_actors=["lkmanka58", "aws-toolkit-automation"],
    time_range_start=datetime(2025, 6, 1),
    time_range_end=datetime(2025, 7, 31),
    evidence=[...],  # List of AnyEvidence
    timeline=[...],  # Ordered TimelineEntry list
    actors=[...],    # ActorProfile list
    iocs=[
        IOC(
            ioc_type="commit_sha",
            value="678851bbe9776228f55e0460e66a6167ac2a1685",
            context="Malicious commit to main branch",
            evidence_id="commit-001",
            confidence="confirmed"
        )
    ],
    findings="Direct API attack using compromised automation token...",
    recommendations=["Rotate automation tokens", "Enable branch protection"]
)
```

## IOC Types

The schema supports these IOC types:

| IOC Type | Example | Evidence Source |
|----------|---------|-----------------|
| `commit_sha` | `678851bbe9...` | CommitEvidence, PushEventEvidence |
| `file_path` | `.env`, `config.json` | CommitFileChange |
| `email` | `attacker@evil.com` | CommitAuthor |
| `username` | `lkmanka58` | GitHubActor |
| `repository` | `lkmanka58/code_whisperer` | GitHubRepository |
| `tag_name` | `stability` | CreateDeleteEventEvidence |
| `branch_name` | `feature/backdoor` | PushEventEvidence, CreateDeleteEventEvidence |
| `workflow_name` | `deploy-automation` | WorkflowRunEvidence |
| `api_key_pattern` | `ghp_...`, `AKIA...` | Recovered content |
| `secret_pattern` | Connection strings | Recovered content |

## Related Skills

- **github-commit-recovery**: Recover commit content using SHAs from this schema
- **github-archive**: Query GH Archive to populate event evidence types
- **github-wayback-recovery**: Recover deleted content for Wayback evidence types

## Usage Notes

1. **Always populate `verification`**: Every evidence piece must include how to verify it
2. **Use full SHAs**: Commit SHAs must be 40 characters for reproducibility
3. **Include BigQuery queries**: For GH Archive evidence, include the exact query used
4. **Link related evidence**: Use `related_evidence_ids` to connect correlated events
5. **Distinguish recovered content**: Mark `is_deleted=True` for content no longer on GitHub
