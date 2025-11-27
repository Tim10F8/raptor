---
name: Github Archive Analysis
description: Analyze OSS Github repositories using Github historical archive
version: 1.0
author: mbrg
tags:
  - github
  - git
  - forensics
---

# GitHub Forensics using GH Archive 

## Overview

GH Archive is an immutable record of public GitHub activity. It's an OSS project that stores GitHub log events for all public repositories. Unlike local git repositories (which can be rewritten), GitHub Archive provides tamper-proof evidence of GitHub events as they occurred. GH Archive is available to query via Google BigQuery (requires Google Cloud credentials).

## Core Principles

**ALWAYS PREFER GitHub Archive as forensic evidence over**:
- Local git command outputs (git log, git show) - commits can be backdated/forged
- Unverified claims from articles or reports - require independent confirmation
- GitHub web interface screenshots - can be manipulated
- Single-source evidence - always cross-verify

**GitHub Archive IS your ground truth for**:
- Actor attribution (who performed actions)
- Timeline reconstruction (when events occurred)
- Event verification (what actually happened)
- Pattern analysis (behavioral fingerprinting)
- Cross-repository activity tracking
- **Deleted content recovery** (issues, PRs, tags, commits references remain in archive)
- **Repository deletion forensics** (commit SHAs persist even after repo deletion and history rewrites)

### What Persists After Deletion

**Deleted Issues & PRs**:
- Issue creation events (IssuesEvent) remain in archive
- Issue comments (IssueCommentEvent) remain accessible
- PR open/close/merge events (PullRequestEvent) persist
- **Forensic Value**: Recover deleted evidence of social engineering, reconnaissance, or coordination

**Deleted Tags & Branches**:
- CreateEvent records for tag/branch creation persist
- DeleteEvent records document when deletion occurred
- **Forensic Value**: Reconstruct attack staging infrastructure (e.g., malicious payload delivery tags)

**Deleted Repositories**:
- All PushEvents to the repository remain queryable
- Commit SHAs are permanently recorded in archive
- Fork relationships (ForkEvent) survive deletion
- **Forensic Value**: Access commit metadata even after threat actor deletes evidence

**Deleted User Accounts**:
- All activity events remain attributed to deleted username
- Timeline reconstruction remains possible
- **Limitation**: Direct code access lost, but commit SHAs can be searched elsewhere

### When to Use This Skill

- Investigating security incidents involving GitHub repositories
- Building threat actor attribution profiles
- Verifying claims about repository activity
- Reconstructing attack timelines
- Analyzing automation system compromises
- Detecting supply chain reconnaissance
- Cross-repository behavioral analysis
- Workflow execution verification
- Pattern-based anomaly detection

GitHub Archive analysis should be your FIRST step in any GitHub-related security investigation. Start with the immutable record, then enrich with additional sources.

## Access GitHub Archive via BigQuery

### Access via BigQuery

The entire GH Archive is also available as a public dataset on Google BigQuery: the dataset is automatically updated every hour and enables you to run arbitrary SQL-like queries over the entire dataset in seconds. To get started:

1. If you don't already have a Google project...
    a. **Login** into the Google Developer Console
    b. **Create a project** and activate the BigQuery API
3. [Go to BigQuery](https://console.cloud.google.com/bigquery), and select your newly created project from the dropdown in the header bar.
Execute your first query against the public "githubarchive" dataset. You can just copy and paste the query below and run, once you've selected your project. You can also look through the public dataset itself, but you will not have permission to execute queries on behalf of the project.

1. If you don't already have a Google project...
    a. **Login** into the Google Developer Console
    b. **Create a project** and activate the BigQuery API
2. **Google Cloud Credentials**: create a service account with BigQuery access and download the JSON credenetials.

Google provides a free tier with 1 TB of data processed per month free.

**Standard Setup Pattern**:
```python
from google.cloud import bigquery
from google.oauth2 import service_account

credentials = service_account.Credentials.from_service_account_file(
    'path/to/credentials.json',
    scopes=['https://www.googleapis.com/auth/bigquery']
)

client = bigquery.Client(
    credentials=credentials,
    project=credentials.project_id
)
```

### Table Organization

**Dataset**: `githubarchive`

**Table Patterns**:
- **Daily tables**: `githubarchive.day.YYYYMMDD` (e.g., `githubarchive.day.20250713`)
- **Monthly tables**: `githubarchive.month.YYYYMM` (e.g., `githubarchive.month.202507`)
- **Yearly tables**: `githubarchive.year.YYYY` (e.g., `githubarchive.year.2025`)

**Wildcard Patterns**:
- All days in June 2025: `githubarchive.day.202506*`
- All months in 2025: `githubarchive.month.2025*`
- All data in 2025: `githubarchive.year.2025*`

**Data Availability**: February 12, 2011 to present (updated hourly)

### Schema Structure

**Top-Level Fields**:
```sql
type              -- Event type (PushEvent, IssuesEvent, etc.)
created_at        -- Timestamp when event occurred (UTC)
actor.login       -- GitHub username who performed the action
actor.id          -- GitHub user ID
repo.name         -- Repository name (org/repo format)
repo.id           -- Repository ID
org.login         -- Organization login (if applicable)
org.id            -- Organization ID
payload           -- JSON string with event-specific data
```

**Payload Field**: JSON-encoded string containing event-specific details. Must be parsed with `JSON_EXTRACT_SCALAR()` or loaded with `json.loads()` in Python.

### Event Types Reference

#### Repository Events

**PushEvent** - Commits pushed to a repository
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.ref')        -- Branch (refs/heads/master)
JSON_EXTRACT_SCALAR(payload, '$.before')     -- SHA before push
JSON_EXTRACT_SCALAR(payload, '$.after')      -- SHA after push
JSON_EXTRACT_SCALAR(payload, '$.size')       -- Number of commits
-- payload.commits[] contains array of commit objects with sha, message, author
```

**PullRequestEvent** - Pull request opened, closed, merged
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.action')              -- opened, closed, merged
JSON_EXTRACT_SCALAR(payload, '$.pull_request.number')
JSON_EXTRACT_SCALAR(payload, '$.pull_request.title')
JSON_EXTRACT_SCALAR(payload, '$.pull_request.merged') -- true/false
```

**CreateEvent** - Branch or tag created
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.ref_type')   -- branch, tag, repository
JSON_EXTRACT_SCALAR(payload, '$.ref')        -- Name of branch/tag
```

**DeleteEvent** - Branch or tag deleted
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.ref_type')   -- branch or tag
JSON_EXTRACT_SCALAR(payload, '$.ref')        -- Name of deleted ref
```

**ForkEvent** - Repository forked
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.forkee.full_name')  -- New fork name
```

#### Automation & CI/CD Events

**WorkflowRunEvent** - GitHub Actions workflow run status changes
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.action')               -- requested, completed
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.name')
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.path')    -- .github/workflows/file.yml
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.status')  -- queued, in_progress, completed
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.conclusion') -- success, failure, cancelled
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.head_sha')
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.head_branch')
```

**WorkflowJobEvent** - Individual job within workflow
**CheckRunEvent** - Check run status (CI systems)
**CheckSuiteEvent** - Check suite for commits

#### Issue & Discussion Events

**IssuesEvent** - Issue opened, closed, edited
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.action')        -- opened, closed, reopened
JSON_EXTRACT_SCALAR(payload, '$.issue.number')
JSON_EXTRACT_SCALAR(payload, '$.issue.title')
JSON_EXTRACT_SCALAR(payload, '$.issue.body')
```

**IssueCommentEvent** - Comment on issue or pull request

**PullRequestReviewEvent** - PR review submitted
**PullRequestReviewCommentEvent** - Comment on PR diff

#### Other Events

**WatchEvent** - Repository starred
**ReleaseEvent** - Release published
**MemberEvent** - Collaborator added/removed
**PublicEvent** - Repository made public

### Learn More

Detailed information in case a drill-down is needed:
- About GH Archive https://www.gharchive.org/
- Full schema of GitHub events https://docs.github.com/en/rest/using-the-rest-api/github-event-types

## Real-World Investigation Patterns

### Find Deleted PRs

**Scenario**: Media claims an attacker has submitted a PR in "late June" containing malicious code, but PR is now deleted and cannot be found on github.com.

**Forensic Approach**:
```sql
-- Search for ALL PR events by suspected actor in June 2025
SELECT
    type,
    created_at,
    repo.name,
    payload
FROM `githubarchive.day.202506*`
WHERE
    actor.login = 'suspected-actor'
    AND repo.name = 'target/repository'
    AND type = 'PullRequestEvent'
ORDER BY created_at
```

**Evidence Validation**:
- If claim is TRUE: Archive will show PullRequestEvent with action='opened'
- If claim is FALSE: No events found, claim is disproven
- **Investigation Outcome**: Can definitively verify or refute timeline claims

**Real Example**: Amazon Q investigation verified no PR from the attacker's account in late June 2025, disproving media's claim of malicious code commited to the repository via deleted PR.

### Deleted Repository Forensics

**Scenario**: Threat actor creates staging repository, pushes malicious code, then deletes repo to cover tracks.

**Forensic Approach**:
```sql
-- Find repository creation and all push events
SELECT
    type,
    created_at,
    payload
FROM `githubarchive.day.2025*`
WHERE
    actor.login = 'threat-actor'
    AND type IN ('CreateEvent', 'PushEvent')
    AND (
        JSON_EXTRACT_SCALAR(payload, '$.repository.name') = 'staging-repo'
        OR repo.name LIKE 'threat-actor/staging-repo'
    )
ORDER BY created_at
```

**Evidence Recovery**:
- CreateEvent reveals repository creation timestamp
- PushEvents contain commit SHAs and metadata
- Commit SHAs can be used to recover code content via other archives or forks
- **Investigation Outcome**: Complete reconstruction of attacker's staging infrastructure

**Real Example**: lkmanka58/code_whisperer repository deleted after attack, but GitHub Archive revealed June 13 creation with 3 commits containing AWS IAM role assumption attempts.

### Deleted Tag Analysis

**Scenario**: Malicious tag used for payload delivery, then deleted to hide evidence.

**Forensic Approach**:
```sql
-- Search for tag creation and deletion events
SELECT
    type,
    created_at,
    actor.login,
    payload
FROM `githubarchive.day.20250713`
WHERE
    repo.name = 'target/repository'
    AND type IN ('CreateEvent', 'DeleteEvent')
    AND JSON_EXTRACT_SCALAR(payload, '$.ref_type') = 'tag'
ORDER BY created_at
```

**Timeline Reconstruction**:
```json
{
  "19:41:44 UTC": "CreateEvent - tag 'stability' created by aws-toolkit-automation",
  "20:30:24 UTC": "PushEvent - malicious commit references tag",
  "Next day": "DeleteEvent - tag 'stability' deleted (cleanup attempt)"
}
```

**Real Example**: Amazon Q attack used 'stability' tag for malicious payload delivery. Tag was deleted, but CreateEvent in GitHub Archive preserved creation timestamp and actor, proving 48-hour staging window.

### Deleted Branch Reconstruction

**Scenario**: Attacker creates development branch with malicious code, pushes commits, then deletes branch after merging or to cover tracks.

**Forensic Approach**:
```sql
-- Step 1: Find branch creation and deletion events
SELECT
    type,
    created_at,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.ref') as branch_name,
    JSON_EXTRACT_SCALAR(payload, '$.ref_type') as ref_type
FROM `githubarchive.day.2025*`
WHERE
    repo.name = 'target/repository'
    AND type IN ('CreateEvent', 'DeleteEvent')
    AND JSON_EXTRACT_SCALAR(payload, '$.ref_type') = 'branch'
ORDER BY created_at
```

**Commit SHA Recovery**:
```sql
-- Step 2: Extract ALL commit SHAs, messages, and authors from deleted branch
SELECT
    created_at,
    actor.login as pusher,
    JSON_EXTRACT_SCALAR(payload, '$.ref') as branch_ref,
    JSON_EXTRACT(payload, '$.commits') as commits_json,
    -- Extract individual commit details
    JSON_EXTRACT_SCALAR(commit, '$.sha') as commit_sha,
    JSON_EXTRACT_SCALAR(commit, '$.message') as commit_message,
    JSON_EXTRACT_SCALAR(commit, '$.author.name') as author_name,
    JSON_EXTRACT_SCALAR(commit, '$.author.email') as author_email
FROM `githubarchive.day.2025*`,
UNNEST(JSON_EXTRACT_ARRAY(payload, '$.commits')) as commit
WHERE
    repo.name = 'target/repository'
    AND type = 'PushEvent'
    AND JSON_EXTRACT_SCALAR(payload, '$.ref') = 'refs/heads/deleted-branch-name'
ORDER BY created_at
```

**Evidence Recovery**:
- **Commit SHAs**: All commit identifiers permanently recorded in PushEvent payload
- **Commit Messages**: Full commit messages preserved in commits array
- **Author Metadata**: Name and email from commit author field
- **Pusher Identity**: Actor who executed the push operation
- **Temporal Sequence**: Exact timestamps for each push operation
- **Branch Lifecycle**: Complete creation-to-deletion timeline

**Forensic Value**: Even after branch deletion, commit SHAs can be used to:
- Search for commits in forked repositories
- Check if commits were merged into other branches
- Search external code archives (Software Heritage, etc.)
- Reconstruct complete attack development timeline

### Automation vs Direct API Attribution

**Scenario**: Suspicious commits appear under automation account name. Determine if they came from legitimate GitHub Actions workflow execution or direct API abuse with compromised token.

**Forensic Approach**:
```sql
-- Step 1: Search for workflow events during suspicious commit window
SELECT
    type,
    created_at,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.workflow_run.name') as workflow_name,
    JSON_EXTRACT_SCALAR(payload, '$.workflow_run.head_sha') as commit_sha,
    JSON_EXTRACT_SCALAR(payload, '$.workflow_run.conclusion') as conclusion
FROM `githubarchive.day.YYYYMMDD`
WHERE
    repo.name = 'org/repository'
    AND type IN ('WorkflowRunEvent', 'WorkflowJobEvent')
    AND created_at >= 'YYYY-MM-DDTHH:MM:SSZ'  -- Start of suspicious window
    AND created_at <= 'YYYY-MM-DDTHH:MM:SSZ'  -- End of suspicious window
ORDER BY created_at
```

**Baseline Pattern Analysis**:
```sql
-- Step 2: Establish normal automation behavior patterns
SELECT
    type,
    created_at,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.workflow_run.name') as workflow_name,
    JSON_EXTRACT_SCALAR(payload, '$.workflow_run.head_sha') as commit_sha
FROM `githubarchive.day.YYYYMMDD*`
WHERE
    repo.name = 'org/repository'
    AND actor.login = 'automation-account'
    AND type = 'WorkflowRunEvent'
ORDER BY created_at
```

**Commit-to-Workflow Correlation**:
```sql
-- Step 3: Check if specific commit SHA has associated workflow
SELECT
    w.type,
    w.created_at,
    w.actor.login,
    JSON_EXTRACT_SCALAR(w.payload, '$.workflow_run.name') as workflow_name,
    JSON_EXTRACT_SCALAR(w.payload, '$.workflow_run.head_sha') as workflow_commit
FROM `githubarchive.day.YYYYMMDD` w
WHERE
    w.repo.name = 'org/repository'
    AND w.type = 'WorkflowRunEvent'
    AND JSON_EXTRACT_SCALAR(w.payload, '$.workflow_run.head_sha') = 'suspicious-commit-sha'
```

**Investigation Outcome**: Absence of workflow events = Direct API attack with stolen token

**Real Example**: Amazon Q investigation needed to determine if malicious commit 678851bbe9776228f55e0460e66a6167ac2a1685 (pushed July 13, 2025 20:30:24 UTC by aws-toolkit-automation) came from compromised workflow or direct API abuse. GitHub Archive query showed ZERO WorkflowRunEvent or WorkflowJobEvent records during the 20:25-20:35 UTC window. Baseline analysis revealed the same automation account had 18 workflows that day, all clustered in 20:48-21:02 UTC. The 9+ hour gap and complete workflow absence during the malicious commit proved direct API attack, not workflow compromise.
