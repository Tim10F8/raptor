"""
GitHub Forensics Verifiable Evidence Schema

Strictly defines verifiable GitHub forensic evidence that can be confirmed
through public sources: GitHub API, GH Archive (BigQuery), Git, and Wayback Machine.

All evidence types are designed to be independently verifiable - no guesses.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl


# =============================================================================
# ENUMS - Evidence Sources and Types
# =============================================================================


class EvidenceSource(str, Enum):
    """Source from which evidence was obtained and can be verified."""

    GITHUB_API = "github_api"  # GitHub REST/GraphQL API
    GITHUB_WEB = "github_web"  # GitHub web interface (commit pages, etc.)
    GHARCHIVE = "gharchive"  # GH Archive via BigQuery
    WAYBACK = "wayback"  # Internet Archive Wayback Machine
    GIT_LOCAL = "git_local"  # Local git repository operations


class EventType(str, Enum):
    """GitHub event types as recorded in GH Archive."""

    PUSH = "PushEvent"
    PULL_REQUEST = "PullRequestEvent"
    PULL_REQUEST_REVIEW = "PullRequestReviewEvent"
    PULL_REQUEST_REVIEW_COMMENT = "PullRequestReviewCommentEvent"
    ISSUES = "IssuesEvent"
    ISSUE_COMMENT = "IssueCommentEvent"
    CREATE = "CreateEvent"
    DELETE = "DeleteEvent"
    FORK = "ForkEvent"
    WATCH = "WatchEvent"
    RELEASE = "ReleaseEvent"
    MEMBER = "MemberEvent"
    PUBLIC = "PublicEvent"
    WORKFLOW_RUN = "WorkflowRunEvent"
    WORKFLOW_JOB = "WorkflowJobEvent"
    CHECK_RUN = "CheckRunEvent"
    CHECK_SUITE = "CheckSuiteEvent"


class RefType(str, Enum):
    """Git reference types for create/delete events."""

    BRANCH = "branch"
    TAG = "tag"
    REPOSITORY = "repository"


class PRAction(str, Enum):
    """Pull request actions."""

    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    EDITED = "edited"
    ASSIGNED = "assigned"
    UNASSIGNED = "unassigned"
    LABELED = "labeled"
    UNLABELED = "unlabeled"
    SYNCHRONIZE = "synchronize"
    REVIEW_REQUESTED = "review_requested"


class IssueAction(str, Enum):
    """Issue actions."""

    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    EDITED = "edited"
    ASSIGNED = "assigned"
    UNASSIGNED = "unassigned"
    LABELED = "labeled"
    UNLABELED = "unlabeled"
    TRANSFERRED = "transferred"
    DELETED = "deleted"


class WorkflowConclusion(str, Enum):
    """Workflow run conclusions."""

    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    ACTION_REQUIRED = "action_required"
    NEUTRAL = "neutral"
    STALE = "stale"


# =============================================================================
# BASE MODELS - Common Fields
# =============================================================================


class VerificationInfo(BaseModel):
    """Information required to independently verify evidence."""

    source: EvidenceSource = Field(
        ..., description="Primary source for verification"
    )
    verified_at: datetime | None = Field(
        default=None, description="When this evidence was verified"
    )
    verification_url: HttpUrl | None = Field(
        default=None, description="Direct URL to verify this evidence"
    )
    bigquery_table: str | None = Field(
        default=None,
        description="BigQuery table for GH Archive verification (e.g., githubarchive.day.20250713)",
    )
    verification_query: str | None = Field(
        default=None, description="SQL query to reproduce GH Archive evidence"
    )


class GitHubActor(BaseModel):
    """GitHub user/actor information."""

    login: str = Field(..., description="GitHub username")
    id: int | None = Field(default=None, description="GitHub user ID (stable)")
    avatar_url: HttpUrl | None = Field(default=None, description="Avatar URL")
    is_bot: bool = Field(
        default=False, description="Whether this is a bot/automation account"
    )


class GitHubRepository(BaseModel):
    """GitHub repository reference."""

    owner: str = Field(..., description="Repository owner (user or org)")
    name: str = Field(..., description="Repository name")
    full_name: str = Field(..., description="Full name (owner/name)")
    id: int | None = Field(default=None, description="GitHub repository ID")
    is_fork: bool = Field(default=False, description="Whether this is a fork")
    parent_full_name: str | None = Field(
        default=None, description="Parent repo if this is a fork"
    )


class EvidenceBase(BaseModel):
    """Base class for all verifiable evidence."""

    evidence_id: str = Field(
        ..., description="Unique identifier for this evidence piece"
    )
    observed_at: datetime = Field(
        ..., description="When this event/evidence was observed (UTC)"
    )
    verification: VerificationInfo = Field(
        ..., description="How to verify this evidence"
    )
    notes: str | None = Field(
        default=None, description="Investigator notes on this evidence"
    )


# =============================================================================
# COMMIT EVIDENCE - Verifiable via GitHub API, Web, or Git
# =============================================================================


class CommitAuthor(BaseModel):
    """Git commit author/committer information."""

    name: str = Field(..., description="Name from git commit")
    email: str = Field(..., description="Email from git commit")
    date: datetime = Field(..., description="Author/commit date (UTC)")


class CommitSignature(BaseModel):
    """GPG/SSH signature verification details."""

    verified: bool = Field(..., description="Whether signature is valid")
    reason: str | None = Field(
        default=None, description="Verification reason/status"
    )
    signature: str | None = Field(default=None, description="Raw signature")
    payload: str | None = Field(default=None, description="Signed payload")


class CommitFileChange(BaseModel):
    """File changed in a commit."""

    filename: str = Field(..., description="Path to file")
    status: Literal["added", "modified", "removed", "renamed", "copied"] = Field(
        ..., description="Change type"
    )
    additions: int = Field(default=0, description="Lines added")
    deletions: int = Field(default=0, description="Lines deleted")
    patch: str | None = Field(
        default=None, description="Unified diff patch for this file"
    )
    previous_filename: str | None = Field(
        default=None, description="Previous filename if renamed"
    )


class CommitEvidence(EvidenceBase):
    """
    Evidence of a specific git commit.

    Verifiable via:
    - GitHub API: GET /repos/{owner}/{repo}/commits/{sha}
    - GitHub Web: https://github.com/{owner}/{repo}/commit/{sha}
    - GitHub Patch: https://github.com/{owner}/{repo}/commit/{sha}.patch
    - Git: git show {sha}
    """

    evidence_type: Literal["commit"] = "commit"
    repository: GitHubRepository = Field(..., description="Repository containing commit")
    sha: Annotated[str, Field(min_length=40, max_length=40)] = Field(
        ..., description="Full 40-character commit SHA"
    )
    short_sha: Annotated[str, Field(min_length=7, max_length=8)] = Field(
        ..., description="Short SHA (7-8 chars)"
    )
    message: str = Field(..., description="Full commit message")
    author: CommitAuthor = Field(..., description="Git author")
    committer: CommitAuthor = Field(..., description="Git committer")
    signature: CommitSignature | None = Field(
        default=None, description="Signature verification if signed"
    )
    parents: list[str] = Field(
        default_factory=list, description="Parent commit SHAs"
    )
    files: list[CommitFileChange] = Field(
        default_factory=list, description="Files changed in this commit"
    )
    is_merge: bool = Field(
        default=False, description="Whether this is a merge commit"
    )
    is_dangling: bool = Field(
        default=False,
        description="Whether commit is dangling (not on any branch)",
    )
    was_force_pushed: bool = Field(
        default=False,
        description="Whether this commit was force-pushed over (recovered)",
    )


class DeletedCommitEvidence(EvidenceBase):
    """
    Evidence of a commit that was force-pushed over ("deleted").

    Recovered via GH Archive zero-commit PushEvent pattern.
    The commit SHA remains accessible on GitHub despite not being
    on any branch.
    """

    evidence_type: Literal["deleted_commit"] = "deleted_commit"
    repository: GitHubRepository = Field(..., description="Repository")
    deleted_sha: Annotated[str, Field(min_length=40, max_length=40)] = Field(
        ..., description="SHA of the deleted/overwritten commit"
    )
    replaced_by_sha: Annotated[str, Field(min_length=40, max_length=40)] = Field(
        ..., description="SHA that replaced this commit (new HEAD)"
    )
    branch: str = Field(..., description="Branch that was force-pushed")
    pusher: GitHubActor = Field(..., description="Who performed the force push")
    force_push_time: datetime = Field(
        ..., description="When the force push occurred (UTC)"
    )
    commit_recovered: bool = Field(
        default=False, description="Whether full commit content was recovered"
    )
    recovered_commit: CommitEvidence | None = Field(
        default=None, description="Recovered commit if available"
    )


# =============================================================================
# GITHUB ARCHIVE EVENTS - Verifiable via BigQuery
# =============================================================================


class PushEventCommit(BaseModel):
    """Individual commit within a PushEvent."""

    sha: str = Field(..., description="Commit SHA")
    message: str = Field(..., description="Commit message")
    author_name: str = Field(..., description="Author name")
    author_email: str = Field(..., description="Author email")
    distinct: bool = Field(
        default=True, description="Whether commit is distinct to this push"
    )


class PushEventEvidence(EvidenceBase):
    """
    Evidence from a PushEvent in GH Archive.

    Verifiable via BigQuery:
    SELECT * FROM `githubarchive.day.YYYYMMDD`
    WHERE type = 'PushEvent' AND repo.name = '{repo}'
    """

    evidence_type: Literal["push_event"] = "push_event"
    repository: GitHubRepository = Field(..., description="Target repository")
    actor: GitHubActor = Field(..., description="Who pushed")
    ref: str = Field(
        ..., description="Git ref (e.g., refs/heads/main)"
    )
    before_sha: str = Field(
        ..., description="SHA before push (use for force-push detection)"
    )
    after_sha: str = Field(..., description="SHA after push (new HEAD)")
    size: int = Field(..., description="Number of commits in push")
    commits: list[PushEventCommit] = Field(
        default_factory=list, description="Commits in this push"
    )
    is_force_push: bool = Field(
        default=False,
        description="Whether this was a force push (size=0 or history rewrite)",
    )


class PullRequestEvidence(EvidenceBase):
    """
    Evidence from a PullRequestEvent in GH Archive.

    Recovers deleted PRs including title, body, and merge status.
    """

    evidence_type: Literal["pull_request_event"] = "pull_request_event"
    repository: GitHubRepository = Field(..., description="Target repository")
    actor: GitHubActor = Field(..., description="Who performed the action")
    action: PRAction = Field(..., description="PR action")
    pr_number: int = Field(..., description="Pull request number")
    pr_title: str = Field(..., description="PR title")
    pr_body: str | None = Field(default=None, description="PR body/description")
    head_sha: str | None = Field(default=None, description="Head commit SHA")
    base_sha: str | None = Field(default=None, description="Base commit SHA")
    head_ref: str | None = Field(default=None, description="Head branch name")
    base_ref: str | None = Field(default=None, description="Base branch name")
    merged: bool = Field(default=False, description="Whether PR was merged")
    merged_by: GitHubActor | None = Field(
        default=None, description="Who merged the PR"
    )
    merge_commit_sha: str | None = Field(
        default=None, description="Merge commit SHA if merged"
    )
    is_deleted: bool = Field(
        default=False,
        description="Whether PR is deleted from GitHub (recovered from archive)",
    )


class IssueEvidence(EvidenceBase):
    """
    Evidence from an IssuesEvent in GH Archive.

    Recovers deleted issues including title and body text.
    """

    evidence_type: Literal["issue_event"] = "issue_event"
    repository: GitHubRepository = Field(..., description="Target repository")
    actor: GitHubActor = Field(..., description="Who performed the action")
    action: IssueAction = Field(..., description="Issue action")
    issue_number: int = Field(..., description="Issue number")
    issue_title: str = Field(..., description="Issue title")
    issue_body: str | None = Field(default=None, description="Issue body text")
    labels: list[str] = Field(default_factory=list, description="Issue labels")
    is_deleted: bool = Field(
        default=False,
        description="Whether issue is deleted from GitHub (recovered from archive)",
    )


class IssueCommentEvidence(EvidenceBase):
    """
    Evidence from an IssueCommentEvent in GH Archive.

    Preserves comment text even if deleted from GitHub.
    """

    evidence_type: Literal["issue_comment_event"] = "issue_comment_event"
    repository: GitHubRepository = Field(..., description="Target repository")
    actor: GitHubActor = Field(..., description="Comment author")
    action: Literal["created", "edited", "deleted"] = Field(
        ..., description="Comment action"
    )
    issue_number: int = Field(..., description="Parent issue/PR number")
    comment_id: int = Field(..., description="Comment ID")
    comment_body: str = Field(..., description="Comment text")
    is_on_pull_request: bool = Field(
        default=False, description="Whether comment is on a PR vs issue"
    )


class CreateDeleteEventEvidence(EvidenceBase):
    """
    Evidence from CreateEvent or DeleteEvent in GH Archive.

    Records branch/tag creation and deletion.
    """

    evidence_type: Literal["create_delete_event"] = "create_delete_event"
    repository: GitHubRepository = Field(..., description="Target repository")
    actor: GitHubActor = Field(..., description="Who created/deleted")
    event_action: Literal["create", "delete"] = Field(
        ..., description="Whether this was create or delete"
    )
    ref_type: RefType = Field(
        ..., description="Type of ref (branch, tag, repository)"
    )
    ref_name: str = Field(..., description="Name of the branch/tag")
    default_branch: str | None = Field(
        default=None, description="Default branch (for repository creation)"
    )


class ForkEventEvidence(EvidenceBase):
    """
    Evidence from a ForkEvent in GH Archive.

    Records fork relationships even after parent/fork deletion.
    """

    evidence_type: Literal["fork_event"] = "fork_event"
    source_repository: GitHubRepository = Field(
        ..., description="Repository that was forked"
    )
    fork_repository: GitHubRepository = Field(
        ..., description="Newly created fork"
    )
    actor: GitHubActor = Field(..., description="Who created the fork")


class WorkflowRunEvidence(EvidenceBase):
    """
    Evidence from WorkflowRunEvent in GH Archive.

    Critical for distinguishing legitimate workflow execution
    from direct API abuse with stolen tokens.
    """

    evidence_type: Literal["workflow_run_event"] = "workflow_run_event"
    repository: GitHubRepository = Field(..., description="Target repository")
    actor: GitHubActor = Field(..., description="Triggering actor")
    action: Literal["requested", "completed", "in_progress"] = Field(
        ..., description="Workflow run action"
    )
    workflow_name: str = Field(..., description="Workflow name")
    workflow_path: str | None = Field(
        default=None, description="Path to workflow file (.github/workflows/...)"
    )
    head_sha: str = Field(..., description="Commit SHA being processed")
    head_branch: str | None = Field(default=None, description="Branch name")
    conclusion: WorkflowConclusion | None = Field(
        default=None, description="Run conclusion (for completed events)"
    )
    run_id: int | None = Field(default=None, description="Workflow run ID")


class ReleaseEvidence(EvidenceBase):
    """
    Evidence from a ReleaseEvent in GH Archive.

    Records release publication including tag and body.
    """

    evidence_type: Literal["release_event"] = "release_event"
    repository: GitHubRepository = Field(..., description="Target repository")
    actor: GitHubActor = Field(..., description="Who created the release")
    action: Literal["published", "created", "edited", "deleted", "prereleased", "released"] = Field(
        ..., description="Release action"
    )
    tag_name: str = Field(..., description="Release tag name")
    release_name: str | None = Field(default=None, description="Release title")
    release_body: str | None = Field(
        default=None, description="Release description/notes"
    )
    prerelease: bool = Field(default=False, description="Whether prerelease")
    draft: bool = Field(default=False, description="Whether draft")
    target_commitish: str | None = Field(
        default=None, description="Target branch/commit"
    )


class WatchEvidence(EvidenceBase):
    """
    Evidence from a WatchEvent (star) in GH Archive.

    Can indicate reconnaissance activity.
    """

    evidence_type: Literal["watch_event"] = "watch_event"
    repository: GitHubRepository = Field(..., description="Starred repository")
    actor: GitHubActor = Field(..., description="Who starred")
    action: Literal["started"] = Field(default="started", description="Watch action")


class MemberEvidence(EvidenceBase):
    """
    Evidence from a MemberEvent in GH Archive.

    Records collaborator additions/removals.
    """

    evidence_type: Literal["member_event"] = "member_event"
    repository: GitHubRepository = Field(..., description="Target repository")
    actor: GitHubActor = Field(..., description="Who made the change")
    action: Literal["added", "removed", "edited"] = Field(
        ..., description="Member action"
    )
    member: GitHubActor = Field(..., description="Affected member")
    permission: str | None = Field(
        default=None, description="Permission level granted"
    )


# =============================================================================
# WAYBACK MACHINE EVIDENCE - Verifiable via Archive.org
# =============================================================================


class WaybackSnapshot(BaseModel):
    """A single Wayback Machine snapshot."""

    timestamp: str = Field(
        ..., description="Archive timestamp (YYYYMMDDHHMMSS)"
    )
    original_url: HttpUrl = Field(..., description="Original URL that was archived")
    archive_url: HttpUrl = Field(
        ..., description="Full archive.org URL to access snapshot"
    )
    status_code: int = Field(..., description="HTTP status code at capture time")
    mime_type: str | None = Field(default=None, description="Content MIME type")
    digest: str | None = Field(default=None, description="Content digest")


class WaybackEvidence(EvidenceBase):
    """
    Evidence from Internet Archive Wayback Machine.

    Verifiable via CDX API:
    https://web.archive.org/cdx/search/cdx?url={url}&output=json
    """

    evidence_type: Literal["wayback_snapshot"] = "wayback_snapshot"
    repository: GitHubRepository | None = Field(
        default=None, description="Associated repository if applicable"
    )
    content_type: Literal[
        "repository_homepage",
        "issue",
        "pull_request",
        "wiki",
        "file_blob",
        "directory_tree",
        "commits_list",
        "release",
        "network_members",
        "user_profile",
        "other",
    ] = Field(..., description="Type of GitHub content archived")
    snapshots: list[WaybackSnapshot] = Field(
        ..., description="Available snapshots (may have multiple timestamps)"
    )
    latest_snapshot: WaybackSnapshot = Field(
        ..., description="Most recent snapshot"
    )
    earliest_snapshot: WaybackSnapshot = Field(
        ..., description="Earliest snapshot"
    )
    total_snapshots: int = Field(..., description="Total number of snapshots")
    content_recovered: bool = Field(
        default=False, description="Whether actual content was extracted"
    )


class RecoveredIssueContent(EvidenceBase):
    """
    Issue/PR content recovered from Wayback Machine.

    Use when GH Archive doesn't have the body text.
    """

    evidence_type: Literal["recovered_issue_content"] = "recovered_issue_content"
    repository: GitHubRepository = Field(..., description="Repository")
    issue_number: int = Field(..., description="Issue/PR number")
    is_pull_request: bool = Field(
        default=False, description="Whether this is a PR vs issue"
    )
    title: str | None = Field(default=None, description="Recovered title")
    body: str | None = Field(default=None, description="Recovered body text")
    author_login: str | None = Field(default=None, description="Author username")
    comments: list[str] = Field(
        default_factory=list, description="Recovered comment texts"
    )
    labels: list[str] = Field(default_factory=list, description="Labels")
    state: Literal["open", "closed", "merged", "unknown"] | None = Field(
        default=None, description="Issue/PR state at snapshot time"
    )
    source_snapshot: WaybackSnapshot = Field(
        ..., description="Wayback snapshot used for recovery"
    )


class RecoveredFileContent(EvidenceBase):
    """
    File content recovered from Wayback Machine.

    Use when repository is deleted but files were archived.
    """

    evidence_type: Literal["recovered_file_content"] = "recovered_file_content"
    repository: GitHubRepository = Field(..., description="Repository")
    file_path: str = Field(..., description="Path to file in repository")
    branch: str | None = Field(default=None, description="Branch name if known")
    content: str = Field(..., description="Recovered file content")
    content_hash: str | None = Field(
        default=None, description="SHA256 hash of content"
    )
    source_snapshot: WaybackSnapshot = Field(
        ..., description="Wayback snapshot used for recovery"
    )


class RecoveredWikiContent(EvidenceBase):
    """
    Wiki page content recovered from Wayback Machine.
    """

    evidence_type: Literal["recovered_wiki_content"] = "recovered_wiki_content"
    repository: GitHubRepository = Field(..., description="Repository")
    page_name: str = Field(..., description="Wiki page name")
    content: str = Field(..., description="Recovered wiki content")
    source_snapshot: WaybackSnapshot = Field(
        ..., description="Wayback snapshot used for recovery"
    )


class RecoveredForkList(EvidenceBase):
    """
    Fork list recovered from archived network/members page.

    Useful for finding surviving forks of deleted repositories.
    """

    evidence_type: Literal["recovered_fork_list"] = "recovered_fork_list"
    repository: GitHubRepository = Field(
        ..., description="Parent repository (possibly deleted)"
    )
    forks: list[str] = Field(
        ..., description="Fork full names (owner/repo)"
    )
    forks_verified_existing: list[str] = Field(
        default_factory=list,
        description="Forks confirmed to still exist on GitHub",
    )
    source_snapshot: WaybackSnapshot = Field(
        ..., description="Wayback snapshot used for recovery"
    )


# =============================================================================
# TIMELINE & INVESTIGATION CONTAINERS
# =============================================================================


# Type alias for any evidence type
AnyEvidence = (
    CommitEvidence
    | DeletedCommitEvidence
    | PushEventEvidence
    | PullRequestEvidence
    | IssueEvidence
    | IssueCommentEvidence
    | CreateDeleteEventEvidence
    | ForkEventEvidence
    | WorkflowRunEvidence
    | ReleaseEvidence
    | WatchEvidence
    | MemberEvidence
    | WaybackEvidence
    | RecoveredIssueContent
    | RecoveredFileContent
    | RecoveredWikiContent
    | RecoveredForkList
)


class TimelineEntry(BaseModel):
    """
    A single entry in an investigation timeline.

    Links evidence to temporal sequence with analysis notes.
    """

    timestamp: datetime = Field(..., description="When this event occurred (UTC)")
    evidence: AnyEvidence = Field(..., description="The evidence for this entry")
    significance: Literal["critical", "high", "medium", "low", "info"] = Field(
        default="info", description="Importance to investigation"
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags for categorization (e.g., 'initial_access', 'exfil')",
    )
    analysis_notes: str | None = Field(
        default=None, description="Investigator analysis"
    )
    related_evidence_ids: list[str] = Field(
        default_factory=list, description="IDs of related evidence pieces"
    )


class ActorProfile(BaseModel):
    """
    Profile of an actor (user/bot) involved in an investigation.

    Aggregates all evidence related to a specific GitHub account.
    """

    actor: GitHubActor = Field(..., description="The GitHub actor")
    first_seen: datetime = Field(
        ..., description="Earliest observed activity (UTC)"
    )
    last_seen: datetime = Field(
        ..., description="Most recent observed activity (UTC)"
    )
    repositories_touched: list[str] = Field(
        default_factory=list, description="Repositories this actor interacted with"
    )
    event_count: int = Field(default=0, description="Total events attributed")
    event_types: list[EventType] = Field(
        default_factory=list, description="Types of events performed"
    )
    is_automation: bool = Field(
        default=False, description="Whether this appears to be an automation account"
    )
    account_created: datetime | None = Field(
        default=None, description="Account creation date if known"
    )
    account_deleted: bool = Field(
        default=False, description="Whether account is now deleted"
    )
    evidence_ids: list[str] = Field(
        default_factory=list, description="IDs of evidence pieces involving this actor"
    )
    notes: str | None = Field(default=None, description="Investigator notes")


class IOC(BaseModel):
    """
    Indicator of Compromise extracted from evidence.

    Only include IOCs that are verifiable from the evidence.
    """

    ioc_type: Literal[
        "commit_sha",
        "file_path",
        "email",
        "username",
        "ip_address",
        "domain",
        "api_key_pattern",
        "secret_pattern",
        "repository",
        "tag_name",
        "branch_name",
        "workflow_name",
        "other",
    ] = Field(..., description="Type of IOC")
    value: str = Field(..., description="The IOC value")
    context: str = Field(
        ..., description="Context where this IOC was found"
    )
    evidence_id: str = Field(
        ..., description="ID of evidence containing this IOC"
    )
    confidence: Literal["confirmed", "high", "medium", "low"] = Field(
        default="medium", description="Confidence in this IOC"
    )
    first_seen: datetime | None = Field(
        default=None, description="First observation time"
    )
    last_seen: datetime | None = Field(
        default=None, description="Last observation time"
    )


class Investigation(BaseModel):
    """
    Container for a complete GitHub forensics investigation.

    Aggregates all evidence, timeline, actors, and IOCs.
    """

    investigation_id: str = Field(..., description="Unique investigation identifier")
    title: str = Field(..., description="Investigation title")
    description: str = Field(..., description="Investigation summary")
    created_at: datetime = Field(..., description="When investigation started")
    updated_at: datetime = Field(..., description="Last update time")
    status: Literal["active", "completed", "archived"] = Field(
        default="active", description="Investigation status"
    )

    # Target scope
    target_repositories: list[GitHubRepository] = Field(
        default_factory=list, description="Repositories under investigation"
    )
    target_actors: list[str] = Field(
        default_factory=list, description="Actor usernames of interest"
    )
    time_range_start: datetime | None = Field(
        default=None, description="Investigation start time boundary"
    )
    time_range_end: datetime | None = Field(
        default=None, description="Investigation end time boundary"
    )

    # Evidence collection
    evidence: list[AnyEvidence] = Field(
        default_factory=list, description="All collected evidence"
    )
    timeline: list[TimelineEntry] = Field(
        default_factory=list, description="Ordered timeline of events"
    )
    actors: list[ActorProfile] = Field(
        default_factory=list, description="Profiles of involved actors"
    )
    iocs: list[IOC] = Field(
        default_factory=list, description="Extracted IOCs"
    )

    # Analysis
    findings: str | None = Field(
        default=None, description="Investigation findings summary"
    )
    recommendations: list[str] = Field(
        default_factory=list, description="Recommended actions"
    )

    # Verification metadata
    bigquery_queries_used: list[str] = Field(
        default_factory=list, description="GH Archive queries executed"
    )
    wayback_urls_checked: list[str] = Field(
        default_factory=list, description="Wayback URLs queried"
    )
    github_api_calls: int = Field(
        default=0, description="Number of GitHub API calls made"
    )
