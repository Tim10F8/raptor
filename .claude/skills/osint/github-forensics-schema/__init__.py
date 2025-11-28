"""
GitHub Forensics Verifiable Evidence Schema

Pydantic models for verifiable GitHub forensic evidence.
All evidence types can be independently verified through:
- GitHub API
- GH Archive (BigQuery)
- Wayback Machine
- Git
"""

from .schema import (
    # Enums
    EvidenceSource,
    EventType,
    RefType,
    PRAction,
    IssueAction,
    WorkflowConclusion,
    # Base types
    VerificationInfo,
    GitHubActor,
    GitHubRepository,
    EvidenceBase,
    # Commit evidence
    CommitAuthor,
    CommitSignature,
    CommitFileChange,
    CommitEvidence,
    DeletedCommitEvidence,
    # GH Archive events
    PushEventCommit,
    PushEventEvidence,
    PullRequestEvidence,
    IssueEvidence,
    IssueCommentEvidence,
    CreateDeleteEventEvidence,
    ForkEventEvidence,
    WorkflowRunEvidence,
    ReleaseEvidence,
    WatchEvidence,
    MemberEvidence,
    # Wayback evidence
    WaybackSnapshot,
    WaybackEvidence,
    RecoveredIssueContent,
    RecoveredFileContent,
    RecoveredWikiContent,
    RecoveredForkList,
    # Investigation containers
    TimelineEntry,
    ActorProfile,
    IOC,
    Investigation,
    # Type alias
    AnyEvidence,
)

__all__ = [
    # Enums
    "EvidenceSource",
    "EventType",
    "RefType",
    "PRAction",
    "IssueAction",
    "WorkflowConclusion",
    # Base types
    "VerificationInfo",
    "GitHubActor",
    "GitHubRepository",
    "EvidenceBase",
    # Commit evidence
    "CommitAuthor",
    "CommitSignature",
    "CommitFileChange",
    "CommitEvidence",
    "DeletedCommitEvidence",
    # GH Archive events
    "PushEventCommit",
    "PushEventEvidence",
    "PullRequestEvidence",
    "IssueEvidence",
    "IssueCommentEvidence",
    "CreateDeleteEventEvidence",
    "ForkEventEvidence",
    "WorkflowRunEvidence",
    "ReleaseEvidence",
    "WatchEvidence",
    "MemberEvidence",
    # Wayback evidence
    "WaybackSnapshot",
    "WaybackEvidence",
    "RecoveredIssueContent",
    "RecoveredFileContent",
    "RecoveredWikiContent",
    "RecoveredForkList",
    # Investigation containers
    "TimelineEntry",
    "ActorProfile",
    "IOC",
    "Investigation",
    # Type alias
    "AnyEvidence",
]
