use folderbase_core::{
    ConflictClassification, ContentKind, MemorySyncCloud, SyncEvent, SyncReplica, SyncVersion,
};
use sha2::{Digest, Sha256};

#[test]
fn three_logical_devices_converge_without_a_device_authority() {
    let mut cloud = MemorySyncCloud::new();
    let mut personal = SyncReplica::new("personal-macbook");
    let mut work = SyncReplica::new("work-macbook");
    let mut mini = SyncReplica::new("mac-mini");

    personal
        .write(
            "FOLDERBASE.md",
            b"version one\n".to_vec(),
            ContentKind::Text,
        )
        .unwrap();
    personal.sync(&mut cloud).unwrap();
    work.sync(&mut cloud).unwrap();
    mini.sync(&mut cloud).unwrap();

    work.write(
        "Decisions/001.md",
        b"use ordinary files\n".to_vec(),
        ContentKind::Text,
    )
    .unwrap();
    work.sync(&mut cloud).unwrap();
    personal.sync(&mut cloud).unwrap();
    mini.sync(&mut cloud).unwrap();

    assert_eq!(
        personal.read("Decisions/001.md"),
        Some(b"use ordinary files\n".as_slice())
    );
    assert_eq!(
        mini.read("Decisions/001.md"),
        Some(b"use ordinary files\n".as_slice())
    );
}

#[test]
fn offline_text_conflict_preserves_both_versions() {
    let mut cloud = MemorySyncCloud::new();
    let mut left = SyncReplica::new("left");
    let mut right = SyncReplica::new("right");

    left.write("Plan.md", b"base\n".to_vec(), ContentKind::Text)
        .unwrap();
    left.sync(&mut cloud).unwrap();
    right.sync(&mut cloud).unwrap();

    left.write("Plan.md", b"left edit\n".to_vec(), ContentKind::Text)
        .unwrap();
    right
        .write("Plan.md", b"right edit\n".to_vec(), ContentKind::Text)
        .unwrap();
    left.sync(&mut cloud).unwrap();
    let report = right.sync(&mut cloud).unwrap();

    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(
        report.conflicts[0].classification,
        ConflictClassification::TextNeedsMerge
    );
    assert_eq!(
        cloud
            .materialize(&report.conflicts[0].local.digest)
            .unwrap(),
        b"right edit\n"
    );
    assert_eq!(
        cloud
            .materialize(&report.conflicts[0].remote.digest)
            .unwrap(),
        b"left edit\n"
    );
    assert_eq!(right.read("Plan.md"), Some(b"right edit\n".as_slice()));
}

#[test]
fn binary_conflict_is_never_silently_discarded() {
    let mut cloud = MemorySyncCloud::new();
    let mut left = SyncReplica::new("left");
    let mut right = SyncReplica::new("right");

    left.write("video.mov", vec![0, 1, 2], ContentKind::Binary)
        .unwrap();
    left.sync(&mut cloud).unwrap();
    right.sync(&mut cloud).unwrap();
    left.write("video.mov", vec![3, 4, 5], ContentKind::Binary)
        .unwrap();
    right
        .write("video.mov", vec![6, 7, 8], ContentKind::Binary)
        .unwrap();

    left.sync(&mut cloud).unwrap();
    let report = right.sync(&mut cloud).unwrap();
    assert_eq!(
        report.conflicts[0].classification,
        ConflictClassification::PreserveBothBinary
    );
    assert_eq!(cloud.conflicts().len(), 1);
}

#[test]
fn duplicate_and_reordered_events_are_idempotent() {
    let mut cloud = MemorySyncCloud::new();
    let mut author = SyncReplica::new("author");
    let mut follower = SyncReplica::new("follower");

    author
        .write("one.md", b"one\n".to_vec(), ContentKind::Text)
        .unwrap();
    author.sync(&mut cloud).unwrap();
    author
        .write("two.md", b"two\n".to_vec(), ContentKind::Text)
        .unwrap();
    author.sync(&mut cloud).unwrap();

    let events = cloud.events().to_vec();
    assert!(follower.apply_event(&cloud, &events[1]).unwrap());
    assert!(follower.apply_event(&cloud, &events[0]).unwrap());
    assert!(!follower.apply_event(&cloud, &events[0]).unwrap());
    assert_eq!(follower.read("one.md"), Some(b"one\n".as_slice()));
    assert_eq!(follower.read("two.md"), Some(b"two\n".as_slice()));
}

#[test]
fn dirty_local_content_is_not_replaced_by_an_event() {
    let mut cloud = MemorySyncCloud::new();
    let mut author = SyncReplica::new("author");
    let mut follower = SyncReplica::new("follower");

    author
        .write("FOLDERBASE.md", b"base\n".to_vec(), ContentKind::Text)
        .unwrap();
    author.sync(&mut cloud).unwrap();
    follower.sync(&mut cloud).unwrap();
    follower
        .write("FOLDERBASE.md", b"dirty\n".to_vec(), ContentKind::Text)
        .unwrap();

    author
        .write("FOLDERBASE.md", b"remote\n".to_vec(), ContentKind::Text)
        .unwrap();
    author.sync(&mut cloud).unwrap();
    let event = cloud.events().last().unwrap().clone();

    assert!(!follower.apply_event(&cloud, &event).unwrap());
    assert_eq!(follower.read("FOLDERBASE.md"), Some(b"dirty\n".as_slice()));
    assert_eq!(follower.sync(&mut cloud).unwrap().conflicts.len(), 1);
}

#[test]
fn reverse_order_same_path_events_never_regress_content() {
    let mut cloud = MemorySyncCloud::new();
    let mut author = SyncReplica::new("author");
    let mut follower = SyncReplica::new("follower");

    author
        .write("FOLDERBASE.md", b"older\n".to_vec(), ContentKind::Text)
        .unwrap();
    author.sync(&mut cloud).unwrap();
    author
        .write("FOLDERBASE.md", b"newer\n".to_vec(), ContentKind::Text)
        .unwrap();
    author.sync(&mut cloud).unwrap();
    let events = cloud.events().to_vec();

    assert!(follower.apply_event(&cloud, &events[1]).unwrap());
    assert!(!follower.apply_event(&cloud, &events[0]).unwrap());
    assert_eq!(follower.read("FOLDERBASE.md"), Some(b"newer\n".as_slice()));
}

#[test]
fn failed_materialization_can_be_retried_after_blob_arrives() {
    let mut cloud = MemorySyncCloud::new();
    let mut follower = SyncReplica::new("follower");
    let bytes = b"arrives later\n";
    let digest = format!("{:x}", Sha256::digest(bytes));
    let event = SyncEvent {
        id: "event_retry".to_owned(),
        path: "Later.md".into(),
        version: SyncVersion {
            digest: digest.clone(),
            bytes: bytes.len() as u64,
            kind: ContentKind::Text,
            author_device: "author".to_owned(),
            sequence: 1,
        },
    };

    assert!(follower.apply_event(&cloud, &event).is_err());
    assert_eq!(cloud.store_blob(bytes), digest);
    assert!(follower.apply_event(&cloud, &event).unwrap());
    assert_eq!(follower.read("Later.md"), Some(bytes.as_slice()));
}
