use std::{collections::BTreeSet, fs, path::Path};

fn collect_rust_files(path: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(path).expect("read workspace directory") {
        let entry = entry.expect("read workspace entry");
        let path = entry.path();
        if path.file_name().is_some_and(|name| {
            name == "target" || name == ".git" || name == "examples" || name == "tests"
        }) {
            continue;
        }
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn raw_nats_authority_has_an_exact_lexical_inventory() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().expect("workspace root");
    let mut files = Vec::new();
    collect_rust_files(workspace, &mut files);

    let raw_dependency = concat!("async_", "nats::");
    let raw_context = concat!("jetstream", "::Context");
    let raw_send = concat!("send_", "publish(");
    let direct_publish = concat!(".jetstream", ".publish(");
    let mut dependency_files = BTreeSet::new();
    let mut context_files = BTreeSet::new();
    let mut send_files = BTreeSet::new();
    let mut direct_publish_files = BTreeSet::new();

    for file in files {
        let relative = file.strip_prefix(workspace).unwrap();
        let relative = relative.to_string_lossy().replace('\\', "/");
        let source = fs::read_to_string(&file).expect("read Rust source");
        if source.contains(raw_dependency) {
            dependency_files.insert(relative.clone());
        }
        if source.contains(raw_context) {
            context_files.insert(relative.clone());
        }
        if source.contains(raw_send) {
            send_files.insert(relative.clone());
        }
        if source.contains(direct_publish) {
            direct_publish_files.insert(relative);
        }
    }

    let expected_dependency_files = BTreeSet::from([
        "psy_node_nats/src/psy_queue.rs".to_owned(),
        "psy_node_nats/src/queue.rs".to_owned(),
        "psy_node_nats/src/recoverable_assignment.rs".to_owned(),
        "psy_node_nats/src/recoverable_segment.rs".to_owned(),
        "psy_node_nats/src/recoverable_transport.rs".to_owned(),
        "psy_cli/psy_dev_cli/src/subcommand/nats_inspect.rs".to_owned(),
    ]);
    assert_eq!(dependency_files, expected_dependency_files);
    assert_eq!(
        context_files,
        BTreeSet::from([
            "psy_node_nats/src/queue.rs".to_owned(),
            "psy_node_nats/src/recoverable_transport.rs".to_owned(),
        ])
    );
    assert_eq!(
        send_files,
        BTreeSet::from([
            "psy_node_nats/src/recoverable_segment.rs".to_owned(),
            "psy_node_nats/src/recoverable_transport.rs".to_owned(),
        ])
    );
    assert_eq!(
        direct_publish_files,
        BTreeSet::from(["psy_node_nats/src/queue.rs".to_owned()])
    );
}

#[test]
fn raw_client_fields_and_arbitrary_subject_helpers_are_not_public() {
    let queue = include_str!("../src/queue.rs");
    assert!(!queue.contains(concat!("pub jet", "stream:")));
    assert!(!queue.contains(concat!("pub async fn push_", "message")));
    assert!(!queue.contains(concat!("pub async fn push_", "messages")));

    let scylla = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("psy_node_scylla/src");
    let mut files = Vec::new();
    collect_rust_files(&scylla, &mut files);
    for file in files {
        let source = fs::read_to_string(&file).expect("read Scylla source");
        assert!(!source.contains(concat!("async_", "nats::")), "{}", file.display());
        assert!(!source.contains(concat!("jetstream", "::Context")), "{}", file.display());
        assert!(!source.contains(concat!("send_", "publish(")), "{}", file.display());
    }
}
