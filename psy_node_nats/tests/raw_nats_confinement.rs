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
    let raw_update = concat!(".update_", "stream(");
    let raw_delete = concat!(".delete_", "stream(");
    let raw_consumer_create = concat!(".create_", "consumer_strict(");
    let typed_consumer_provision = concat!(".provision_", "recoverable_capture_consumer(");
    let typed_consumer_open = concat!(".open_", "existing_recoverable_capture(");
    let durable_binding_constructor = concat!(
        "RecoverableNatsExistingConsumerBinding::",
        "try_from_durable("
    );
    let mut dependency_files = BTreeSet::new();
    let mut context_files = BTreeSet::new();
    let mut send_files = BTreeSet::new();
    let mut direct_publish_files = BTreeSet::new();
    let mut update_sites = Vec::new();
    let mut delete_sites = Vec::new();
    let mut consumer_create_sites = Vec::new();
    let mut typed_consumer_provision_sites = Vec::new();
    let mut typed_consumer_open_sites = Vec::new();
    let mut durable_binding_sites = Vec::new();

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
            direct_publish_files.insert(relative.clone());
        }
        let update_count = source.matches(raw_update).count();
        if update_count != 0 {
            update_sites.push((relative.clone(), update_count));
        }
        let delete_count = source.matches(raw_delete).count();
        if delete_count != 0 {
            delete_sites.push((relative.clone(), delete_count));
        }
        let consumer_create_count = source.matches(raw_consumer_create).count();
        if consumer_create_count != 0 {
            consumer_create_sites.push((relative.clone(), consumer_create_count));
        }
        let provision_count = source.matches(typed_consumer_provision).count();
        if provision_count != 0 {
            typed_consumer_provision_sites.push((relative.clone(), provision_count));
        }
        let open_count = source.matches(typed_consumer_open).count();
        if open_count != 0 {
            typed_consumer_open_sites.push((relative.clone(), open_count));
        }
        let binding_count = source.matches(durable_binding_constructor).count();
        if binding_count != 0 {
            durable_binding_sites.push((relative, binding_count));
        }
    }
    delete_sites.sort();
    typed_consumer_provision_sites.sort();
    typed_consumer_open_sites.sort();
    durable_binding_sites.sort();

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
    assert_eq!(
        update_sites,
        vec![(
            "psy_node_nats/src/recoverable_transport.rs".to_owned(),
            1,
        )],
        "only the typed recoverable seal façade may update a stream",
    );
    assert_eq!(
        delete_sites,
        vec![
            (
                "psy_node_nats/src/recoverable_segment.rs".to_owned(),
                3,
            ),
            (
                "psy_node_nats/src/recoverable_transport.rs".to_owned(),
                1,
            ),
        ],
        "only historical test cleanup and the typed recoverable delete façade may delete a stream",
    );
    assert_eq!(
        consumer_create_sites,
        vec![(
            "psy_node_nats/src/recoverable_transport.rs".to_owned(),
            1,
        )],
        "only the typed recoverable provisioning façade may create a consumer",
    );
    assert_eq!(
        typed_consumer_provision_sites,
        vec![
            (
                "psy_node_nats/src/recoverable_transport.rs".to_owned(),
                1,
            ),
            (
                "psy_node_scylla/src/rollback/pending_queue_consumer_gate.rs".to_owned(),
                1,
            ),
        ],
        "only the RF=3 transport test and durable consumer gate may provision",
    );
    assert_eq!(
        typed_consumer_open_sites,
        vec![
            (
                "psy_node_nats/src/recoverable_transport.rs".to_owned(),
                1,
            ),
            (
                "psy_node_scylla/src/rollback/pending_queue_consumer_gate.rs".to_owned(),
                1,
            ),
            (
                "psy_node_scylla/src/rollback/pending_queue_nats_capture.rs".to_owned(),
                1,
            ),
        ],
        "existing-only capture is confined to the test, gate, and typed source",
    );
    assert_eq!(
        durable_binding_sites,
        vec![
            (
                "psy_node_nats/src/recoverable_transport.rs".to_owned(),
                1,
            ),
            (
                "psy_node_scylla/src/rollback/pending_queue_consumer_gate.rs".to_owned(),
                1,
            ),
        ],
        "only the RF=3 test and durable gate may construct an existing binding",
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
