# Scylla runtime connection options

The existing unauthenticated connection and automatic keyspace creation remain
unchanged when the following optional settings are absent.

For authenticated deployments, set both:

```text
SCYLLA_USERNAME_FILE=/run/credentials/username
SCYLLA_PASSWORD_FILE=/run/credentials/password
```

Mount these files from the application's own Secret. Never pass credentials in
command-line flags or log them. Files accept one trailing LF/CRLF, preserve
meaningful spaces, and reject missing/empty/invalid/oversized content. Setting
only one variable fails startup; an authentication failure does not fall back
to an anonymous connection. Projected Secret symlinks are supported.

For roles without global `CREATE KEYSPACE` permission, provision both the
configured keyspace and its `<keyspace>_no_tablet` counterpart in a separate
administrator step, grant the application its required permissions there, and
set:

```text
PSY_SCYLLA_SCHEMA_PRECREATED=true
```

This mode queries `system_schema.keyspaces` for both exact names using bound
parameters. It fails if either is missing and does not create/alter a keyspace.
It does not change table initialization within the existing keyspaces.
Accepted values are `1`/`true` and `0`/`false`; typos fail startup.

This change does not alter queries in legacy mode, schema formats, Genesis,
proof circuits, protocol fingerprints or queue encodings. It is intended for
the isolated Kubernetes lab; publishing source does not deploy it to the live
network. Real authenticated integration and the CLI transaction flow must be
verified before describing the new chain as ready.

The pure credential/parser tests can be checked without building circuits:

```bash
rustc --edition=2021 --test psy_node_scylla/src/auth.rs -o /tmp/psy-scylla-auth-tests
/tmp/psy-scylla-auth-tests
```

The complete crate and final binaries must also build with the cohort's pinned
Rust/Go toolchain before release deployment.
