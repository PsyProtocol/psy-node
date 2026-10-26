#!/usr/bin/env python3
"""Validate the actual installer template without touching Docker or live data.

Requires PyYAML; run with python3 deploy/gcp/tests/test-hasura-log-retention.py.
"""
import pathlib
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "remote/install-envio.sh").read_text()
MARKER = "cat > generated/docker-compose.hasura.yaml <<'EOF'\n"
COMPOSE = yaml.safe_load(SCRIPT.split(MARKER, 1)[1].split("\nEOF", 1)[0])


class HasuraLogRetentionTests(unittest.TestCase):
    def test_bounded_docker_managed_rotation(self):
        self.assertEqual(COMPOSE["services"]["graphql-engine"]["logging"], {
            "driver": "json-file",
            "options": {"max-size": "100m", "max-file": "100", "compress": "true"},
        })

    def test_runtime_policy_checked_after_container_creation(self):
        create = SCRIPT.index("compose -f generated/docker-compose.hasura.yaml up -d")
        inspect = SCRIPT.index("docker inspect --format '{{json .HostConfig.LogConfig}}'")
        self.assertGreater(inspect, create)
        for check in ('.Type == "json-file"', '.Config["max-size"] == "100m"',
                      '.Config["max-file"] == "100"', '.Config.compress == "true"'):
            self.assertIn(check, SCRIPT[inspect:])
        self.assertIn('echo "Hasura log retention policy not applied" >&2; exit 1;', SCRIPT)

    def test_logging_change_does_not_replace_database_or_log_types(self):
        self.assertEqual(set(COMPOSE["services"]), {"graphql-engine"})
        env = COMPOSE["services"]["graphql-engine"]["environment"]
        self.assertEqual(env["HASURA_GRAPHQL_DATABASE_URL"], "${ENVIO_DATABASE_URL}")
        self.assertEqual(env["HASURA_GRAPHQL_ENABLED_LOG_TYPES"],
                         "startup, http-log, webhook-log, websocket-log, query-log")


if __name__ == "__main__":
    unittest.main()
