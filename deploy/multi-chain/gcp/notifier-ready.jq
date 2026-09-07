.ready == true and .evm_all_healthy == true
and ([.evm_probes[] | select(.healthy == true) | .chain_id] | sort
     == [97, 84532, 11155111])
and (.collectors as $collectors | all($hosts[]; . as $host |
  any($collectors[];
    .collector_id == $host and .environment == "staging"
    and (.last_seen_ms | type) == "number"
    and .last_seen_ms >= ($now - 120000)
    and .last_seen_ms <= ($now + 30000))))
