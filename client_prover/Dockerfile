FROM rust:1.88.0-slim AS builder

RUN cargo install sqlx-cli \
    --no-default-features \
    --features rustls,postgres,mysql

FROM docker.io/library/ubuntu:24.04

ARG PROFILE=release

RUN apt update -y \
  && apt install -y ca-certificates libssl-dev tzdata jq wget curl docker.io vim net-tools postgresql-client \
  && apt clean \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/sqlx /usr/local/bin/

WORKDIR /psy-node

COPY ./target/${PROFILE}/psy_node_cli /psy-node
COPY ./target/${PROFILE}/psy_user_cli /psy-node
COPY ./target/${PROFILE}/psy_dev_cli /psy-node
COPY ./target/${PROFILE}/psy_services /psy-node
COPY ./psy_services/migrations /psy-node/migrations
COPY .env /psy-node/.env

RUN echo '#!/bin/bash\n/psy-node/psy_node_cli $@' > /psy-node/.entrypoint.sh
RUN chmod u+x /psy-node/.entrypoint.sh

ENTRYPOINT ["/psy-node/.entrypoint.sh"]

