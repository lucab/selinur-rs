FROM rust:1.28

WORKDIR /usr/local/src/selinur-rs/
COPY . .

RUN cargo test
