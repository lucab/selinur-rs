FROM rust:1.28

# Copy whole projects (see .dockerignore for execptions)
WORKDIR /usr/local/src/selinur-rs/
COPY . .

# Populate registry, cache dependencies and ensure source builds
RUN cargo build

# Run integration tests
# This requires `-v /sys/fs/selinux:/sys/fs/selinux`
CMD cargo test --frozen
