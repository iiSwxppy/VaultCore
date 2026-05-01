# Multi-stage build for the VaultCore CLI.
#
# Final image: Debian slim with the `vault` binary installed.
# Use case: scripted sync from cron, CI integrations, or just a portable
# container with a known-good vault toolchain.
#
# Build:
#   docker build -t vaultcore-cli .
#
# Use (mount your vault directory, pass the secret key via env):
#   docker run --rm -it \
#     -v $HOME/vaults:/vaults \
#     -e VAULT_SECRET_KEY="A1-..." \
#     vaultcore-cli list /vaults/my.vault
#
# Scripted sync from cron:
#   docker run --rm \
#     -v $HOME/vaults:/vaults \
#     -e VAULT_SECRET_KEY="$SK" \
#     -e VAULT_MASTER_PASSWORD="$PWD" \
#     vaultcore-cli sync /vaults/my.vault --quiet

# ---------- Build stage ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy project files first so dependency restore is cached separately.
COPY Directory.Build.props .
COPY src/Vault.Crypto/Vault.Crypto.csproj src/Vault.Crypto/
COPY src/Vault.Core/Vault.Core.csproj src/Vault.Core/
COPY src/Vault.Ipc/Vault.Ipc.csproj src/Vault.Ipc/
COPY src/Vault.Sync/Vault.Sync.csproj src/Vault.Sync/
COPY src/Vault.Cli/Vault.Cli.csproj src/Vault.Cli/

RUN dotnet restore src/Vault.Cli/Vault.Cli.csproj

# Now the source code.
COPY src/Vault.Crypto/ src/Vault.Crypto/
COPY src/Vault.Core/ src/Vault.Core/
COPY src/Vault.Ipc/ src/Vault.Ipc/
COPY src/Vault.Sync/ src/Vault.Sync/
COPY src/Vault.Cli/ src/Vault.Cli/

RUN dotnet publish src/Vault.Cli/Vault.Cli.csproj \
    -c Release \
    -r linux-x64 \
    --self-contained true \
    -p:PublishReadyToRun=true \
    -p:PublishSingleFile=true \
    -o /app/publish

# ---------- Runtime stage ----------
FROM debian:bookworm-slim AS runtime

# Tools we want available next to the CLI: ca-certificates for HTTPS S3,
# tini for proper signal handling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user.
RUN useradd -m -u 1000 -s /bin/bash vault

WORKDIR /home/vault
COPY --from=build /app/publish/vault /usr/local/bin/vault
RUN chmod +x /usr/local/bin/vault

USER vault
ENV PATH="/usr/local/bin:${PATH}"

ENTRYPOINT ["/usr/bin/tini", "--", "vault"]
CMD ["--help"]
