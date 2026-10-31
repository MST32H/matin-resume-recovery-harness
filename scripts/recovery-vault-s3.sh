#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-}"
LOCAL_DIR="${2:-}"
OBJECT_PREFIX="${3:-}"

: "${RECOVERY_VAULT_S3_ENDPOINT:?RECOVERY_VAULT_S3_ENDPOINT is required}"
: "${RECOVERY_VAULT_S3_BUCKET:?RECOVERY_VAULT_S3_BUCKET is required}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"

case "$MODE" in
  push|pull|stat) ;;
  *) echo "Usage: $0 {push|pull|stat} LOCAL_DIR OBJECT_PREFIX" >&2; exit 2 ;;
esac

[[ -d "$LOCAL_DIR" ]] || { echo "Local directory missing: $LOCAL_DIR" >&2; exit 1; }
[[ -n "$OBJECT_PREFIX" ]] || { echo "Object prefix is required." >&2; exit 1; }

LOCAL_DIR="$(cd "$LOCAL_DIR" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S3_HELPER="$SCRIPT_DIR/recovery-s3-object.py"
test -s "$S3_HELPER"

bundle_key="$OBJECT_PREFIX/recovery-vault.tar.gz"
manifest_key="$OBJECT_PREFIX/recovery-vault-manifest.json"

case "$MODE" in
  push)
    test -s "$LOCAL_DIR/recovery-vault.tar.gz"
    test -s "$LOCAL_DIR/recovery-vault-manifest.json"
    python3 "$S3_HELPER" ensure-bucket "$LOCAL_DIR/recovery-vault-manifest.json" "__bucket__"
    python3 "$S3_HELPER" put "$LOCAL_DIR/recovery-vault.tar.gz" "$bundle_key"
    python3 "$S3_HELPER" put "$LOCAL_DIR/recovery-vault-manifest.json" "$manifest_key"
    python3 "$S3_HELPER" head "$LOCAL_DIR/recovery-vault.tar.gz" "$bundle_key"
    python3 "$S3_HELPER" head "$LOCAL_DIR/recovery-vault-manifest.json" "$manifest_key"
    echo "RECOVERY_VAULT_S3_PUSH_OK prefix=$OBJECT_PREFIX"
    ;;
  pull)
    rm -f "$LOCAL_DIR/recovery-vault.tar.gz" "$LOCAL_DIR/recovery-vault-manifest.json"
    python3 "$S3_HELPER" get "$LOCAL_DIR/recovery-vault.tar.gz" "$bundle_key"
    python3 "$S3_HELPER" get "$LOCAL_DIR/recovery-vault-manifest.json" "$manifest_key"
    test -s "$LOCAL_DIR/recovery-vault.tar.gz"
    test -s "$LOCAL_DIR/recovery-vault-manifest.json"
    echo "RECOVERY_VAULT_S3_PULL_OK prefix=$OBJECT_PREFIX"
    ;;
  stat)
    python3 "$S3_HELPER" head "$LOCAL_DIR/recovery-vault.tar.gz" "$bundle_key"
    python3 "$S3_HELPER" head "$LOCAL_DIR/recovery-vault-manifest.json" "$manifest_key"
    echo "RECOVERY_VAULT_S3_STAT_OK prefix=$OBJECT_PREFIX"
    ;;
esac
