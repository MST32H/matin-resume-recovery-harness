#!/usr/bin/env python3
import argparse
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

class VaultError(Exception):
    pass

def require(condition, message):
    if not condition:
        raise VaultError(message)

def compact(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()

def load_object(path, label):
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise VaultError(f"cannot read {label} {path}: {exc}") from exc
    require(isinstance(obj, dict), f"{label} must be a JSON object")
    return obj

def manifest_seal(manifest):
    payload = {key: value for key, value in manifest.items() if key != "manifest_seal"}
    return hashlib.sha256(compact(payload).encode("utf-8")).hexdigest().upper()

def validate_policy(policy):
    require(policy.get("schema_version") == 1, "RV-1 policy schema mismatch")
    require(policy.get("vault_version") == "RV-1", "vault version mismatch")
    require(policy.get("format") == "deterministic-tar-gzip", "vault format mismatch")
    require(policy.get("provider_protocol") == "s3-compatible", "provider protocol mismatch")
    require(policy.get("provider_adapter") == "stdlib-sigv4-path-style", "provider adapter mismatch")
    require(policy.get("bundle_name") == "recovery-vault.tar.gz", "bundle name mismatch")
    require(policy.get("manifest_name") == "recovery-vault-manifest.json", "manifest name mismatch")
    require(policy.get("portability_report_name") == "recovery-vault-portability-report.json", "portability report name mismatch")
    require(policy.get("retention_days") == 30, "retention mismatch")
    required = policy.get("required_recovery_files")
    require(isinstance(required, list) and len(required) >= 8, "required recovery files incomplete")
    require("production-image.tar.gz" in required and "recovery-artifact-chain.jsonl" in required, "critical recovery files missing")
    require(policy.get("manifest_seal_algorithm") == "sha256", "manifest seal algorithm mismatch")
    require(policy.get("manifest_canonicalization") == "compact-json-sorted-keys-excluding-manifest_seal", "manifest canonicalization mismatch")
    claim = str(policy.get("provider_diversity_claim_rule"))
    require("Do not claim strict 3-2-1" in claim, "provider diversity claim rule incomplete")
    target = str(policy.get("three_two_one_target"))
    require("one additional independently operated recovery copy or medium" in target, "3-2-1 target must require an additional independent recovery copy")
    require("GitHub Actions artifact storage is not required" in target, "3-2-1 target must not require GitHub Actions artifact storage")
    require("GitHub-hosted ubuntu-latest" in str(policy.get("portability_test")) and "standard-library AWS SigV4 path-style S3 client" in str(policy.get("portability_test")), "portability test policy incomplete")

def normalized_members(source):
    paths = [p for p in source.rglob("*") if p.is_file()]
    return sorted(paths, key=lambda p: p.relative_to(source).as_posix())

def build_bundle(source, output):
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for path in normalized_members(source):
            rel = path.relative_to(source).as_posix()
            info = tf.gettarinfo(str(path), arcname=rel)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            info.mode = 0o644
            with open(path, "rb") as fh:
                tf.addfile(info, fh)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            gz.write(tar_buffer.getvalue())

def safe_extract(bundle, destination):
    with tarfile.open(bundle, "r:gz") as tf:
        for member in tf.getmembers():
            require(member.isfile(), f"vault contains non-file member: {member.name}")
            require(not member.name.startswith("/") and ".." not in Path(member.name).parts, f"unsafe vault path: {member.name}")
        tf.extractall(destination)

def read_chain_head(path):
    records = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        if raw.strip():
            records.append(json.loads(raw))
    require(records, "artifact chain is empty")
    return records[-1]

def create(args, policy):
    source = Path(args.source_dir)
    require(source.is_dir(), f"source recovery directory missing: {source}")
    for name in policy["required_recovery_files"]:
        require((source / name).is_file(), f"source recovery directory missing {name}")

    build = load_object(source / "build.json", "build provenance")
    attestation = load_object(source / "release-attestation.json", "release attestation")
    image_manifest = load_object(source / "immutable-image-manifest.json", "immutable image manifest")
    chain_head = read_chain_head(source / "recovery-artifact-chain.jsonl")

    require(build.get("git_sha") == args.expected_sha, "build SHA mismatch")
    require(attestation.get("git_sha") == args.expected_sha, "attestation SHA mismatch")
    require(image_manifest.get("git_sha") == args.expected_sha, "immutable image manifest SHA mismatch")
    require(chain_head.get("git_sha") == args.expected_sha, "artifact chain SHA mismatch")
    require(chain_head.get("generation_id") == args.generation_id, "artifact chain generation mismatch")
    require(chain_head.get("artifact_name") == args.artifact_name, "artifact chain artifact mismatch")

    bundle = Path(args.output_bundle)
    manifest_path = Path(args.output_manifest)
    build_bundle(source, bundle)

    manifest = {
        "app": "matin-resume",
        "purpose": "provider-neutral-recovery-vault",
        "schema_version": 1,
        "vault_version": "RV-1",
        "format": policy["format"],
        "provider_protocol": policy["provider_protocol"],
        "git_sha": args.expected_sha,
        "generation_id": args.generation_id,
        "artifact_name": args.artifact_name,
        "bundle_name": bundle.name,
        "bundle_sha256": sha256_file(bundle),
        "bundle_size_bytes": bundle.stat().st_size,
        "source_archive_sha256": image_manifest["archive_sha256"],
        "artifact_chain_head": chain_head["record_hash"],
        "attestation_seal": attestation["attestation_seal"],
        "file_count": len(normalized_members(source)),
        "manifest_seal": ""
    }
    manifest["manifest_seal"] = manifest_seal(manifest)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(compact(manifest) + "\n", encoding="utf-8")
    validate_manifest(manifest, policy, bundle)
    print(
        "RECOVERY_VAULT_OK "
        f"generation={manifest['generation_id']} sha={manifest['git_sha']} "
        f"bundle={manifest['bundle_sha256']} files={manifest['file_count']} seal={manifest['manifest_seal']}"
    )

def validate_manifest(manifest, policy, bundle=None):
    expected = {
        "app","purpose","schema_version","vault_version","format","provider_protocol",
        "git_sha","generation_id","artifact_name","bundle_name","bundle_sha256",
        "bundle_size_bytes","source_archive_sha256","artifact_chain_head",
        "attestation_seal","file_count","manifest_seal"
    }
    require(set(manifest) == expected, "RV-1 manifest fields mismatch")
    require(manifest["app"] == "matin-resume", "manifest app mismatch")
    require(manifest["purpose"] == "provider-neutral-recovery-vault", "manifest purpose mismatch")
    require(manifest["schema_version"] == 1 and manifest["vault_version"] == "RV-1", "manifest version mismatch")
    require(manifest["format"] == policy["format"], "manifest format mismatch")
    require(manifest["provider_protocol"] == policy["provider_protocol"], "manifest provider protocol mismatch")
    require(re.fullmatch(r"[0-9a-fA-F]{40}", str(manifest["git_sha"])) is not None, "manifest git_sha invalid")
    require(re.fullmatch(r"GH-[0-9]+-[0-9]+", str(manifest["generation_id"])) is not None, "manifest generation invalid")
    require(isinstance(manifest["artifact_name"], str) and manifest["artifact_name"].startswith("matin-resume-recovery-"), "manifest artifact invalid")
    require(manifest["bundle_name"] == policy["bundle_name"], "manifest bundle name mismatch")
    for key in ("bundle_sha256","source_archive_sha256","artifact_chain_head","attestation_seal","manifest_seal"):
        require(re.fullmatch(r"[0-9A-F]{64}", str(manifest[key])) is not None, f"{key} invalid")
    require(isinstance(manifest["bundle_size_bytes"], int) and manifest["bundle_size_bytes"] > 0, "bundle size invalid")
    require(isinstance(manifest["file_count"], int) and manifest["file_count"] >= len(policy["required_recovery_files"]), "file count invalid")
    require(manifest["manifest_seal"] == manifest_seal(manifest), "RV-1 manifest seal mismatch")
    if bundle is not None:
        bundle = Path(bundle)
        require(bundle.is_file(), "vault bundle missing")
        require(bundle.stat().st_size == manifest["bundle_size_bytes"], "vault bundle size mismatch")
        require(sha256_file(bundle) == manifest["bundle_sha256"], "vault bundle digest mismatch")

def verify(args, policy):
    manifest = load_object(args.manifest, "RV-1 manifest")
    bundle = Path(args.bundle)
    validate_manifest(manifest, policy, bundle)

    with tempfile.TemporaryDirectory(prefix="matin-resume-vault-") as tmp:
        root = Path(tmp)
        safe_extract(bundle, root)
        for name in policy["required_recovery_files"]:
            require((root / name).is_file(), f"vault bundle missing {name}")
        build = load_object(root / "build.json", "restored build provenance")
        attestation = load_object(root / "release-attestation.json", "restored release attestation")
        image_manifest = load_object(root / "immutable-image-manifest.json", "restored immutable image manifest")
        head = read_chain_head(root / "recovery-artifact-chain.jsonl")
        require(build.get("git_sha") == manifest["git_sha"], "restored build SHA mismatch")
        require(attestation.get("git_sha") == manifest["git_sha"], "restored attestation SHA mismatch")
        require(attestation.get("attestation_seal") == manifest["attestation_seal"], "restored attestation seal mismatch")
        require(image_manifest.get("archive_sha256") == manifest["source_archive_sha256"], "restored source archive digest mismatch")
        require(head.get("record_hash") == manifest["artifact_chain_head"], "restored artifact chain head mismatch")
        require(head.get("generation_id") == manifest["generation_id"], "restored artifact chain generation mismatch")
        require(head.get("artifact_name") == manifest["artifact_name"], "restored artifact name mismatch")

    if args.extract_to:
        destination = Path(args.extract_to)
        destination.mkdir(parents=True, exist_ok=True)
        require(not any(destination.iterdir()), f"extract destination must be empty: {destination}")
        safe_extract(bundle, destination)

    print(
        "RECOVERY_VAULT_VERIFY_OK "
        f"generation={manifest['generation_id']} sha={manifest['git_sha']} "
        f"bundle={manifest['bundle_sha256']} seal={manifest['manifest_seal']}"
    )

def self_test(policy):
    validate_policy(policy)
    manifest = {
        "app":"matin-resume","purpose":"provider-neutral-recovery-vault","schema_version":1,
        "vault_version":"RV-1","format":policy["format"],"provider_protocol":policy["provider_protocol"],
        "git_sha":"1"*40,"generation_id":"GH-1000-1",
        "artifact_name":"matin-resume-recovery-"+"1"*40+"-1000-1",
        "bundle_name":"recovery-vault.tar.gz","bundle_sha256":"A"*64,"bundle_size_bytes":12345,
        "source_archive_sha256":"B"*64,"artifact_chain_head":"C"*64,"attestation_seal":"D"*64,
        "file_count":12,"manifest_seal":""
    }
    manifest["manifest_seal"] = manifest_seal(manifest)
    validate_manifest(manifest, policy)
    bad = dict(manifest)
    bad["provider_protocol"] = "github-only"
    try:
        validate_manifest(bad, policy)
    except VaultError:
        pass
    else:
        raise VaultError("provider protocol tamper self-test failed")
    print("RECOVERY_VAULT_SELF_TEST_OK format=deterministic-tar-gzip protocol=s3-compatible claim=guarded")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--source-dir")
    parser.add_argument("--expected-sha")
    parser.add_argument("--generation-id")
    parser.add_argument("--artifact-name")
    parser.add_argument("--output-bundle")
    parser.add_argument("--output-manifest")
    parser.add_argument("--bundle")
    parser.add_argument("--manifest")
    parser.add_argument("--extract-to")
    parser.add_argument("--create", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--verify-manifest", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        policy = load_object(args.policy, "RV-1 policy")
        validate_policy(policy)
        if args.self_test:
            self_test(policy)
            return
        if args.create:
            required = [args.source_dir,args.expected_sha,args.generation_id,args.artifact_name,args.output_bundle,args.output_manifest]
            require(all(required), "RV-1 create arguments incomplete")
            create(args, policy)
            return
        if args.verify:
            require(args.bundle and args.manifest, "RV-1 verify requires --bundle and --manifest")
            verify(args, policy)
            return
        if args.verify_manifest:
            require(args.manifest, "RV-1 manifest verification requires --manifest")
            manifest = load_object(args.manifest, "RV-1 manifest")
            validate_manifest(manifest, policy)
            print(
                "RECOVERY_VAULT_MANIFEST_OK "
                f"generation={manifest['generation_id']} sha={manifest['git_sha']} "
                f"bundle={manifest['bundle_sha256']} seal={manifest['manifest_seal']}"
            )
            return
        raise VaultError("choose --create, --verify, --verify-manifest or --self-test")
    except (VaultError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"RECOVERY_VAULT_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
