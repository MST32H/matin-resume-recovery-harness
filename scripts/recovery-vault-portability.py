#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

class PortabilityError(Exception):
    pass

def require(condition, message):
    if not condition:
        raise PortabilityError(message)

def compact(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def load_object(path, label):
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise PortabilityError(f"cannot read {label} {path}: {exc}") from exc
    require(isinstance(obj, dict), f"{label} must be a JSON object")
    return obj

def report_seal(report):
    payload = {k: v for k, v in report.items() if k != "report_seal"}
    return hashlib.sha256(compact(payload).encode("utf-8")).hexdigest().upper()

def validate_policy(policy):
    require(policy.get("vault_version") == "RV-1", "RV-1 policy mismatch")
    require(policy.get("provider_protocol") == "s3-compatible", "provider protocol mismatch")
    require("GitHub-hosted ubuntu-latest" in str(policy.get("portability_test")), "portability policy incomplete")

def validate_report(report, policy):
    validate_policy(policy)
    expected = {
        "app","purpose","schema_version","vault_version","result",
        "generation_id","artifact_name","git_sha","runner_environment",
        "runner_os","runner_arch","provider_protocol","endpoint_class",
        "bundle_sha256","manifest_seal","roundtrip_bundle_sha256",
        "roundtrip_manifest_seal","push_result","pull_result","verify_result",
        "started_at","finished_at","report_seal"
    }
    require(set(report) == expected, "RV-1 portability report fields mismatch")
    require(report["app"] == "matin-resume", "report app mismatch")
    require(report["purpose"] == "recovery-vault-s3-portability-test", "report purpose mismatch")
    require(report["schema_version"] == 1 and report["vault_version"] == "RV-1", "report version mismatch")
    require(report["result"] == "PASS", "vault portability result is not PASS")
    require(re.fullmatch(r"GH-[0-9]+-[0-9]+", str(report["generation_id"])) is not None, "generation invalid")
    require(isinstance(report["artifact_name"], str) and report["artifact_name"].startswith("matin-resume-recovery-"), "artifact invalid")
    require(re.fullmatch(r"[0-9a-fA-F]{40}", str(report["git_sha"])) is not None, "git SHA invalid")
    require(report["runner_environment"] == "github-hosted", "portability runner must be github-hosted")
    require(report["runner_os"] == "Linux", "portability runner OS must be Linux")
    require(isinstance(report["runner_arch"], str) and report["runner_arch"], "runner arch missing")
    require(report["provider_protocol"] == policy["provider_protocol"], "provider protocol mismatch")
    require(report["endpoint_class"] == "disposable-stdlib-s3", "endpoint class mismatch")
    for key in ("bundle_sha256","manifest_seal","roundtrip_bundle_sha256","roundtrip_manifest_seal","report_seal"):
        require(re.fullmatch(r"[0-9A-F]{64}", str(report[key])) is not None, f"{key} invalid")
    require(report["bundle_sha256"] == report["roundtrip_bundle_sha256"], "vault bundle changed during S3 round trip")
    require(report["manifest_seal"] == report["roundtrip_manifest_seal"], "vault manifest changed during S3 round trip")
    require(report["push_result"] == "PASS" and report["pull_result"] == "PASS" and report["verify_result"] == "PASS", "portability sub-check failed")
    require(report["report_seal"] == report_seal(report), "portability report seal mismatch")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--write-report")
    parser.add_argument("--verify-report")
    parser.add_argument("--generation-id")
    parser.add_argument("--artifact-name")
    parser.add_argument("--git-sha")
    parser.add_argument("--runner-environment")
    parser.add_argument("--runner-os")
    parser.add_argument("--runner-arch")
    parser.add_argument("--bundle-sha256")
    parser.add_argument("--manifest-seal")
    parser.add_argument("--roundtrip-bundle-sha256")
    parser.add_argument("--roundtrip-manifest-seal")
    parser.add_argument("--started-at")
    parser.add_argument("--finished-at")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        policy = load_object(args.policy, "RV-1 policy")
        validate_policy(policy)

        if args.self_test:
            report = {
                "app":"matin-resume","purpose":"recovery-vault-s3-portability-test",
                "schema_version":1,"vault_version":"RV-1","result":"PASS",
                "generation_id":"GH-1000-1","artifact_name":"matin-resume-recovery-"+"1"*40+"-1000-1",
                "git_sha":"1"*40,"runner_environment":"github-hosted","runner_os":"Linux","runner_arch":"X64",
                "provider_protocol":"s3-compatible","endpoint_class":"disposable-stdlib-s3",
                "bundle_sha256":"A"*64,"manifest_seal":"B"*64,
                "roundtrip_bundle_sha256":"A"*64,"roundtrip_manifest_seal":"B"*64,
                "push_result":"PASS","pull_result":"PASS","verify_result":"PASS",
                "started_at":"2026-10-03T10:00:00Z","finished_at":"2026-10-03T10:01:00Z","report_seal":""
            }
            report["report_seal"] = report_seal(report)
            validate_report(report, policy)
            print("RECOVERY_VAULT_PORTABILITY_SELF_TEST_OK protocol=s3-compatible runner=github-hosted")
            return

        if args.verify_report:
            report = load_object(args.verify_report, "RV-1 portability report")
            validate_report(report, policy)
            print(
                "RECOVERY_VAULT_PORTABILITY_REPORT_OK "
                f"generation={report['generation_id']} sha={report['git_sha']} "
                f"bundle={report['bundle_sha256']} report={report['report_seal']}"
            )
            return

        if args.write_report:
            values = [
                args.generation_id,args.artifact_name,args.git_sha,args.runner_environment,
                args.runner_os,args.runner_arch,args.bundle_sha256,args.manifest_seal,
                args.roundtrip_bundle_sha256,args.roundtrip_manifest_seal,args.started_at,args.finished_at
            ]
            require(all(values), "portability report arguments incomplete")
            report = {
                "app":"matin-resume",
                "purpose":"recovery-vault-s3-portability-test",
                "schema_version":1,
                "vault_version":"RV-1",
                "result":"PASS",
                "generation_id":args.generation_id,
                "artifact_name":args.artifact_name,
                "git_sha":args.git_sha,
                "runner_environment":args.runner_environment,
                "runner_os":args.runner_os,
                "runner_arch":args.runner_arch,
                "provider_protocol":"s3-compatible",
                "endpoint_class":"disposable-stdlib-s3",
                "bundle_sha256":args.bundle_sha256,
                "manifest_seal":args.manifest_seal,
                "roundtrip_bundle_sha256":args.roundtrip_bundle_sha256,
                "roundtrip_manifest_seal":args.roundtrip_manifest_seal,
                "push_result":"PASS",
                "pull_result":"PASS",
                "verify_result":"PASS",
                "started_at":args.started_at,
                "finished_at":args.finished_at,
                "report_seal":""
            }
            report["report_seal"] = report_seal(report)
            validate_report(report, policy)
            Path(args.write_report).write_text(compact(report) + "\n", encoding="utf-8")
            print(
                "RECOVERY_VAULT_PORTABILITY_OK "
                f"generation={report['generation_id']} sha={report['git_sha']} "
                f"bundle={report['bundle_sha256']} report={report['report_seal']}"
            )
            return

        raise PortabilityError("choose --write-report, --verify-report or --self-test")
    except (PortabilityError, OSError, ValueError) as exc:
        print(f"RECOVERY_VAULT_PORTABILITY_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
