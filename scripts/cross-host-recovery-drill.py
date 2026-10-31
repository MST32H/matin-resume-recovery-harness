#!/usr/bin/env python3
import argparse
import copy
import gzip
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

class CrossHostError(Exception):
    pass

def require(condition, message):
    if not condition:
        raise CrossHostError(message)

def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def load_object(path, label):
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise CrossHostError(f"cannot read {label} {path}: {exc}") from exc
    require(isinstance(obj, dict), f"{label} must be a JSON object")
    return obj

def compact(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def report_seal(report):
    payload = {key: value for key, value in report.items() if key != "report_seal"}
    return hashlib.sha256(compact(payload).encode("utf-8")).hexdigest().upper()

def run(cmd, *, input_file=None, check=True):
    try:
        result = subprocess.run(
            cmd,
            stdin=input_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=input_file is None,
        )
    except Exception as exc:
        raise CrossHostError(f"cannot execute {' '.join(cmd)}: {exc}") from exc
    if check and result.returncode != 0:
        stdout = result.stdout if isinstance(result.stdout, str) else ""
        stderr = result.stderr if isinstance(result.stderr, str) else ""
        detail = (stderr or stdout).strip()
        raise CrossHostError(f"command failed ({' '.join(cmd)}): {detail}")
    return result

def validate_policy(policy):
    require(policy.get("schema_version") == 1, "CH-1 policy schema mismatch")
    require(policy.get("drill_version") == "CH-1", "CH-1 version mismatch")
    require(policy.get("mode") == "github-hosted-cross-host-restore", "CH-1 mode mismatch")
    require(policy.get("required_runner_environment") == "github-hosted", "runner environment policy mismatch")
    require(policy.get("required_runs_on") == "ubuntu-latest", "runner label policy mismatch")
    require(policy.get("restored_network") == "none", "restored network must be none")
    require(policy.get("production_container") == "matin-resume", "Production container policy mismatch")
    require(policy.get("production_state_path") == "/var/lib/matin-resume", "Production state path mismatch")
    require(policy.get("report_file") == "/var/lib/matin-resume/ci/cross-host-recovery-report.json", "report file mismatch")
    require(policy.get("report_artifact_retention_days") == 30, "report retention mismatch")
    require(policy.get("report_seal_algorithm") == "sha256", "report seal algorithm mismatch")
    require(policy.get("report_canonicalization") == "compact-json-sorted-keys-excluding-report_seal", "report canonicalization mismatch")
    checks = policy.get("required_checks")
    require(isinstance(checks, list) and len(checks) >= 12, "required checks incomplete")
    for name in ("github_hosted_runner","production_container_absent","production_state_absent","docker_load","isolated_health","recovery_tag_cleanup","container_cleanup"):
        require(name in checks, f"required check missing: {name}")
    invariant = str(policy.get("safety_invariant"))
    require("GitHub-hosted ubuntu-latest" in invariant and "receives no VPS credentials" in invariant and "--network none" in invariant, "safety invariant incomplete")
    require("GitHub-hosted runner separate from the Production VPS" in str(policy.get("publication_rule")), "publication rule incomplete")

def validate_report(report, policy):
    validate_policy(policy)
    expected_keys = {
        "app","purpose","schema_version","drill_version","mode","result",
        "generation_id","artifact_name","git_sha","run_id","run_attempt",
        "started_at","finished_at","archive_sha256","immutable_manifest_seal",
        "image_identity_seal","recovery_checkpoint_seal","attestation_seal",
        "runner_environment","runner_os","runner_arch","runner_name",
        "docker_server_version","docker_storage_driver","images_before",
        "production_container_absent","production_state_absent",
        "recovery_tag_absent_before","loaded_image_id","restored_container_image_id",
        "restored_build_sha","restored_attestation_seal","restored_network",
        "recovery_tag_absent_after","container_absent_after","checks","report_seal"
    }
    require(set(report) == expected_keys, "CH-1 report fields mismatch")
    require(report["app"] == "matin-resume", "report app mismatch")
    require(report["purpose"] == "cross-host-disaster-recovery-rehearsal", "report purpose mismatch")
    require(report["schema_version"] == 1 and report["drill_version"] == "CH-1", "report version mismatch")
    require(report["mode"] == policy["mode"], "report mode mismatch")
    require(report["result"] == "PASS", "cross-host rehearsal did not pass")
    require(re.fullmatch(r"GH-[0-9]+-[0-9]+", str(report["generation_id"])) is not None, "generation_id invalid")
    require(isinstance(report["artifact_name"], str) and report["artifact_name"].startswith("matin-resume-recovery-"), "artifact_name invalid")
    require(re.fullmatch(r"[0-9a-fA-F]{40}", str(report["git_sha"])) is not None, "git_sha invalid")
    require(str(report["run_id"]).isdigit() and int(report["run_id"]) > 0, "run_id invalid")
    require(str(report["run_attempt"]).isdigit() and int(report["run_attempt"]) > 0, "run_attempt invalid")
    require(report["generation_id"] == f"GH-{report['run_id']}-{report['run_attempt']}", "generation does not bind workflow run")
    for key in ("archive_sha256","immutable_manifest_seal","image_identity_seal","recovery_checkpoint_seal","attestation_seal","restored_attestation_seal","report_seal"):
        require(re.fullmatch(r"[0-9A-F]{64}", str(report[key])) is not None, f"{key} invalid")
    require(report["runner_environment"] == policy["required_runner_environment"], "report runner environment mismatch")
    require(report["runner_os"] == "Linux", "runner OS must be Linux")
    require(isinstance(report["runner_arch"], str) and report["runner_arch"], "runner arch missing")
    require(isinstance(report["runner_name"], str) and report["runner_name"], "runner name missing")
    require(isinstance(report["docker_server_version"], str) and report["docker_server_version"], "Docker server version missing")
    require(isinstance(report["docker_storage_driver"], str) and report["docker_storage_driver"], "Docker storage driver missing")
    require(isinstance(report["images_before"], int) and report["images_before"] >= 0, "images_before invalid")
    require(report["production_container_absent"] is True, "Production container unexpectedly exists on cross-host runner")
    require(report["production_state_absent"] is True, "Production state unexpectedly exists on cross-host runner")
    require(report["recovery_tag_absent_before"] is True, "recovery tag existed before cross-host restore")
    require(str(report["loaded_image_id"]).startswith("sha256:"), "loaded image ID invalid")
    require(report["restored_container_image_id"] == report["loaded_image_id"], "restored container image mismatch")
    require(report["restored_build_sha"] == report["git_sha"], "restored build SHA mismatch")
    require(report["restored_attestation_seal"] == report["attestation_seal"], "restored attestation mismatch")
    require(report["restored_network"] == "none", "restored workload network was not none")
    require(report["recovery_tag_absent_after"] is True, "recovery tag was not cleaned from cross-host runner")
    require(report["container_absent_after"] is True, "cross-host restore container was not cleaned")
    require(isinstance(report["checks"], dict), "checks must be object")
    for check in policy["required_checks"]:
        require(report["checks"].get(check) == "PASS", f"required cross-host check failed: {check}")
    require(report["report_seal"] == report_seal(report), "CH-1 report seal mismatch")

def validate_package(root, expected_sha, generation_id, artifact_name):
    required = [
        "production-image.tar.gz","immutable-image-manifest.json","production-image-identity.json",
        "recovery-checkpoint.json","deployment-attestation-history.jsonl","recovery-artifact-chain.jsonl",
        "build.json","release-attestation.json","recovery-artifact-chain-policy.json",
        "immutable-production-image-policy.json","recovery-checkpoint-policy.json",
        "recruiter-baseline-release.json","recruiter-baseline-ledger.json",
        "validate-deployment-attestation-history.py","validate-recovery-checkpoint.py",
        "validate-production-image-identity.py","immutable-image-archive.py","recovery-artifact-chain.py"
    ]
    for name in required:
        require((root / name).is_file(), f"recovery artifact missing {name}")

    manifest = load_object(root / "immutable-image-manifest.json", "immutable image manifest")
    identity = load_object(root / "production-image-identity.json", "production image identity")
    checkpoint = load_object(root / "recovery-checkpoint.json", "recovery checkpoint")
    attestation = load_object(root / "release-attestation.json", "release attestation")
    build = load_object(root / "build.json", "build provenance")

    for obj, label in ((manifest,"manifest"),(identity,"identity"),(checkpoint,"checkpoint"),(attestation,"attestation"),(build,"build")):
        require(obj.get("git_sha") == expected_sha, f"{label} git_sha mismatch")

    run([sys.executable, str(root / "recovery-artifact-chain.py"),
         "--policy", str(root / "recovery-artifact-chain-policy.json"),
         "--chain", str(root / "recovery-artifact-chain.jsonl"),
         "--expected-sha", expected_sha,
         "--expected-generation-id", generation_id])

    run([sys.executable, str(root / "immutable-image-archive.py"),
         "--identity", str(root / "production-image-identity.json"),
         "--checkpoint", str(root / "recovery-checkpoint.json"),
         "--archive", str(root / "production-image.tar.gz"),
         "--manifest", str(root / "immutable-image-manifest.json")])

    chain = [
        json.loads(line) for line in (root / "recovery-artifact-chain.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    require(chain and chain[-1].get("generation_id") == generation_id, "artifact chain generation mismatch")
    require(chain[-1].get("artifact_name") == artifact_name, "artifact chain artifact mismatch")
    require(chain[-1].get("archive_sha256") == manifest.get("archive_sha256"), "artifact chain archive digest mismatch")
    return manifest, identity, checkpoint, attestation, build

def read_json_from_container(container, path):
    result = run(["docker", "exec", container, "wget", "-qO-", f"http://127.0.0.1{path}"])
    try:
        return json.loads(result.stdout)
    except Exception as exc:
        raise CrossHostError(f"restored {path} invalid: {exc}") from exc

def wait_health(container, timeout=60):
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        result = run(["docker", "exec", container, "wget", "-qO-", "http://127.0.0.1/healthz"], check=False)
        last = result.stdout.strip() if isinstance(result.stdout, str) else ""
        if result.returncode == 0 and last == "ok":
            return
        time.sleep(1)
    raise CrossHostError(f"cross-host restored workload failed health check: {last}")

def rehearse(args, policy):
    root = Path(args.artifact_dir)
    require(root.is_dir(), f"artifact directory missing: {root}")
    started = now_utc()
    checks = {name: "PENDING" for name in policy["required_checks"]}
    restored = f"matin-resume-cross-host-{int(time.time())}"
    recovery_tag = ""
    manifest = identity = checkpoint = attestation = build = None
    loaded_image_id = ""
    restored_image_id = ""
    restored_build_sha = ""
    restored_attestation_seal = ""
    container_absent_after = False
    tag_absent_after = False

    try:
        require(args.runner_environment == policy["required_runner_environment"], "workflow runner is not GitHub-hosted")
        checks["github_hosted_runner"] = "PASS"

        production_container_absent = run(["docker", "inspect", policy["production_container"]], check=False).returncode != 0
        require(production_container_absent, "Production container unexpectedly exists on cross-host runner")
        checks["production_container_absent"] = "PASS"

        production_state_absent = not Path(policy["production_state_path"]).exists()
        require(production_state_absent, "Production VPS state path unexpectedly exists on cross-host runner")
        checks["production_state_absent"] = "PASS"

        manifest, identity, checkpoint, attestation, build = validate_package(
            root, args.expected_sha, args.generation_id, args.artifact_name
        )
        checks["artifact_chain"] = "PASS"
        checks["immutable_archive"] = "PASS"

        recovery_tag = manifest["recovery_tag"]
        tag_absent_before = run(["docker", "image", "inspect", recovery_tag], check=False).returncode != 0
        require(tag_absent_before, "recovery tag unexpectedly exists before cross-host restore")
        checks["recovery_tag_absent_before"] = "PASS"

        server_version = run(["docker", "version", "--format", "{{.Server.Version}}"]).stdout.strip()
        storage_driver = run(["docker", "info", "--format", "{{.Driver}}"]).stdout.strip()
        images_before = int(run(["bash", "-lc", "docker image ls -q | sort -u | wc -l"]).stdout.strip())

        with gzip.open(root / "production-image.tar.gz", "rb") as archive:
            run(["docker", "load"], input_file=archive)
        checks["docker_load"] = "PASS"

        loaded_image_id = run(["docker", "image", "inspect", recovery_tag, "--format", "{{.Id}}"]).stdout.strip()
        require(loaded_image_id.startswith("sha256:"), "loaded image ID invalid")

        run(["docker", "run", "-d", "--name", restored, "--network", "none", "--restart", "no", recovery_tag])
        restored_image_id = run(["docker", "inspect", restored, "--format", "{{.Image}}"]).stdout.strip()
        require(restored_image_id == loaded_image_id, "restored container did not use downloaded image")
        restored_network = run(["docker", "inspect", restored, "--format", "{{.HostConfig.NetworkMode}}"]).stdout.strip()
        require(restored_network == "none", "restored workload network is not none")

        wait_health(restored)
        checks["isolated_health"] = "PASS"

        restored_build = read_json_from_container(restored, "/build.json")
        restored_attestation = read_json_from_container(restored, "/release-attestation.json")
        require(restored_build == build, "restored build.json differs from artifact")
        require(restored_attestation == attestation, "restored release-attestation.json differs from artifact")
        restored_build_sha = restored_build.get("git_sha", "")
        restored_attestation_seal = restored_attestation.get("attestation_seal", "")
        require(restored_build_sha == args.expected_sha, "restored build SHA mismatch")
        require(restored_attestation_seal == attestation.get("attestation_seal"), "restored attestation seal mismatch")
        checks["restored_build"] = "PASS"
        checks["restored_attestation"] = "PASS"

        run(["docker", "rm", "-f", restored])
        container_absent_after = run(["docker", "inspect", restored], check=False).returncode != 0
        require(container_absent_after, "cross-host restore container cleanup failed")
        checks["container_cleanup"] = "PASS"

        run(["docker", "image", "rm", recovery_tag])
        tag_absent_after = run(["docker", "image", "inspect", recovery_tag], check=False).returncode != 0
        require(tag_absent_after, "cross-host recovery tag cleanup failed")
        checks["recovery_tag_cleanup"] = "PASS"

        report = {
            "app": "matin-resume",
            "purpose": "cross-host-disaster-recovery-rehearsal",
            "schema_version": 1,
            "drill_version": "CH-1",
            "mode": policy["mode"],
            "result": "PASS",
            "generation_id": args.generation_id,
            "artifact_name": args.artifact_name,
            "git_sha": args.expected_sha,
            "run_id": str(args.run_id),
            "run_attempt": str(args.run_attempt),
            "started_at": started,
            "finished_at": now_utc(),
            "archive_sha256": manifest["archive_sha256"],
            "immutable_manifest_seal": manifest["manifest_seal"],
            "image_identity_seal": identity["identity_seal"],
            "recovery_checkpoint_seal": checkpoint["checkpoint_seal"],
            "attestation_seal": attestation["attestation_seal"],
            "runner_environment": args.runner_environment,
            "runner_os": args.runner_os,
            "runner_arch": args.runner_arch,
            "runner_name": args.runner_name,
            "docker_server_version": server_version,
            "docker_storage_driver": storage_driver,
            "images_before": images_before,
            "production_container_absent": production_container_absent,
            "production_state_absent": production_state_absent,
            "recovery_tag_absent_before": tag_absent_before,
            "loaded_image_id": loaded_image_id,
            "restored_container_image_id": restored_image_id,
            "restored_build_sha": restored_build_sha,
            "restored_attestation_seal": restored_attestation_seal,
            "restored_network": restored_network,
            "recovery_tag_absent_after": tag_absent_after,
            "container_absent_after": container_absent_after,
            "checks": checks,
            "report_seal": "",
        }
        report["report_seal"] = report_seal(report)
        validate_report(report, policy)
        Path(args.output_report).write_text(compact(report) + "\n", encoding="utf-8")
        print(
            "CROSS_HOST_RECOVERY_OK "
            f"generation={args.generation_id} sha={args.expected_sha} "
            f"runner={args.runner_environment}/{args.runner_os}/{args.runner_arch} "
            f"docker={server_version} archive={report['archive_sha256']} "
            f"report={report['report_seal']}"
        )
    finally:
        run(["docker", "rm", "-f", restored], check=False)
        if recovery_tag:
            run(["docker", "image", "rm", recovery_tag], check=False)

def self_test(policy):
    validate_policy(policy)
    report = {
        "app": "matin-resume",
        "purpose": "cross-host-disaster-recovery-rehearsal",
        "schema_version": 1,
        "drill_version": "CH-1",
        "mode": policy["mode"],
        "result": "PASS",
        "generation_id": "GH-1000-1",
        "artifact_name": "matin-resume-recovery-" + "1" * 40 + "-1000-1",
        "git_sha": "1" * 40,
        "run_id": "1000",
        "run_attempt": "1",
        "started_at": "2026-10-03T07:00:00Z",
        "finished_at": "2026-10-03T07:02:00Z",
        "archive_sha256": "A" * 64,
        "immutable_manifest_seal": "B" * 64,
        "image_identity_seal": "C" * 64,
        "recovery_checkpoint_seal": "D" * 64,
        "attestation_seal": "E" * 64,
        "runner_environment": "github-hosted",
        "runner_os": "Linux",
        "runner_arch": "X64",
        "runner_name": "GitHub Actions 1",
        "docker_server_version": "28.0.0",
        "docker_storage_driver": "overlay2",
        "images_before": 5,
        "production_container_absent": True,
        "production_state_absent": True,
        "recovery_tag_absent_before": True,
        "loaded_image_id": "sha256:" + "f" * 64,
        "restored_container_image_id": "sha256:" + "f" * 64,
        "restored_build_sha": "1" * 40,
        "restored_attestation_seal": "E" * 64,
        "restored_network": "none",
        "recovery_tag_absent_after": True,
        "container_absent_after": True,
        "checks": {name: "PASS" for name in policy["required_checks"]},
        "report_seal": "",
    }
    report["report_seal"] = report_seal(report)
    validate_report(report, policy)

    tampered = copy.deepcopy(report)
    tampered["runner_environment"] = "self-hosted"
    try:
        validate_report(tampered, policy)
    except CrossHostError:
        pass
    else:
        raise CrossHostError("runner-environment tamper self-test failed")
    print("CROSS_HOST_RECOVERY_SELF_TEST_OK runner=github-hosted production=absent network=none cleanup=verified")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--artifact-dir")
    parser.add_argument("--expected-sha")
    parser.add_argument("--generation-id")
    parser.add_argument("--artifact-name")
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    parser.add_argument("--runner-environment")
    parser.add_argument("--runner-os")
    parser.add_argument("--runner-arch")
    parser.add_argument("--runner-name")
    parser.add_argument("--output-report")
    parser.add_argument("--verify-report")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        policy = load_object(args.policy, "cross-host recovery policy")
        validate_policy(policy)
        if args.self_test:
            self_test(policy)
            return
        if args.verify_report:
            report = load_object(args.verify_report, "cross-host recovery report")
            validate_report(report, policy)
            print(
                "CROSS_HOST_RECOVERY_REPORT_OK "
                f"generation={report['generation_id']} sha={report['git_sha']} "
                f"runner={report['runner_environment']} report={report['report_seal']}"
            )
            return
        missing = [
            name for name, value in (
                ("--artifact-dir", args.artifact_dir),
                ("--expected-sha", args.expected_sha),
                ("--generation-id", args.generation_id),
                ("--artifact-name", args.artifact_name),
                ("--run-id", args.run_id),
                ("--run-attempt", args.run_attempt),
                ("--runner-environment", args.runner_environment),
                ("--runner-os", args.runner_os),
                ("--runner-arch", args.runner_arch),
                ("--runner-name", args.runner_name),
                ("--output-report", args.output_report),
            ) if not value
        ]
        if missing:
            raise CrossHostError("cross-host rehearsal missing: " + ", ".join(missing))
        rehearse(args, policy)
    except (CrossHostError, OSError, ValueError) as exc:
        print(f"CROSS_HOST_RECOVERY_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
