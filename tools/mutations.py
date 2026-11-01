#!/usr/bin/env python3
"""Plant one bug at a time in the atom and prove the checks catch it.

A passing smoke suite means nothing if it passes for a broken atom, so each mutation below is a single textual change
to the real source; the atom is rebuilt from the mutated tree and the named case has to fail. If a mutation survives,
the suite has a hole.

    python3 tools/mutations.py
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent.parent
SOURCE = HERE / "src" / "main" / "java" / "com" / "jenkinschina" / "atom" / "jirabuildinfo" / "JiraBuildInfoAtom.java"

MUTATIONS = [
    ("UNSTABLE maps to failed instead of unknown",
     'default -> "unknown";', 'default -> "failed";', "build_status_mapping"),
    ("pipeline id is the project name length, not its hash",
     "String pipelineId = String.valueOf(projectName.hashCode());",
     "String pipelineId = String.valueOf(projectName.length());", "build_basic"),
    ("the JWT outlives the five minutes the app allows",
     'claims.put("exp", iat + 300);', 'claims.put("exp", iat + 3600);', "build_basic"),
    ("the body is sent as application/json instead of application/jwt",
     '.header("Content-Type", "application/jwt")', '.header("Content-Type", "application/json")', "build_basic"),
    ("passed is total - failed, so skipped tests are counted as passed",
     "int passed = Math.max(0, total - failed - skipped);",
     "int passed = Math.max(0, total - failed);", "build_test_info"),
    ("a malformed issue key is forwarded to Jira instead of refused",
     "if (!EXPLICIT_ISSUE_KEY.matcher(candidate).matches()) {",
     "if (false && !EXPLICIT_ISSUE_KEY.matcher(candidate).matches()) {", "build_bad_key_is_refused_locally"),
    ("issue keys keep the order they were typed in instead of being sorted",
     "Set<String> issueKeys = new TreeSet<>();", "Set<String> issueKeys = new LinkedHashSet<>();",
     "build_explicit_keys"),
    ("the environment type is not validated",
     "if (!ENVIRONMENT_TYPES.contains(environmentType)) {", "if (false) {",
     "deployment_environment_is_validated"),
    ("a run with nothing to associate still posts to Jira",
     "if (issueKeys.isEmpty()) {\n                context.log(\"[jira] skipped",
     "if (false) {\n                context.log(\"[jira] skipped", "build_lowercase_branch_is_skipped"),
]


def sdk_jar():
    # a sibling checkout locally, a subdirectory on CI (the workflow checks the SDK out inside the repo)
    for root in (HERE.parent / "jenkins-atom-sdk", HERE / "jenkins-atom-sdk"):
        candidates = sorted((root / "target").glob("jenkins-atom-sdk-*.jar"))
        if candidates:
            return candidates[-1]
    sys.exit("no SDK jar: build ../jenkins-atom-sdk first")


def build(tree):
    env = dict(os.environ)
    env["SDK_JAR"] = str(sdk_jar())
    proc = subprocess.run(["./build.sh"], cwd=tree, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        return None, proc.stderr[-1500:]
    return tree / "dist" / "jira-build-info" / "jira-build-info.jar", proc.stdout


def main():
    failures = 0
    for index, (name, old, new, case) in enumerate(MUTATIONS, 1):
        tree = pathlib.Path(tempfile.mkdtemp(prefix="jibi-mut-")) / "atom"
        shutil.copytree(HERE, tree, ignore=shutil.ignore_patterns("dist", ".git", "__pycache__"))
        source = tree / SOURCE.relative_to(HERE)
        text = source.read_text()
        if old not in text:
            print("SKIP  %s: the mutation no longer matches the source" % name)
            failures += 1
            continue
        source.write_text(text.replace(old, new, 1))
        jar, output = build(tree)
        if jar is None:
            print("SKIP  %s: the mutated atom does not build: %s" % (name, output))
            failures += 1
            continue
        proc = subprocess.run([sys.executable, str(HERE / "tools" / "check.py"), "run", case, "--jar", str(jar)],
                              capture_output=True, text=True, cwd=str(HERE))
        caught = proc.returncode != 0
        print("%s  %s (%s) %s" % ("caught" if caught else "MISSED", name, case,
                                  "" if caught else proc.stdout.strip().splitlines()[:2]))
        if not caught:
            failures += 1
    print("%d/%d mutations caught" % (len(MUTATIONS) - failures, len(MUTATIONS)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
