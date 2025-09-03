import os
import sys
from setuptools_scm import get_version

def main():
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    github_ref = os.environ.get("GITHUB_REF")
    workflow_dispatch_version = os.environ.get("WORKFLOW_DISPATCH_VERSION")
    workflow_dispatch_pre_release = os.environ.get("WORKFLOW_DISPATCH_PRE_RELEASE")

    version = ""
    is_prerelease = ""

    if event_name == "workflow_dispatch" and workflow_dispatch_version:
        version = workflow_dispatch_version
        is_prerelease = workflow_dispatch_pre_release
    elif github_ref and github_ref.startswith("refs/tags/"):
        version = github_ref.replace("refs/tags/v", "")
        is_prerelease = "true" if "-" in version else "false"
    else:
        # Development build
        version = get_version(root="..", relative_to=__file__, local_scheme="dirty-tag")
        is_prerelease = "true"
    
    # GitHub Actions sets GITHUB_OUTPUT as a file path
    with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
        print(f"version={version}", file=fh)
        print(f"is_prerelease={is_prerelease}", file=fh)

    print(f"📋 Version: {version} (Pre-release: {is_prerelease})")

if __name__ == "__main__":
    main()
