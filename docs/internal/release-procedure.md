# Release procedure

This document describes WebAuthn4J release procedure.

### Trigger GitHub Actions release workflow

https://github.com/webauthn4j/webauthn4j/actions/workflows/release.yml

It will automatically executes following steps:
1. Create a release commit by updating the `isSnapshot` flag, and versions in documents from the `HEAD` of the `master` branch.
2. Create a release tag
3. Publish to Maven Central
4. Create a draft GitHub Release with auto-generated changelog and reproducible build instructions (including the exact JDK version used)

After the release workflow completion, bump-version workflow is automatically triggered, and it will create a commit that bumps to the next patch version.

### Review and publish the release note

The release workflow creates a draft release at https://github.com/webauthn4j/webauthn4j/releases.
Review the auto-generated content, edit as needed, then publish it.
