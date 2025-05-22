# Release procedure

This document describes WebAuthn4J release procedure.

### Trigger GitHub Actions release workflow

https://github.com/webauthn4j/webauthn4j/actions/workflows/release.yml

It will automatically executes following steps:
1. Create a release commit by updating the `isSnapshot` flag, and versions in documents from the `HEAD` of the `master` branch.
2. Create a release tag
3. Publish to Maven Central

After the release workflow completion, bump-version workflow is automatically triggered, and it will create a commit that bumps to the next patch version.

### Prepare a release note

Write a release note on the GitHub: https://github.com/webauthn4j/webauthn4j/releases

Release note draft can be generated with the following command. 

```
./gradlew generateReleaseNote
```
