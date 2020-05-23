# Release procedure

This document describes WebAuthn4J release procedure.

### Prepare a release commit

##### Create a release branch

```
git checkout -b release-<version>
```

##### Update version variables in build.gradle

gradle.properties
```
webAuthn4JVersion=<version>.RELEASE
latestReleasedWebAuthn4JVersion=<version>.RELEASE
```

##### Update versions in documents

```
./gradlew updateVersionsInDocuments
```

##### Create a release commit

```
git commit -a -m "Release <version>.RELEASE"
```

##### Push the release branch

```
git push origin release-<version>
```

##### Create a pull request

create a pull request with following title: `Release <version>.RELEASE`

##### Check the build status & Merge the pull request

Check the build status & merge the pull request.

### Prepare a release tag

##### Prepare a release note

generate a release note draft

```
./gradlew generateReleaseNote
```

update the release note draft (`build/release-note.md`) properly with your editor.

##### Create a release tag

```
git tag <version>.RELEASE
```

### Ship the release

##### Push the release tag

```
git push origin <version>.RELEASE
```

##### Retry maven central sync (if release job failed)
Sometimes release job invoked by tag push fails because of some files are not signed by bintray.
Following command resolves GPG signing problem and syncs to Maven Central.

```
BINTRAY_USER=<BINTRAY_USER> BINTRAY_TOKEN=<BINTRAY_TOKEN> ./gradlew bintrayGpgSign bintrayMavenCentralSync
```

##### Update the release note on GitHub

Update the release note on GitHub

### Declare new version development start

##### Create a branch

```
git checkout -b <new version>-development
```

##### Update version variables in build.gradle

gradle.properties
```
webAuthn4JVersion=<new version>-SNAPSHOT
latestReleasedWebAuthn4JVersion=<version>.RELEASE
```

##### Commit the change

 ```
git commit -a -m "Start <new version> development"
 ```
 
##### Push the release branch

```
git push origin <new version>-development
```

##### Check the build status

Check the build status before continue.

##### Merge the pull request

merge the pull request and delete the branch.
