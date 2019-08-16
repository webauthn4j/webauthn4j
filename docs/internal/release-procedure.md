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

##### Check the build status

Check the build status before continue.

### Prepare a release tag

##### Prepare a release note

generate a release note draft

```
./gradlew generateReleaseNote
```

update the release note draft (`build/release-note.md`) properly with your editor.

##### Create a release tag

```
git tag -a <version>.RELEASE -F build/release-note.md
```

### Ship the release

##### Push the release tag

```
git push origin <version>.RELEASE
```

### Declare new version development start

##### Update version variables in build.gradle

gradle.properties
```
webAuthn4JVersion=<new version>-SNAPSHOT
latestReleasedWebAuthn4JVersion=<version>.RELEASE
```

##### Update versions in documents

```
./gradlew updateVersionsInDocuments
```

##### Commit the change

 ```
git commit -a -m "Start <new version> development"
 ```

##### Merge the pull request

merge the pull request and delete the branch.
