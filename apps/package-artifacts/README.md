# orcel package artifacts

The `orcel-pkg` Vercel project builds and publishes orcel tarballs to private Vercel Blob using deployment OIDC. Its production domain, `pkg.orcel.dev`, serves both `main` and same-repository pull-request packages.

```text
/main/orcel.tgz
/main/latest.json
/pr/<number>/orcel.tgz
/pr/<number>/latest.json
/<full-sha>/orcel.tgz
```

Initialize an agent from the current `main` build with:

```bash
npm exec --yes --package=https://pkg.orcel.dev/main/orcel.tgz -- orcel init my-agent
```

A same-repository pull-request build is available after its **Vercel – orcel-pkg** deployment succeeds, including when the pull request targets another branch in a stack. Fork pull requests and direct branch deployments never build or publish package artifacts. For example:

```bash
npm exec --yes --package=https://pkg.orcel.dev/pr/123/orcel.tgz -- orcel init my-agent
```

Both moving routes redirect to an immutable `/<sha>/orcel.tgz` artifact. The packaged CLI also stamps that immutable URL into generated projects.

## Publishing

Vercel deploys `main` to Production and same-repository pull requests to Preview. The build derives the source SHA and PR number from Vercel system environment variables, packages orcel, verifies that the source still represents the current branch or pull-request head, and writes the following objects:

```text
packages/<sha>/orcel.tgz
packages/<sha>/manifest.json
packages/refs/main.json
packages/refs/pr/<number>.json
```

SHA objects are immutable. Main and PR pointer objects are mutable and short-cached.

The build requires `VERCEL_OIDC_TOKEN` and `BLOB_STORE_ID` and passes them explicitly to the Blob SDK. It does not accept or use a static Blob write token.

## Project setup

The `orcel-pkg` Vercel project must:

- use this directory as its project root;
- enable Vercel system environment variables and OIDC;
- connect the private package Blob store to Production and Preview;
- deploy `main` to Production;
- omit `BLOB_READ_WRITE_TOKEN` from Production and Preview;
- disable Deployment Protection so package managers can reach the production proxy; and
- use the following trusted Ignored Build Step:

```sh
if [ "$VERCEL_ENV" = "production" ]; then
  test "$VERCEL_GIT_COMMIT_REF" != "main"
else
  test "$VERCEL_ENV" != "preview" ||
    test "$VERCEL_GIT_REPO_OWNER" != "vercel" ||
    test "$VERCEL_GIT_REPO_SLUG" != "orcel" ||
    test -z "$VERCEL_GIT_PULL_REQUEST_ID"
fi
```

Vercel interprets exit code `0` as “skip this build.” The command therefore permits only production `main` and same-repository PR Preview deployments, rejecting forks before dependency installation. The build repeats the repository and deployment checks as defense in depth.

Same-repository PR code runs with package-store OIDC access during its Preview build. This is acceptable only while write access to `vercel/orcel` is restricted to trusted employees. The Blob store must remain package-only and must not contain unrelated application data.

The smoke check verifies public access and the downloaded main artifact's gzip signature.
