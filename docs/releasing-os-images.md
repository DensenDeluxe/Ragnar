# Releasing the Ragnar OS images

The **Release OS images** workflow (`.github/workflows/release-os-images.yml`) is a
one-click, manually-triggered pipeline that cuts a fresh release of the Ragnar OS
images — the standard (defensive) edition and the Ulfberht (offensive) edition —
and follows each build through to a published, downloadable release.

It lives in this **public** repo on purpose: anyone with write access here (for
example a collaborator such as `solarflere`) can start a release from the Actions
tab without needing direct access to the private build repo.

## How to run it

1. Open **Actions ▸ Release OS images ▸ Run workflow**.
2. Pick the options (all have sensible defaults):

   | Input | Default | Meaning |
   |---|---|---|
   | `which` | `both` | Release `both` images, or just `standard` / `ulfberht`. |
   | `bump` | `minor` | How to bump each edition's version: `minor` (1.7.0 → 1.8.0), `patch` (→ 1.7.1) or `major` (→ 2.0.0). Ignored for an edition where you type an explicit version. |
   | `std_version` | *(blank)* | Explicit standard version, e.g. `1.8.0`. Blank = auto-bump from the latest `os-v*` release. |
   | `ulf_version` | *(blank)* | Explicit Ulfberht version, e.g. `1.5.0`. Blank = auto-bump from the latest `os-ulfberht-v*` release. |
   | `dry_run` | `false` | Only print the versions it *would* release, create no tags. Handy to double-check the numbers **and to confirm the cross-repo token is healthy** before committing to a ~3-hour release. |

3. Click **Run workflow** and watch it. The run page (and its summary) shows the
   planned tags, links to each build on the private runner, and the final result.

> **Tip:** run it once with `dry_run` ticked first. The very first step validates
> `RAGNAROS_DISPATCH_TOKEN` and prints a table showing the token owner, that it can
> reach RagnarOS, that it holds **Contents: write** + **Actions: read**, and **when
> it expires** — so you catch an expired or under-scoped token in seconds instead of
> part-way through a real release.

## What happens under the hood

```
Actions tab (this repo)
   │  workflow_dispatch
   ▼
Release OS images
   │  0. validate RAGNAROS_DISPATCH_TOKEN (present, unexpired, Contents:write + Actions:read)
   │  1. compute next versions (or use your overrides)
   │  2. create tags  os-v<X.Y.Z>  and  os-ulfberht-v<X.Y.Z>  in PierreGode/RagnarOS
   ▼
RagnarOS build workflows (tag-triggered, self-hosted Pi runner)
   │  build image → upload to ragnar.life → publish GitHub Release here
   ▼
Release OS images (same run, still watching)
   │  3. wait for both builds, verify the release + ragnar.life manifest
   │  4. mark the standard release as "Latest"
   ▼
Done — images live at https://ragnar.life/ and on the Releases page
```

The image builds themselves are defined in the private `PierreGode/RagnarOS` repo
(`build-os-image.yml` / `build-ulfberht-image.yml`). They fire on a tag push, build
natively on the self-hosted `ragnar-os-builder` runner (the project's Raspberry Pi),
upload the `.img.xz` to ragnar.life, and publish the GitHub Release back onto this
repo. This pipeline just creates the tags and babysits the result.

## One-time setup — the cross-repo token

This repo has no access to the private RagnarOS repo by default, so the pipeline
needs a Personal Access Token stored as a repo secret named
**`RAGNAROS_DISPATCH_TOKEN`**:

- **Fine-grained PAT** (recommended) — resource owner `PierreGode`, repository
  `RagnarOS`, permissions **Contents: Read and write** + **Actions: Read**.
- or a **classic PAT** with the `repo` scope.

Add it under **Settings ▸ Secrets and variables ▸ Actions ▸ New repository secret**.
Until it exists, the pipeline stops on its first step with a clear error.

The pipeline's first step **validates this token on every run** (dry runs included)
and fails fast with a specific message if it is missing, **expired**, cannot reach
RagnarOS, or is missing **Contents: write** or **Actions: read** — so a stale or
under-scoped PAT is caught up front rather than mid-release. A near-expiry token
(≤ 7 days left) passes with a warning so you have time to rotate it.

## Prerequisites for a build to actually run

- The self-hosted **`ragnar-os-builder`** runner (the Pi) must be powered on with
  its Actions runner service running. If it is offline the builds queue and the
  pipeline eventually times out (it waits up to ~5¾ hours).
- The private repo's **`RAGNAR_RELEASE_TOKEN`** secret must be valid — that is what
  the build uses to publish the Release and upload to ragnar.life (already set up).

## Notes

- The two images version **independently** (standard is currently ahead of Ulfberht),
  so each is bumped from its own latest release.
- Builds share the single Pi runner, so they run **back-to-back**, not in parallel —
  expect roughly 2½–3 hours for both.
- The standard edition is deliberately kept as the **Latest** release; Ulfberht
  publishes last and would otherwise take the badge.
- Re-running with a version that already has a tag fails fast ("tag exists") — bump
  to a higher number.
