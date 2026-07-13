# Releasing triton

Releases are built and published by the `Release` GitHub Actions workflow
(`.github/workflows/release.yml`) when a `v*` tag is pushed. The workflow
cross-compiles every supported platform, packages each binary, generates a
`SHA256SUMS` manifest, optionally signs it, and uploads everything to the
GitHub release.

The self-updater (`triton --update`) then:

1. downloads `SHA256SUMS`,
2. verifies its ed25519 signature when a signing key is configured,
3. downloads the platform archive and checks it against the manifest, and
4. only then replaces the running binary.

It refuses to install if `SHA256SUMS` is missing, if the checksum does not
match, or (when signing is configured) if the signature is missing or invalid.
It also refuses to downgrade: a release is installed only when its version is
strictly newer.

## One-time signing setup (recommended)

Signing is what protects users against a tampered release, not just a corrupted
download. To enable it:

1. Generate a keypair locally:

   ```
   go run ./scripts/keygen
   ```

   This prints a base64 public key and a base64 private key.

2. Paste the public key into `internal/updater/verify.go`:

   ```go
   const releasePublicKey = "<base64 public key>"
   ```

   Commit that change. With the key set, the updater requires a valid signature
   on every update.

3. Store the private key as a repository secret named `RELEASE_SIGNING_KEY`
   (Settings -> Secrets and variables -> Actions). Keep it out of the repository
   and out of logs.

The release workflow signs `SHA256SUMS` with `scripts/sign` whenever
`RELEASE_SIGNING_KEY` is present, producing `SHA256SUMS.sig`.

## Without signing

If `releasePublicKey` is left empty and no secret is set, releases still ship a
`SHA256SUMS` manifest and the updater still verifies checksums. It prints a
warning that signature verification is not configured. This protects against
corrupted or truncated downloads but not against a maliciously modified release,
so configuring signing is strongly recommended.

## Cutting a release

1. Update `VERSION`.
2. Tag and push:

   ```
   git tag v1.2.3
   git push origin v1.2.3
   ```

3. The workflow publishes the release with all assets, `SHA256SUMS`, and (if
   configured) `SHA256SUMS.sig`.
