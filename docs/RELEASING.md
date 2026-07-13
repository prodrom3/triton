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
download. Generate the key yourself in a trusted environment; do not let a third
party generate your signing key.

Order matters: enabling verification (`releasePublicKey`) before a signed
release exists would make `--update` refuse the current, unsigned "latest"
release. Follow these steps in order so `--update` never breaks.

1. Generate a keypair locally, writing the private key straight to a file so it
   never lands in your shell history:

   ```
   go run ./scripts/keygen -priv-out release-signing.key
   ```

   The public key prints to stdout; the private key is written to
   `release-signing.key`.

2. Store the private key as a repository secret named `RELEASE_SIGNING_KEY`
   (Settings -> Secrets and variables -> Actions), then delete the local file:

   ```
   gh secret set RELEASE_SIGNING_KEY < release-signing.key
   rm release-signing.key
   ```

   The release workflow now signs `SHA256SUMS` with `scripts/sign` on every
   release, producing `SHA256SUMS.sig`. Verification is not yet enforced, so
   `--update` keeps working.

3. Cut a release (see below). Because the secret is set, this release is signed.

4. Now enforce verification: paste the public key into
   `internal/updater/verify.go` and commit it.

   ```go
   const releasePublicKey = "<base64 public key>"
   ```

   From this point the updater requires a valid signature. Because the latest
   release (step 3) is already signed, `--update` continues to work, and any
   tampered or unsigned release is rejected.

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
