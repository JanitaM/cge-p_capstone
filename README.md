# Acme Health GRC Capstone

> Patient Intake API for "Acme Health", wrapped in four GRC layers. A fork of `cgep-app-starter` for the **CGE-P capstone**. Primary framework: **SOC 2**.

## What this is

A minimal AWS workload: VPC, Lambda, API Gateway, DynamoDB, S3. It ingests patient intake submissions over HTTPS. The starter shipped with eight known compliance gaps ([GAPS.md](GAPS.md)). This repo makes it audit-defensible with four layers:

1. **Terraform baseline** (`terraform/`): KMS key, Object Lock evidence vault, CloudTrail, and fixes for six gaps.
2. **Rego policies** (`policies/`): five policies that block a change that brings a gap back.
3. **Pipeline** (`.github/workflows/grc-gate.yml`): plan, policy check, apply, sign with Cosign, upload to the vault.
4. **OSCAL** (`oscal/`): a component and profile tracing each control to a Terraform resource and to signed evidence.

The reasoning, trade-offs and honest gaps are in [WRITEUP.md](WRITEUP.md).

## Run the tests

| Command | What it proves | Needs |
|---|---|---|
| `opa test ./policies` | The five policies pass their pass/fail tests | Nothing |
| `make validate-oscal` | The OSCAL files are valid and the profile resolves against the NIST catalog | `trestle`, internet |
| `make test` | The deployed API accepts an intake submission | AWS, workload deployed |

`make test` stops working once the workload is destroyed (see the teardown plan in the write-up), so the first two always work.

## Verify the evidence

Every merge to `main` produces a signed bundle in the Object Lock vault. The vault is private, so its evidence for one run is pulled into [evidence/35371787746/](evidence/35371787746/) by `scripts/pull-evidence.sh`. That is the run the write-up and the OSCAL evidence links point to. To check it, no AWS needed:

```bash
scripts/verify-evidence.sh 35371787746
```

```
PASS: SHA-256 matches the .sha256 file and receipt.json (147c19f2...)
PASS: Cosign signature verifies (signer: https://github.com/JanitaM/cge-p_capstone/.github/workflows/grc-gate.yml@refs/heads/main)
PASS: retention: Object Lock GOVERNANCE, retained until 2026-12-17T17:01:04.386000+00:00

CHAIN INTACT for run 35371787746
```

The three checks:
- **SHA-256:** the bundle's hash matches the `.sha256` file and `receipt.json`.
- **Cosign:** the signature verifies against the exact workflow that signs (this repo's `grc-gate.yml` on `main`), through GitHub's OIDC identity and the public Sigstore log.
- **Retention:** `retention.json` shows the bundle is under Object Lock until a date still in the future.

Needs `cosign`, `jq` and `shasum`. The signature and the hash can be re-checked by anyone. `retention.json` is S3's own answer, saved when the bundle was pulled. The 90-day lock ends on 2026-12-17, after which the retention check fails by design. `test/verify_evidence.sh` shows the verifier also fails on a changed bundle, an expired retention date, and an unknown run.

## Where the proof is

- Green PR, gate passed and merged: [#12](https://github.com/JanitaM/cge-p_capstone/pull/12)
- Red PR, gate blocked it (reintroduces GAP-01): [#13](https://github.com/JanitaM/cge-p_capstone/pull/13)
- OSCAL: [component](oscal/components/acme-health-intake.json) and [profile](oscal/profiles/acme-health-soc2.json)
- Pulled evidence: [evidence/35371787746/](evidence/35371787746/)

## The deploy gate

The pipeline applies on merge to `main`. To deploy by hand you need your own AWS account, and the Terraform state backend in `terraform/main.tf` names this project's state bucket, so change that first.

```bash
git clone https://github.com/JanitaM/cge-p_capstone
cd cge-p_capstone

# Confirm you're authenticated to the right account:
make creds AWS_PROFILE=<your-sandbox-profile>

make deploy AWS_PROFILE=<your-sandbox-profile>
make test    AWS_PROFILE=<your-sandbox-profile>
```

> **AWS SSO note:** if your profile is SSO-based, Terraform's AWS provider can fail to read it directly with `failed to find SSO session section`. The Makefile's `eval $(aws configure export-credentials)` pattern handles this. If you're running `terraform` commands by hand, do the same export first.
>
> **`aws login` note:** a `default` profile created via the newer `aws login` (device-flow) command stores a `login_session` key in `~/.aws/config` instead of a standard `sso_session`. The AWS CLI reads it fine, but Terraform's AWS provider credential chain doesn't recognize that key and fails with `No valid credential sources found`. Use a classic `sso_session`-based profile for `terraform` commands instead (e.g. `AWS_PROFILE=<sso-profile> terraform plan`).

Expected output of `make test`:

```json
{
    "submission_id": "f1e3...",
    "status": "received"
}
```

When you're done exploring: `make destroy`.

## Cost

The base workload is roughly $0 if destroyed within an hour: Lambda, API Gateway, DynamoDB and S3 are pay-per-use. The baseline adds about $1 a month for the KMS key and about $7 a month for the CloudWatch Logs VPC endpoint, plus cents for CloudTrail and the evidence vault.

## Layout

```
.
├── README.md            # this file
├── WRITEUP.md           # design reasoning, trade-offs, honest gaps
├── WORKLOAD.md          # what the API does
├── GAPS.md              # the eight named flaws
├── FRAMEWORKS.md        # HIPAA / SOC 2 / CMMC mapping primer
├── Makefile             # make deploy | test | destroy | validate-oscal
├── terraform/           # starter workload + GRC baseline
├── policies/            # Rego policies and their tests
├── oscal/               # component definition and profile
├── evidence/            # pulled, signed evidence bundle(s)
├── scripts/             # validate-oscal, pull-evidence, verify-evidence
├── test/                # shell tests (intake, OIDC, state, OSCAL, evidence)
└── .github/workflows/   # grc-gate.yml
```

## License

MIT. Fork freely. Submissions remain learners' own work.
