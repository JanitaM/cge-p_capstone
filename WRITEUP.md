# Acme Health GRC Capstone: Write-up

Acme Health has a small patient intake API on AWS. It works, but it was built with eight known
compliance gaps (listed in [GAPS.md](GAPS.md)). My job was not to rebuild it. It was to make it
defensible in an audit, and to make that provable on every code change.

I did this with four layers: Terraform fixes, Rego policies that block bad changes, a GitHub
Actions pipeline that signs its evidence, and an OSCAL file that traces each control to that
evidence.

## Framework choice

I chose **SOC 2**, the security audit standard most software companies are asked to pass.

- **It is widely used.** Almost every software, fintech and security company asks vendors about
  SOC 2. HIPAA would tie this project to healthcare only.
- **It fits what I built.** SOC 2 Type II is about controls that keep working over time. A
  pipeline that signs evidence on every push is exactly that kind of proof.
- **The healthcare app is only an example.** The gaps and controls are the same for any
  workload. The point of this project is the evidence pipeline, not the patient data.

## Gap remediation

The brief asks for at least five gaps closed with depth. I closed six with Terraform, and
five of those also have a policy that blocks the gap from coming back. The other two are
documented, not fixed.

| Gap | What was wrong | How it was closed | Blocked by policy | OSCAL control |
|---|---|---|---|---|
| GAP-01 | Uploads bucket used AWS's default encryption, not my own key | Encrypted with my own KMS key (`uploads-bucket-kms-encryption.tf`) | `cc61_s3_kms` | sc-28 |
| GAP-02 | Database used AWS's default key | Same KMS key, through the `dynamodb-table` module (`dynamodb-submissions.tf`) | `cc61_dynamodb_kms` | sc-28 |
| GAP-03 | Bucket allowed unencrypted (non-HTTPS) requests | Bucket policy that denies them (`uploads-bucket-policy.tf`) | `cc67_s3_tls_deny` | sc-8 |
| GAP-04 | Bucket had no versioning, so overwrites could not be undone | Versioning turned on (`uploads-bucket-versioning.tf`) | None (see below) | cp-9 |
| GAP-05 | Lambda ran outside the private network | Lambda moved into the private subnets with a locked-down security group (`lambda-vpc-config.tf`) | `cc66_lambda_vpc` | sc-7 |
| GAP-06 | No reserved concurrency, dead-letter queue or tracing | **Not fixed.** Documented in OSCAL as a known gap | None | si-4 (planned) |
| GAP-07 | Lambda role allowed `dynamodb:*` and `s3:*` | Replaced with a role that lists only the actions it needs (`lambda-iam-role.tf`) | `cc63_lambda_iam_least_privilege` | ac-6 |
| GAP-08 | API had no logging, throttling or firewall | **Not fixed.** Documented in OSCAL as a known gap | None | si-4 (planned) |

Terms used above:
- **KMS key:** an encryption key in AWS that I control, and can rotate or turn off. Rotation is on.
- **Rego / Conftest:** Rego is a policy language. Conftest runs my Rego policies against the
  Terraform plan before anything is built.
- **OSCAL:** a standard file format that says which control is met, by which resource, with what
  evidence. Mine is in `oscal/components/acme-health-intake.json`.

**Why the layers differ.** GAP-04 has no policy because there is no useful "bad change" to test.
It is one setting, and the fix is either there or not. GAP-06 and GAP-08 are documented in OSCAL
rather than fixed. I chose depth on five controls over shallow coverage of all eight, as
GAPS.md allows. One detail worth knowing for GAP-08: AWS's firewall (WAF) cannot attach to this
kind of API (an HTTP API), so closing that part means changing the API type or putting
CloudFront in front of it.

**Other Terraform I added:** an evidence vault (an S3 bucket the pipeline uploads to),
CloudTrail (an AWS audit log), and the GitHub login setup the pipeline uses (no stored AWS
passwords). The evidence vault and database come from my own module library,
[infra-modules](https://github.com/JanitaM/infra-modules). I first extended two of its modules
(tagged `v1.25.0`) so they could take my KMS key.

## What I found first

Before changing anything, I checked the starter against GAPS.md. All eight gaps were really
there, and I found nothing extra. The starter is small, and every resource is either one of the
eight gaps or plain supporting setup.

The live apply then caught two mistakes of mine. My notes said GAP-01 and GAP-04 were closed,
but they were not:

- **GAP-01:** the KMS key was wired into the evidence vault and the database, but never into
  the uploads bucket, which is the one the gap is about.
- **GAP-04:** the versioning fix was on a branch that never got merged into `main`.

I found both by checking the live resources instead of trusting my notes. I fixed them (PR #8 and
PR #9), applied again, and confirmed there was no drift. The first apply created 45 resources,
the second added 2 more, and a plan afterwards showed no changes. The lesson: "merged" and
"marked done" are not proof. Only the live system is.

## Proof the gate works

The pipeline is `.github/workflows/grc-gate.yml`. It runs five steps in order: plan, policy
check, apply, sign, upload. Apply, sign and upload only run after a merge to `main`.

- **Green PR (#12), merged.** After the merge, run `35371787746` passed every step. It applied
  the changes, signed the evidence bundle, and uploaded it to the vault.
- **Red PR (#13), not merged.** It changes one file and puts the uploads bucket back on default
  encryption (GAP-01). The check failed at the policy step with:
  `GAP-01 (SOC2-CC6.1): S3 bucket "aws_s3_bucket.uploads" is not encrypted with SSE-KMS using a customer-managed key`.
  I left the PR open on purpose, as the permanent record.
- **PR #11** was an earlier throwaway test of the same idea. It is closed and not the proof.

Signing uses **Cosign** in keyless mode: GitHub proves who is running the workflow, and Sigstore
issues a short-lived certificate. There is no signing key for me to store or lose. Anyone can
check the signature against the public Sigstore log.

## Design trade-offs

**One shared KMS key, not one per resource.** One key is simpler to manage and explain. The
cost is that if it is misused or disabled, everything it protects is affected. In production I
would use a separate key for each resource. Here the smaller setup is fine.

**One AWS account, not a separate account for the evidence vault.** A separate account would
protect the evidence even if the workload account were compromised. The brief allows one account
for 30 days, and this is a sandbox with no real data. A real system should use two.

**Object Lock in governance mode, not compliance mode.** Governance mode blocks deletes and
overwrites for 90 days, but a user with special permission can override it. Compliance mode
cannot be overridden by anyone, including me. SOC 2 does not require compliance mode, and
governance mode is safer to experiment with. A real audit trail should probably use compliance
mode.

**Apply on merge, with no manual approval step.** The policy check on the PR is the real
control. A human clicking "approve" afterwards would add delay without adding much protection
for a solo project. A team with more than one person would likely want the second check. If a
bad apply happens, I fix it with a revert PR that goes through the same gate.

## AI use

I used Claude Code (Anthropic's AI coding tool) throughout this project. It helped write the
specs, Terraform, Rego policies, pipeline, OSCAL file and this write-up. I directed the work,
reviewed the output, ran the tests, checked the live resources, and can explain how each part
works. The spec files that record this process are kept locally in `context/`, which is not
committed.

## Honest limits

- **A real SOC 2 audit would flag CC7.2 as an exception.** CC7.2 is about monitoring for
  problems. GAP-06 and GAP-08 mean nothing here watches for or alerts on anomalies. The OSCAL
  file says this directly and marks the control `planned`, not `implemented`.
- **CloudTrail is not monitoring.** It records what happens, which is useful input for
  monitoring, but nothing reads it or raises an alarm. I chose not to claim it as an
  implemented control for CC7.2, because that would overstate what is in place.
- **Type II needs months, not one apply.** A Type II report checks that controls worked over a
  period, usually six to twelve months. This project shows one apply and a handful of signed
  runs. It shows the mechanism, not the track record.
- **Two of my checks run only on my machine.** `test/oscal_component.sh` needs live AWS access
  and Cosign. `make validate-oscal` needs `trestle` (the OSCAL validation tool) and internet.
  Neither is in the pipeline, so a broken evidence link or an OSCAL format error would not be
  caught by CI.
- **Patient data lifecycle is not covered.** Deleting or exporting a patient's data on request
  is a real requirement, and nothing here handles it.

## With another sprint

- Close GAP-06 and GAP-08: dead-letter queue, tracing, alarms, API logging and throttling.
- Add a real alerting process, so CC7.2 can move from `planned` to `implemented`.
- Give each resource its own KMS key.
- Move the evidence vault to a separate AWS account.
- Switch Object Lock to compliance mode.
- Run the OSCAL checks in the pipeline.
- Add a plan for patient data deletion and export.

## What didn't get done

- GAP-06 and GAP-08 are not fixed. They are documented only.
- GAP-04 has no policy that blocks it from coming back.
- The OSCAL checks are not in CI.
- Patient data deletion and export are not handled.
- CC7.2 has no working monitoring, so it would fail an audit today.

## Teardown plan

When I am done, I will destroy the workload (the API, Lambda, database and uploads bucket).
I will keep the **evidence vault, the KMS key and the Terraform state bucket** until grading is
finished. The OSCAL file links to specific signed objects in the vault, and those objects are
encrypted with the KMS key. If either is deleted, the links stop working and the evidence cannot
be checked. The vault's 90-day Object Lock runs until about 2026-12-17.
