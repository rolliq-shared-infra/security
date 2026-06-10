# rolliq-shared-infra/security

Canonical security workflows shared across all entity orgs (rolliq-com, cashbucket-com, chargingblindly, klsjapan-com, bpnz).

## Usage

Entity org security repos call these reusable workflows via:

```yaml
uses: rolliq-shared-infra/security/.github/workflows/<name>.yml@main
```

with `secrets: inherit` to pass through org secrets.
