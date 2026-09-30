# Run the SZL maintenance build on Windows

The PowerShell launcher uses the isolated Python installation at `../work/runtime`. It does not require activating a virtual environment or changing the system Python installation. The provider runner remains read-only unless `--apply` is explicitly supplied.

Open PowerShell in the delivery directory and install:

```powershell
Set-Location 'C:\Users\steph\Documents\Codex\2026-09-07\x20-fu\outputs'
.\setup.ps1
.\run-szl.ps1 --help
```

`setup.ps1` creates the virtual environment if it is absent, installs the exact runtime and test dependency versions in `runtime-requirements.lock.txt`, runs `pip check`, and executes the offline regression suite. Bootstrap tools such as pip and setuptools are intentionally excluded from that lock, so setup does not downgrade a newer environment's tooling. Repeated setup runs reuse the existing environment. It does not alter credentials, execution policy, scheduled tasks, or provider configuration.

The setup prefers the installed Python 3.11 launcher, then an existing Python executable, then the local Codex bundled Python. Python 3.11 or newer is required. To select an interpreter explicitly:

```powershell
.\setup.ps1 -PythonPath 'C:\Path\To\Python311\python.exe'
```

After an environment has already passed its tests, `-SkipTests` runs installation and the dependency consistency check without repeating the regression suite.

## Read-only checks

Select one provider or several. Each example below performs an audit:

```powershell
.\run-szl.ps1 --providers github
.\run-szl.ps1 --providers huggingface
.\run-szl.ps1 --providers cloudflare
.\run-szl.ps1 --providers github huggingface cloudflare
```

Every run creates a new timestamped directory under `outputs/runs` containing an `estate-report.md`, `estate-state.json`, and the requested provider reports. Existing delivery evidence is preserved. A custom relative output path is resolved from this delivery directory:

```powershell
.\run-szl.ps1 --providers github --output runs\github-manual-review
```

Use a new custom directory for a new observation if the prior evidence should be preserved.

## Applying reviewed operations

After reviewing a fresh audit, explicitly select apply mode for the needed provider:

```powershell
.\run-szl.ps1 --providers github --apply
.\run-szl.ps1 --providers huggingface --apply
.\run-szl.ps1 --providers cloudflare --apply
```

Apply uses the runner's existing scope checks, provider-specific preconditions, readbacks, and local apply lock. HF changes also use `hf-policy.json`; a changed provider revision must receive a fresh policy review. See `README.md` for the exact supported actions and migration limits.

## Existing logins

The launcher inherits the current process environment and existing official CLI credential caches supported by each provider module. It does not copy tokens into files, print them, or manufacture provider authority.

For GitHub, inspect the authenticated identity through the official CLI:

```powershell
gh api user --jq .login
```

If GitHub is not signed in, use its interactive login flow:

```powershell
gh auth login
```

Hugging Face's official CLI is installed inside this dedicated environment:

```powershell
..\work\runtime\Scripts\hf.exe auth whoami
..\work\runtime\Scripts\hf.exe auth login
```

Use the login command only when a new login is needed.

Cloudflare supports existing environment credentials or the dedicated Windows Credential Manager entry. The [Cloudflare authentication setup](CLOUDFLARE-AUTH-SETUP.md) documents the exact token scope and its validation. To enter a scoped token through the secure interactive prompt:

```powershell
..\work\runtime\Scripts\python.exe -m szl_estate.cloudflare_ops --setup-credential
```

That setup validates the two exact zones before saving the dedicated vault entry. Successful login to a different tool does not itself prove that this runner has the required zone access.

## Exit codes and diagnosis

- `0`: the requested audit or apply completed without a recorded blocker.
- `2`: a provider operation, migration precondition, or existing apply lock requires attention. Read the newly created report before retrying.
- `3`: the launcher could not find the runtime or entry point; run setup or restore the delivery files.
- `130`: the runner was interrupted. Inspect its checkpoint files before retrying an apply.

PowerShell exposes the last result as `$LASTEXITCODE`. A successful maintenance report establishes the reported metadata/configuration operation; it does not certify training, application deployment, runtime quality, or production readiness.

To check the installation without contacting a provider:

```powershell
..\work\runtime\Scripts\python.exe -m pip check
..\work\runtime\Scripts\python.exe -B -m pytest -q
.\run-szl.ps1 --help
```

The exact installed interpreter, dependency-lock digest, test outcome, and read-only launcher observations from installation are recorded in `windows-setup-evidence.json`.
