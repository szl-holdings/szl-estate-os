# Cloudflare authentication for the standalone runner

The live Cloudflare baseline and domain redirects were verified on September 24, 2026. The remaining standalone setup requirement is a local credential with the required permissions. The connected Codex Cloudflare identity is a separate transport; its credentials are not exported to this program.

The runner accepts credentials in this order:

1. `CF_API_TOKEN` from the process environment.
2. `CLOUDFLARE_API_TOKEN` from the process environment.
3. The generic Windows Credential Manager record named `SZL/Cloudflare/estate-api-token` belonging to the current Windows user.

An explicitly configured invalid credential fails instead of silently switching identities. The runner reads only its exact named Windows credential. It does not enumerate other credentials, read browser storage, or inspect Codex authentication files.

## Create or select the scoped token

In Cloudflare's **My Profile → API Tokens**, select an existing appropriate token if its value is already available through your approved secret manager, or prepare a custom token with these permissions:

| Cloudflare permission | Why the runner needs it |
|---|---|
| Zone → Zone → Read | Discover and verify the exact target zones. |
| Zone → DNS → Read | Inventory DNS records before reconciling settings. |
| Zone → Zone Settings → Edit | Read and, when necessary, update the three baseline settings. |

Under **Zone Resources**, include only these two specific zones:

- `a-11-oy.com` — `27911fb3d5ed874fdd4e844ed7f5e248`
- `a11oy.net` — `6893093cd089c9994349bc16b0906006`

DNS Edit, Workers permissions, account administration, and token administration are not required for this runner. Optional routing investigations may be unavailable with this minimal token. In that case, an attempted SSL-mode upgrade remains blocked until origin routing can be independently verified. Existing strict SSL settings remain unchanged.

The final token creation and permission grant in Cloudflare is a user-controlled security action. Choose the intended expiry and source-IP restrictions in that flow. Do not paste the token into chat, a command argument, source code, or a report. The program never creates tokens or broadens their grants.

## Store the token securely on this Windows computer

Open an interactive PowerShell terminal in the directory containing `szl_operational.py`. Run:

```powershell
.\configure-cloudflare.ps1
```

The prompt hides the token while you paste it. Setup refuses redirected input or a terminal that would echo the secret. It then:

1. Discovers and verifies both exact zones using the supplied token.
2. Reads each zone's DNS records and all three required settings.
3. Checks that the provider's zone permissions report Zone Settings edit access.
4. Saves the token only after both zones pass validation.
5. Reads the exact Windows credential back to verify local storage without displaying it.

The setup performs no remote writes. Its permission result is explicitly labeled as provider-reported access, not as a witnessed settings mutation. It confirms required access to the two zones; the Cloudflare creation screen is where you restrict the token from accessing any other resources.

Successful setup prints `STORED_VERIFIED` and a credential target name. No token value appears in output. The record is stored with Windows `CRED_PERSIST_LOCAL_MACHINE`, which makes it available to later sessions of the **same Windows user on the same computer**. It does not grant other Windows users access or create a machine-wide environment variable.

If the dedicated record already exists, successful setup replaces only that record. Failed remote validation leaves an existing record untouched. If local storage succeeds but readback fails, setup reports `UNKNOWN_AFTER_ATTEMPT`; inspect that specific credential before retrying. It never reports that uncertain local write as a confirmed save.

## Run without credential environment variables

After setup, these commands automatically read the dedicated Windows credential:

```powershell
.\run-szl.ps1 --providers cloudflare
.\run-szl.ps1 --providers cloudflare --apply
```

Results are written under a new `runs/` directory. Confirm `authentication.source` is `windows_credential_manager`, each requested action is verified, and `blockers` is empty. A credential only enables access; each run still performs fresh provider reads and does not reuse the historical evidence as current state.

Revoke the token in Cloudflare when it is no longer needed. Remove the local entry through **Control Panel → Credential Manager → Windows Credentials**, selecting only `SZL/Cloudflare/estate-api-token`. Local removal and provider revocation are separate operations.

## Current credential discovery result

On September 24, 2026, the supported local checks found no configured Cloudflare API token/key in the process, user, or machine environment. Official Wrangler 4.135.0 reported `loggedIn: false`. Its available OAuth scopes included `zone:read` but did not include DNS or Zone Settings access, so the runner does not start a broad Wrangler login or treat one as sufficient authorization.

This build does not claim a working local authenticated connection until a scoped token has passed setup and a fresh standalone audit succeeds. The offline tests exercise native credential lookup, permission failures, storage ordering, uncertain readback, and the no-environment authentication path using mocks.

References: [Cloudflare API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/), [read zone settings](https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/get/), [edit zone settings](https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/edit/), [Wrangler authentication commands](https://developers.cloudflare.com/workers/wrangler/commands/general/), [Windows CredReadW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw), [Windows CredWriteW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew).
