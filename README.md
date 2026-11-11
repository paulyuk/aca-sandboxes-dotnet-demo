# Secure .NET tools with Azure Container Apps Sandboxes

Give an agent an untrusted loan application without giving its document tool your model key, internet access, or an Azure identity.

The agent has a model. The tool does not. Both are C#; the tool runs inside a .NET 10 sandbox. The host uses the new Sandbox .NET SDK to create the sandbox, upload files, execute the tool, inspect egress decisions, and clean up.

## Quickstart

Prerequisites: .NET 10 SDK, the current [ACA CLI](https://sandboxes.azure.com/docs/sandboxes/quickstart/setup-cli) configured with your subscription, resource group and region, an existing Azure CLI sign-in, and Copilot CLI available on `PATH`. Model requests use your existing OpenAI-compatible Azure AI Gateway connection, not Copilot's default model.

```bash
git clone https://github.com/paulyuk/aca-sandboxes-dotnet-demo.git
cd aca-sandboxes-dotnet-demo

# Reference an existing host-only file. Do not copy its secrets into the repo.
export DEMO_ENV_FILE=/absolute/path/to/your/existing/.env

dotnet restore
dotnet run -- setup
dotnet run -- model-check
```

The existing environment file must supply `AI_GATEWAY_BASE_URL`, `AI_GATEWAY_MODEL`, and `AI_GATEWAY_API_KEY`. The base URL ends in `/default/models/openai/v1`; this sample uses the gateway's `api-key` header contract. Environment variables override the file. `.env.example` contains empty placeholders.

Setup creates a dedicated `dotnet-demo-<suffix>` group, leaves managed identity disabled, and publishes the package-free tool. It does not change the shared sandbox group or your ACA defaults.

Example output; generated IDs vary:

```text
[group-identity] {"enabled":false}
[setup] {"group":"dotnet-demo-9222f5","region":"eastus2","identity":"disabled"}
[model] {"outcome":"live-response","model":"gpt-mini-latest"}
OK
```

On the Microsoft corporate network, use the configured NuGet source `https://packagefeedproxy.microsoft.io/nuget/v3/index.json`. Normal `dotnet restore` uses that source; no public package download is necessary.

## The stage demo

### 1. Hand the agent a loan application

```bash
dotnet run -- demo samples/loan-application.txt
```

The model calls the single `validate_loan` tool. The host chooses the file and command; the model cannot supply shell commands, paths, network destinations, or identity settings. The raw document stays out of the model prompt.

Example output, with sandbox IDs shortened:

```text
[group-identity] {"enabled":false}
[sandbox-running] {"sandbox":"...","runtime":"dotnet-10","egress":"Deny","elapsedMs":6239}
[runtime] {"sandbox":"...","runtime":".NET 10.0.14"}
[document] {"sandbox":"...","verdict":"approved","reason":"sanitized","rawDocumentReturned":false,"redactions":{"paymentCard":0,"email":1,"ssn":1,"phone":1}}

Stated income: $5,400/month
Vehicle price: $31,500
Down payment: $7,500
Requested loan: $24,000 over 60 months
Illustrative APR: 7.5%
Missing information: employment details, existing debts, monthly expenses...
All statements are unverified and based on sanitized demo data only.

[sandbox-deleted] {"sandbox":"..."}
```

The summary is generated live and varies. `approved` is the document-processing verdict, not a credit decision. The tool redacts demonstrated email, phone, SSN, and payment-card patterns before returning bounded JSON.

### 2. Try to escape through a document

```bash
dotnet run -- security
```

This rejects the adversarial fixture, checks that selected host credential variables and credential-store paths are absent, and runs a separate fixed `HEAD https://example.com/` probe. It sends no document or credential to that site.

Expected success evidence:

```text
[document] {"sandbox":"...","verdict":"rejected","reason":"untrusted-instructions","rawDocumentReturned":false,"redactions":null}
[security-pass] {"sandbox":"...","test":"egress-and-secret-isolation","enforcement":"aca-egress-proxy","host":"example.com","method":"HEAD","path":"/","matchedRule":null,"hostCredentialsPresent":false}
```

A timeout is not a pass. The command must find a matching denied request in the ACA platform's egress decisions. Missing evidence makes the command fail.

### 3. Decide whether sandbox code can mint an Azure token

```bash
dotnet run -- identity
```

This runs MI OFF -> ON -> OFF on the dedicated group, using fresh sandboxes. It restores MI to OFF even when the enabled test fails. It grants no Azure resource roles to the group identity.

Expected success evidence; the rejected status may be 400, 401, or 403:

```text
[identity-pass] {"sandbox":"...","groupMiEnabled":false,"httpStatus":401,"tokenIssued":false,"tokenValue":"[REDACTED]","isolation":{...}}
[identity-pass] {"sandbox":"...","groupMiEnabled":true,"httpStatus":200,"tokenIssued":true,"tokenValue":"[REDACTED]","isolation":{...}}
[identity-pass] {"sandbox":"...","groupMiEnabled":false,"httpStatus":401,"tokenIssued":false,"tokenValue":"[REDACTED]","isolation":{...}}
```

`IDENTITY_ENDPOINT` and `IDENTITY_HEADER` may exist when MI is OFF. Their presence is platform plumbing, not permission to obtain a token. The tool returns only their presence, HTTP status, and whether a token was issued. Neither header nor token value is printed, persisted, or given to the model. A token alone does not demonstrate Azure RBAC access.

## Optional scale finale

Start small:

```bash
dotnet run -- scale 5 5
```

After checking regional capacity, quota, and cost, explicitly opt into the larger batch:

```bash
dotnet run -- scale 100 10
```

The arguments are count and concurrency. The command counts success only after Running state and actual .NET 10 execution. `scale-summary` reports requested count, verified completions, failures, elapsed time, and verified throughput. Partial failures produce a nonzero exit code. This README does not claim that a 100-sandbox batch has been run.

## Traces and cleanup

Each command deletes its own sandboxes. A dedicated group is retained for repeat demos. After an interrupted run:

```bash
dotnet run -- cleanup
```

Cleanup disables the dedicated group's MI and deletes only sandboxes carrying this demo's ownership label. Run commands sequentially so identity changes cannot overlap a document run. Local settings, run manifests, and runtime artifacts are ignored under `.demo/`. The correlated `.demo/trace.jsonl` excludes raw documents, sanitized document text, credentials, and token values. Copilot runtime session history may contain the sanitized tool result; treat `.demo/` as private.

Pattern matching is a limited demonstration, not comprehensive prompt-injection defense, PII detection, or malware scanning. Network enforcement, credential separation, constrained tool access, and identity settings provide distinct boundaries.

## Read the C#

- `SandboxDemo.csproj`: the root console app, so the demo runs directly with `dotnet run`.
- `src/DemoAgent/Agent.cs`: model connection and the one-tool allowlist.
- `src/DemoAgent/Program.cs`: Sandbox SDK lifecycle, upload, execution, security evidence, identity controls, and cleanup.
- `src/LoanTool/Program.cs`: model-free .NET 10 document processor and explicit probes.
- `samples/`: fictional applications, including an adversarial fixture.
- `config/egress-policy.yaml`: equivalent CLI policy for default-deny egress.

Run the local document checks:

```bash
dotnet run -- self-test
(cd src/LoanTool && dotnet run -- self-test)
```

The optional `scripts/demo.sh` wrapper runs the same `dotnet run -- ...` commands.

References: [Sandbox data-plane SDK](https://www.nuget.org/packages/Microsoft.Azure.ContainerApps.Sandbox/1.0.0-beta.1), [App Containers control-plane SDK](https://www.nuget.org/packages/Azure.ResourceManager.AppContainers/1.6.0), [Copilot SDK](https://www.nuget.org/packages/GitHub.Copilot.SDK/1.0.31), [Azure Sandbox samples](https://github.com/Azure-Samples/azure-container-apps-sandboxes).
