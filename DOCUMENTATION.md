# Extreme Value Risk Analytics Platform: Written Deliverables

## A. One-Page Threat Model and Security Checklist

**System:** FastAPI (Azure App Service) -> Azure SQL Database + Azure Blob Storage; Power BI reads Azure SQL.
**Assets to protect:** user credentials, JWT signing key, uploaded returns data, risk metrics integrity, DB/Blob secrets.
**Trust boundaries:** Internet -> API; API -> Azure SQL; API -> Blob Storage; Power BI -> Azure SQL.
**Actors:** Quant (read/write), Viewer (read-only), anonymous attacker, malicious insider with a Viewer token.

### Threats (STRIDE) and mitigations

- **Spoofing**
  - Threat: credential stuffing, stolen or forged JWT, "alg: none" token.
  - Mitigation: bcrypt (cost 12), JWT signature verified with a pinned HS256 algorithm, 30-minute expiry, generic 401 message, dummy-hash verification for unknown users.
- **Tampering**
  - Threat: SQL injection through CSV cells, ticker or username fields; tampering with stored metrics.
  - Mitigation: parameterised queries only (`?` placeholders), allow-list regex and type validation (ASCII ISO date, strict float, range -1 < r < 1), `sp_LogRiskCalculation` is the only write path to `RiskMetrics`, DB CHECK/FK/UNIQUE constraints as a second line of defence.
- **Repudiation**
  - Threat: a user denies uploading data or running a calculation.
  - Mitigation: `UploadedBy` / `CalculatedBy` foreign keys with UTC timestamps, immutable raw CSV in Blob with SHA-256 and uploader metadata, application logging.
- **Information disclosure**
  - Threat: leaked secrets, plaintext passwords, verbose errors, public blobs, interception.
  - Mitigation: secrets only in environment variables / Key Vault, hash-only password storage, private blob container, `Encrypt=yes` to SQL, HTTPS + HSTS, error messages never echo user input, `Cache-Control: no-store`.
- **Denial of service**
  - Threat: huge uploads, request floods, expensive calculations.
  - Mitigation: 5 MB / 20,000-row caps, capped query `limit`, bounded O(n log n) calculation. Rate limiting is applied at the Azure edge (see "Planned" below).
- **Elevation of privilege**
  - Threat: a Viewer calling Quant endpoints; over-privileged DB account.
  - Mitigation: server-side `require_role()` on every route (403 otherwise), role read from a signed token, DB service account limited to the `app_runtime` role (no DDL, no direct write to `RiskMetrics`).
- **XSS**
  - Threat: script payloads in CSV, asset names or usernames that are later rendered.
  - Mitigation: values are converted to `date` / `float` or matched against character allow-lists, raw cell content is never reflected in responses, JSON-only API, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`. Any frontend must still output-encode.

### Security checklist

**Completed (implemented in code):**
- [x] Passwords hashed with bcrypt before storage; 72-byte bcrypt limit enforced
- [x] JWT with expiry, pinned algorithm, role claim; RBAC enforced server-side (Quant vs Viewer)
- [x] 100% parameterised SQL; no string-concatenated queries
- [x] Upload validation: extension + content type, size cap, UTF-8 check, header check, per-cell regex + `float`/`date` conversion, `isfinite` and range checks, duplicate-date check, row cap
- [x] DB credentials and JWT secret loaded from environment variables; start-up fails fast if missing or weak
- [x] TLS to Azure SQL (`Encrypt=yes`, `TrustServerCertificate=no`)
- [x] Least-privilege SQL role (`app_runtime`) and stored-procedure-only writes to `RiskMetrics`
- [x] Atomic transactions with rollback for batch inserts
- [x] Security headers, explicit CORS allow-list, API docs disabled when `ENV=production`
- [x] Audit columns (who/when) and raw-file archive with SHA-256 in Blob

**Planned / configured in Azure (outside the code):**
- [ ] Store secrets in Azure Key Vault and reference them from App Service settings
- [ ] Rate limiting and WAF (Azure Front Door / API Management); login lockout
- [ ] Azure SQL firewall + private endpoint; Microsoft Defender for SQL; auditing on
- [ ] Blob lifecycle rule to expire unparsed or rejected raw files; soft delete enabled
- [ ] Managed identity for Blob access (code already supports `AZURE_STORAGE_ACCOUNT_URL`)
- [ ] HTTPS-only on App Service, TLS 1.2+ minimum
- [ ] `pip-audit` / Dependabot in CI

---

## B. DP-900: Data Classification and Power BI Configuration

### Classification of the application's data

- **Structured (relational, Azure SQL Database):** `Users`, `Roles`, `Assets`, `DailyReturns`, `RiskMetrics`. Fixed schema, typed columns, PK/FK/CHECK constraints, schema-on-write, queried with T-SQL. This is the transactional and analytical source of truth.
- **Non-relational / unstructured object storage (Azure Blob Storage):** the raw uploaded CSV files. The CSV *content* is tabular delimited text, but Blob Storage treats each file as an opaque binary object (no enforced schema, no SQL querying), so it is stored in the non-relational object store. Its value is as an immutable audit/replay copy.
- **Workload types:** OLTP for uploads and metric logging (small, atomic, concurrent writes); analytical (OLAP-style) for Power BI reading `RiskMetrics`.

### Power BI configuration to compare Gaussian VaR vs Hill VaR

1. **Get data:** Azure SQL Database connector, server `<server>.database.windows.net`, database `evt_risk`. Use a **read-only** SQL login (SELECT only). Select `RiskMetrics` and `Assets` (optionally `DailyReturns`).
2. **Storage mode:** *Import* (small data, fast visuals, schedule a refresh in the Power BI Service via a gateway or cloud connection). Use *DirectQuery* only if near-real-time is needed.
3. **Model:** relationship `Assets[AssetID]` 1 -> * `RiskMetrics[AssetID]`, single direction. Set `ConfidenceLevel` to Percentage, `GaussianVaR` and `HillVaR` to Percentage with 2 decimals, `HillXi` to Decimal (3 places).
4. **DAX measures:**
   - `Gaussian VaR = AVERAGE(RiskMetrics[GaussianVaR])`
   - `Hill VaR = AVERAGE(RiskMetrics[HillVaR])`
   - `Gaussian Underestimation % = DIVIDE([Hill VaR] - [Gaussian VaR], [Hill VaR])`
   - `Avg Tail Index xi = AVERAGE(RiskMetrics[HillXi])`
5. **Visuals:**
   - Clustered column chart: Axis = `Assets[Ticker]`, Values = `Gaussian VaR` and `Hill VaR` (side-by-side comparison).
   - Line chart: Axis = `RiskMetrics[CalculatedAt]` (or `WindowEnd`), Values = both VaR measures.
   - Cards: `Gaussian Underestimation %` and `Avg Tail Index xi`.
   - Table: Ticker, ConfidenceLevel, SampleSize, TailK, both VaRs.
6. **Slicers (important):** `ConfidenceLevel` as a single-select slicer. Only compare VaR numbers at the *same* confidence level. Add `Assets[Ticker]` and a date slicer.
7. **Security:** publish to a workspace and give Viewers the *Viewer* workspace role (or share via an app). Add row-level security only if assets must be restricted per user.

---

## C. System Design

### Functional requirements
- Authenticate users and issue a JWT carrying a Quant or Viewer role.
- Quant users can register users, create assets, and upload daily-return CSVs for an asset.
- Archive each raw CSV in Azure Blob Storage before parsing, then validate it and store the returns in Azure SQL in one transaction.
- Quant users can trigger a risk calculation per asset and confidence level: Gaussian VaR, Hill tail index xi, and EVT (Hill/Weissman) VaR.
- Persist every calculation (with parameters and timestamp) in `RiskMetrics` via `sp_LogRiskCalculation`.
- Quant and Viewer users can list assets, view stored risk metrics, and view the worst-5% losses (`vw_ExtremeLosses`).
- Expose metrics to Power BI for Gaussian-vs-Hill comparison dashboards.

### Non-functional requirements
- **Security:** bcrypt, JWT, RBAC, parameterised SQL, strict input validation, TLS everywhere, secrets outside source control.
- **Performance:** a 10-year calculation (about 2,520 rows) in under 1 s server-side; a composite covering index on `DailyReturns (AssetID, TradeDate)`; upload of 5 MB in under 5 s.
- **Reliability and integrity:** atomic batch inserts with rollback, UNIQUE (asset, date), CHECK/FK constraints, raw-file archive for replay.
- **Scalability:** stateless API (JWT) so it can scale out horizontally on App Service; DB scaled via Azure SQL tiers.
- **Availability:** target 99.9% using managed Azure services (App Service + Azure SQL SLAs).
- **Maintainability:** modular code (`risk_engine`, `config`, `blob_storage`, `main`), typed models, documented schema, unit-testable pure math module.
- **Auditability:** who/when columns on writes, immutable raw files with hashes.
- **Usability:** clear validation errors (row number and field, never the raw value), auto-generated OpenAPI docs in non-production.

### REST API routes

| Method | Route | Role | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | Public | Verify credentials, return JWT |
| POST | `/api/auth/register` | Quant | Create a user (password hashed) |
| GET | `/api/assets` | Quant, Viewer | List assets |
| POST | `/api/assets` | Quant | Create an asset |
| POST | `/api/upload` | Quant | Upload returns CSV (Blob archive, validate, insert) |
| POST | `/api/risk/calculate/{asset_id}?confidence=0.99` | Quant | Compute and log Gaussian + Hill VaR |
| GET | `/api/risk/metrics?asset_id=&limit=` | Quant, Viewer | List stored risk metrics |
| GET | `/api/assets/{asset_id}/extreme-losses` | Quant, Viewer | Worst-5% losses from `vw_ExtremeLosses` |
| GET | `/api/health` | Public | Liveness probe |

### Architectural trade-off: Synchronous Monolith vs Background Workers

We deliberately chose a synchronous, monolithic FastAPI service over a queue-plus-worker design (for example Azure Functions or Service Bus consumers) for the risk calculation. Ten years of daily returns is only about 2,520 observations, and the Hill/Gaussian computation is one sort plus a few vector operations, which completes in milliseconds, far below any sensible HTTP timeout. A single deployable unit therefore gives us a simpler architecture, one transaction boundary (calculate and log in the same request), immediate feedback to the user, trivial debugging, lower cost, and a smaller attack surface (no message broker, no extra credentials). The cost of this choice is weaker isolation and elasticity: a long-running or very large computation (for example thousands of assets, bootstrap confidence intervals, or Hill plots over many k) would occupy a request thread and could hurt API latency under load, and there is no automatic retry. We accept that trade-off because the workload is small and bounded, and we would move to background workers only if the calculation time or volume grew beyond what a request can serve.
