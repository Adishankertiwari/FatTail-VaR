/* ==========================================================================
   schema.sql  -  Extreme Value Risk Analytics Platform
   Target     : Azure SQL Database / SQL Server 2016 SP1+
   Run        : in one session, top to bottom (GO = batch separator).
   Idempotent : tables use IF OBJECT_ID guards; view/proc use CREATE OR ALTER.

   3NF justification
   -----------------
   Roles        : RoleName depends only on RoleID.
   Users        : every column depends on UserID; role facts live in Roles.
   Assets       : Ticker/Name/Currency depend only on AssetID.
   DailyReturns : DailyReturn depends on the whole key (AssetID, TradeDate);
                  asset attributes are NOT repeated here.
   RiskMetrics  : each VaR/xi value depends only on MetricID (one calculation run);
                  asset and user facts are reached through foreign keys.
   ========================================================================== */

/* -------------------------------------------------------------------------
   1. TABLES  (exactly 5)
   ------------------------------------------------------------------------- */

IF OBJECT_ID(N'dbo.Roles', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Roles
    (
        RoleID    TINYINT      IDENTITY(1,1) NOT NULL,
        RoleName  NVARCHAR(20) NOT NULL,
        CONSTRAINT PK_Roles          PRIMARY KEY CLUSTERED (RoleID),
        CONSTRAINT UQ_Roles_RoleName UNIQUE (RoleName),
        CONSTRAINT CK_Roles_RoleName CHECK (RoleName IN (N'Quant', N'Viewer'))
    );
END
GO

IF OBJECT_ID(N'dbo.Users', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Users
    (
        UserID        INT           IDENTITY(1,1) NOT NULL,
        Username      NVARCHAR(50)  NOT NULL,
        PasswordHash  NVARCHAR(255) NOT NULL,   -- bcrypt hash only, never plaintext
        RoleID        TINYINT       NOT NULL,
        IsActive      BIT           NOT NULL CONSTRAINT DF_Users_IsActive  DEFAULT (1),
        CreatedAt     DATETIME2(0)  NOT NULL CONSTRAINT DF_Users_CreatedAt DEFAULT (SYSUTCDATETIME()),
        CONSTRAINT PK_Users          PRIMARY KEY CLUSTERED (UserID),
        CONSTRAINT UQ_Users_Username UNIQUE (Username),
        CONSTRAINT FK_Users_Roles    FOREIGN KEY (RoleID) REFERENCES dbo.Roles (RoleID),
        CONSTRAINT CK_Users_Username CHECK (LEN(Username) >= 3),
        CONSTRAINT CK_Users_Hash     CHECK (LEN(PasswordHash) >= 59)   -- bcrypt output is 60 chars
    );
END
GO

IF OBJECT_ID(N'dbo.Assets', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Assets
    (
        AssetID    INT           IDENTITY(1,1) NOT NULL,
        Ticker     NVARCHAR(20)  NOT NULL,
        AssetName  NVARCHAR(100) NOT NULL,
        Currency   CHAR(3)       NOT NULL CONSTRAINT DF_Assets_Currency DEFAULT ('USD'),
        CreatedAt  DATETIME2(0)  NOT NULL CONSTRAINT DF_Assets_CreatedAt DEFAULT (SYSUTCDATETIME()),
        CONSTRAINT PK_Assets        PRIMARY KEY CLUSTERED (AssetID),
        CONSTRAINT UQ_Assets_Ticker UNIQUE (Ticker),
        CONSTRAINT CK_Assets_Ticker CHECK (LEN(Ticker) >= 1)
    );
END
GO

IF OBJECT_ID(N'dbo.DailyReturns', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.DailyReturns
    (
        ReturnID     BIGINT        IDENTITY(1,1) NOT NULL,
        AssetID      INT           NOT NULL,
        TradeDate    DATE          NOT NULL,
        DailyReturn  DECIMAL(12,8) NOT NULL,     -- simple return r_t = P_t / P_{t-1} - 1
        UploadedBy   INT           NOT NULL,
        UploadedAt   DATETIME2(0)  NOT NULL CONSTRAINT DF_DailyReturns_UploadedAt DEFAULT (SYSUTCDATETIME()),
        CONSTRAINT PK_DailyReturns        PRIMARY KEY CLUSTERED (ReturnID),
        CONSTRAINT FK_DailyReturns_Assets FOREIGN KEY (AssetID)    REFERENCES dbo.Assets (AssetID),
        CONSTRAINT FK_DailyReturns_Users  FOREIGN KEY (UploadedBy) REFERENCES dbo.Users  (UserID),
        CONSTRAINT CK_DailyReturns_Range  CHECK (DailyReturn > -1.0 AND DailyReturn < 10.0)
    );
END
GO

IF OBJECT_ID(N'dbo.RiskMetrics', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.RiskMetrics
    (
        MetricID         BIGINT        IDENTITY(1,1) NOT NULL,
        AssetID          INT           NOT NULL,
        CalculatedBy     INT           NOT NULL,
        CalculatedAt     DATETIME2(0)  NOT NULL CONSTRAINT DF_RiskMetrics_CalculatedAt DEFAULT (SYSUTCDATETIME()),
        ConfidenceLevel  DECIMAL(6,5)  NOT NULL,   -- e.g. 0.99000
        WindowStart      DATE          NOT NULL,
        WindowEnd        DATE          NOT NULL,
        SampleSize       INT           NOT NULL,   -- n
        TailK            INT           NOT NULL,   -- k (Hill exceedances)
        HillXi           DECIMAL(10,6) NOT NULL,   -- tail index xi_hat
        GaussianVaR      DECIMAL(12,8) NOT NULL,
        HillVaR          DECIMAL(12,8) NOT NULL,
        CONSTRAINT PK_RiskMetrics        PRIMARY KEY CLUSTERED (MetricID),
        CONSTRAINT FK_RiskMetrics_Assets FOREIGN KEY (AssetID)      REFERENCES dbo.Assets (AssetID),
        CONSTRAINT FK_RiskMetrics_Users  FOREIGN KEY (CalculatedBy) REFERENCES dbo.Users  (UserID),
        CONSTRAINT CK_RiskMetrics_Conf   CHECK (ConfidenceLevel > 0.5 AND ConfidenceLevel < 1),
        CONSTRAINT CK_RiskMetrics_Window CHECK (WindowEnd >= WindowStart),
        CONSTRAINT CK_RiskMetrics_Sample CHECK (SampleSize > 0 AND TailK > 0 AND TailK < SampleSize),
        CONSTRAINT CK_RiskMetrics_Xi     CHECK (HillXi >= 0),
        CONSTRAINT CK_RiskMetrics_VaR    CHECK (HillVaR > 0)     -- Gaussian VaR may be <= 0 for extreme drift
    );
END
GO

/* Seed the two RBAC roles (safe to re-run) */
INSERT INTO dbo.Roles (RoleName)
SELECT v.RoleName
FROM (VALUES (N'Quant'), (N'Viewer')) AS v (RoleName)
WHERE NOT EXISTS (SELECT 1 FROM dbo.Roles r WHERE r.RoleName = v.RoleName);
GO

/* -------------------------------------------------------------------------
   2. COMPOSITE INDEX  DailyReturns (AssetID, TradeDate)
      UNIQUE: one return per asset per day (also protects against duplicate
      uploads). INCLUDE makes it covering for the VaR query
      "SELECT DailyReturn ... WHERE AssetID = ? ORDER BY TradeDate".
   ------------------------------------------------------------------------- */
IF NOT EXISTS (SELECT 1 FROM sys.indexes
               WHERE name = N'IX_DailyReturns_AssetID_TradeDate'
                 AND object_id = OBJECT_ID(N'dbo.DailyReturns'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX IX_DailyReturns_AssetID_TradeDate
        ON dbo.DailyReturns (AssetID, TradeDate)
        INCLUDE (DailyReturn);
END
GO

/* -------------------------------------------------------------------------
   3. VIEW  vw_ExtremeLosses
      The worst 5% of daily returns PER ASSET: k = FLOOR(0.05 * n) rows,
      identical to the k exceedances the Hill estimator uses in risk_engine.py.
      (The threshold L_(k+1) is the next order statistic, read from the full
      series by the engine.)
   ------------------------------------------------------------------------- */
CREATE OR ALTER VIEW dbo.vw_ExtremeLosses
AS
WITH Ranked AS
(
    SELECT
        dr.AssetID,
        dr.TradeDate,
        dr.DailyReturn,
        ROW_NUMBER() OVER (PARTITION BY dr.AssetID ORDER BY dr.DailyReturn ASC) AS LossRank,  -- 1 = worst day
        COUNT(*)     OVER (PARTITION BY dr.AssetID)                             AS N
    FROM dbo.DailyReturns AS dr
)
SELECT
    AssetID,
    TradeDate,
    DailyReturn,
    -DailyReturn AS LossMagnitude,     -- L_t = -r_t
    LossRank,
    N
FROM Ranked
WHERE LossRank <= FLOOR(0.05 * N);
GO

/* -------------------------------------------------------------------------
   4. STORED PROCEDURE  sp_LogRiskCalculation
      Fully parameterised (no dynamic SQL => no SQL injection surface),
      validates inputs, writes atomically, returns the new MetricID.
   ------------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.sp_LogRiskCalculation
    @AssetID         INT,
    @CalculatedBy    INT,
    @ConfidenceLevel DECIMAL(6,5),
    @WindowStart     DATE,
    @WindowEnd       DATE,
    @SampleSize      INT,
    @TailK           INT,
    @HillXi          DECIMAL(10,6),
    @GaussianVaR     DECIMAL(12,8),
    @HillVaR         DECIMAL(12,8)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;      -- any run-time error dooms the transaction

    DECLARE @OwnTran BIT = CASE WHEN @@TRANCOUNT = 0 THEN 1 ELSE 0 END;

    BEGIN TRY
        IF NOT EXISTS (SELECT 1 FROM dbo.Assets WHERE AssetID = @AssetID)
            THROW 50001, 'Unknown AssetID.', 1;
        IF NOT EXISTS (SELECT 1 FROM dbo.Users WHERE UserID = @CalculatedBy AND IsActive = 1)
            THROW 50002, 'Unknown or inactive user.', 1;

        IF @OwnTran = 1 BEGIN TRANSACTION;

        INSERT INTO dbo.RiskMetrics
            (AssetID, CalculatedBy, ConfidenceLevel, WindowStart, WindowEnd,
             SampleSize, TailK, HillXi, GaussianVaR, HillVaR)
        VALUES
            (@AssetID, @CalculatedBy, @ConfidenceLevel, @WindowStart, @WindowEnd,
             @SampleSize, @TailK, @HillXi, @GaussianVaR, @HillVaR);

        DECLARE @MetricID BIGINT = SCOPE_IDENTITY();

        IF @OwnTran = 1 COMMIT TRANSACTION;

        SELECT @MetricID AS MetricID;
    END TRY
    BEGIN CATCH
        IF @OwnTran = 1 AND @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;              -- re-raise the original error to the caller
    END CATCH
END
GO

/* -------------------------------------------------------------------------
   5. DAILY RETURNS
      No sample rows are inserted by the schema script. Run this schema first,
      create the evt_api database user, then start the API to seed demo accounts.
      Upload actual historical returns through /api/upload after adding an asset.
      DailyReturns enforces a unique (AssetID, TradeDate) key, so each asset/date
      can be uploaded only once.
   ------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
   6. LEAST-PRIVILEGE ROLE for the FastAPI service account
      RiskMetrics rows are written ONLY through sp_LogRiskCalculation
      (ownership chaining: same schema/owner => no direct INSERT right needed).
      Create the login/user yourself, e.g. in the user database:
          CREATE USER [evt_api] WITH PASSWORD = '<strong secret from Key Vault>';
          ALTER ROLE app_runtime ADD MEMBER [evt_api];
   ------------------------------------------------------------------------- */
IF DATABASE_PRINCIPAL_ID(N'app_runtime') IS NULL
    CREATE ROLE app_runtime;
GO
GRANT SELECT, INSERT ON dbo.Users        TO app_runtime;
GRANT SELECT, INSERT ON dbo.Assets       TO app_runtime;
GRANT SELECT, INSERT ON dbo.DailyReturns TO app_runtime;
GRANT SELECT         ON dbo.Roles        TO app_runtime;
GRANT SELECT         ON dbo.RiskMetrics  TO app_runtime;
GRANT SELECT         ON dbo.vw_ExtremeLosses TO app_runtime;
GRANT EXECUTE        ON dbo.sp_LogRiskCalculation TO app_runtime;
GO
