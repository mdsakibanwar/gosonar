BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "stems" (`stem` TEXT, "status" INTEGER DEFAULT 0, func_names TEXT, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS "loops" (`loop` TEXT , "status" INTEGER DEFAULT 0, func_names TEXT, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS "lassos" (`loop` TEXT NOT NULL REFERENCES "loops"(`loop`), `stem` TEXT NOT NULL REFERENCES `stems`(`stem`), `loop_head` INTEGER, "status" INTEGER DEFAULT 0, "data" TEXT, `stem_finding_start` REAL DEFAULT 0, `stem_finding_finish` REAL DEFAULT 0, `stem_execution_start` REAL DEFAULT 0, `stem_execution_finish` REAL DEFAULT 0, `loop_execution_start` REAL DEFAULT 0, `loop_execution_finish` REAL DEFAULT 0 , `iteration_verified` INTEGER DEFAULT 0);
CREATE UNIQUE INDEX `idx_stems` ON `stems` (`stem`);
CREATE UNIQUE INDEX `idx_loops` ON "loops" (`loop`);
CREATE UNIQUE INDEX `idx_lassos_2` ON `lassos` (`loop`, `stem`);
CREATE INDEX `idx_lassos` ON `lassos` (`loop`);
COMMIT;

-- CREATE TABLE "overview" ( `mode` TEXT,`package` TEXT, `loops` INTEGER, `valid-loops` INTEGER, `stem-not-found` INTEGER, `stems` INTEGER, `valid-stems` INTEGER, `lassos` INTEGER, `not-analyzed` INTEGER, `loop-not-seen` INTEGER, `stem-aborted` INTEGER, `timeout` INTEGER, `loop-not-verified` INTEGER, `cons-not-verified` INTEGER, `stem-executed` INTEGER, `cons-verified` INTEGER, `angr-errored` INTEGER, `runtime` INTEGER)
-- CREATE TABLE "lassos" ( `mode` TEXT, `package` TEXT,`loop` TEXT NOT NULL , `stem` TEXT NOT NULL, `loop_head` INTEGER, "status" INTEGER DEFAULT 0, "data" TEXT, `stem_finding_start` REAL DEFAULT 0, `stem_finding_finish` REAL DEFAULT 0, `stem_execution_start` REAL DEFAULT 0, `stem_execution_finish` REAL DEFAULT 0, `loop_execution_start` REAL DEFAULT 0, `loop_execution_finish` REAL DEFAULT 0 , `iteration_verified` INTEGER DEFAULT 0)