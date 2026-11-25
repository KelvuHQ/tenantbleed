import type { Observation, WorldSummary } from "./observation.js";
import type { CoverageRow, LintRow, ScanResult } from "./scan-result.js";
import type { Schema } from "../supabase/introspect.js";
import type { TraceRow } from "./trace.js";
import type { ScanTarget, SourceRef } from "./report-context.js";

/**
 * Everything the engine collected in one scan, as plain JSON: what the API receives. The judge
 * returns the ScanResult. Version 1 of this contract is the Supabase engine's.
 */
export interface JudgeInput {
  v: 1;
  stack: "supabase";
  startedAt: string;
  durationMs: number;
  /** The app and version scanned. */
  target?: ScanTarget;
  /** Scanned schemas, and the schemas the Data API exposes. */
  schemas: string[];
  exposed: string[];
  schema: Schema;
  tenants: string[];
  world: WorldSummary;
  observations: Observation[];
  coverage: CoverageRow[];
  ownerAccess?: ScanResult["ownerAccess"];
  /** Engine notes, in report order. */
  notes: string[];
  /** True when every probe ran to the end. */
  probesFinished: boolean;
  /** Test-data steps and argument strategies the scan used (src/core/trace.ts). */
  trace?: TraceRow[];
  /** Set when the scan aborted; the judge reports what it has. */
  aborted?: boolean;
  hints: {
    /** Objects created by seed files and by no migration. */
    seedOnly: string[];
    /** Every GRANT or REVOKE on a function in the migrations, in order. */
    functionGrants: string[];
    tenancy?: "multi" | "single";
    /** config.toml sets [db.migrations] enabled = false. */
    migrationsDisabled: boolean;
    /** Where policies, functions, tables and views are defined in the migrations. */
    sources?: SourceRef[];
  };
  /** Absent when triage is off. */
  lint?:
    | {
        rows: LintRow[];
        triggerFunctions: string[];
        /** Functions and tables that belong to an extension (PostGIS, pg_trgm), "schema.name" to extension name. */
        extensionObjects?: Record<string, string>;
      }
    | { error: string };
}
