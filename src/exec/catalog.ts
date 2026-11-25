import type pg from "pg";
import { introspect, type Schema } from "../supabase/introspect.js";

/** The `catalog` primitive: the introspected schema, the same JSON the scan uses in-process. */
export const catalog = (db: pg.Client, schemas: string[]): Promise<Schema> => introspect(db, schemas);
