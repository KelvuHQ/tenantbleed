/**
 * The executor's five primitives. Each takes a batch of plain-JSON operations and returns plain-JSON
 * results; the in-process engine (first split) and the remote executor (second split) share them.
 */
export { catalog } from "./catalog.js";
export { http, storage, type HttpLimits, type HttpOp, type HttpResult, type StorageOp } from "./http.js";
export { asUserClaims, query, sql, sqlOne, type SqlError, type SqlOp, type SqlResult, type SqlStatement } from "./sql.js";
export { createUserDirect, users, type UserOp, type UserResult } from "./user.js";
