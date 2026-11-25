import { readFileSync } from "node:fs";

/** A saved facts file from a planted app, judged in the judge tests. */
export const plantedInput = readFileSync(new URL("../test/fixtures/planted-app.input.json", import.meta.url), "utf8");
