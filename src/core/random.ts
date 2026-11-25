/**
 * Seeded pseudo-random numbers for test data, so the same app gets the same values on every run
 * and corpus comparisons are exact. Not for anything secret: markers, passwords and keys keep
 * using crypto.randomUUID.
 */
export type Rand = () => number;

/** mulberry32 over an FNV-1a hash of the seed. */
export function seeded(seed: string): Rand {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) h = Math.imul(h ^ seed.charCodeAt(i), 16777619);
  let a = h >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** An integer in [0, n). */
export const pick = (rand: Rand, n: number) => Math.floor(rand() * n);
