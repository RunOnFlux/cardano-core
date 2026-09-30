/** Seeded PRNG (mulberry32) so every failure is reproducible from its seed. */
export class Rng {
  private s: number;
  constructor(seed: number) {
    this.s = seed >>> 0;
  }
  u32(): number {
    this.s = (this.s + 0x6d2b79f5) >>> 0;
    let t = this.s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  }
  int(maxExclusive: number): number {
    return this.u32() % maxExclusive;
  }
  range(min: number, maxInclusive: number): number {
    return min + this.int(maxInclusive - min + 1);
  }
  bool(p = 0.5): boolean {
    return this.u32() / 0x100000000 < p;
  }
  bytes(n: number): Uint8Array {
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = this.u32() & 0xff;
    return b;
  }
  u64(): bigint {
    return (BigInt(this.u32()) << 32n) | BigInt(this.u32());
  }
  pick<T>(xs: readonly T[]): T {
    return xs[this.int(xs.length)] as T;
  }
  /** Lovelace across the regimes that matter for CBOR width and min-ADA. */
  lovelace(): bigint {
    switch (this.int(5)) {
      case 0:
        return BigInt(this.range(1_000_000, 3_000_000));
      case 1:
        return (
          BigInt(this.range(1, 100)) * 1_000_000n +
          BigInt(this.range(0, 999_999))
        );
      case 2:
        return BigInt(this.range(1, 100_000)) * 1_000_000n;
      case 3:
        return BigInt(this.range(1, 45_000_000)) * 1_000_000n;
      default:
        return BigInt(this.range(1_000_000, 0x7fffffff));
    }
  }
  /** Asset quantity across CBOR widths. */
  quantity(): bigint {
    switch (this.int(4)) {
      case 0:
        return BigInt(this.range(1, 23));
      case 1:
        return BigInt(this.range(24, 65_535));
      case 2:
        return BigInt(this.range(1, 0x7fffffff)) * BigInt(this.range(1, 1000));
      default:
        return (this.u64() % 18_000_000_000_000_000_000n) + 1n;
    }
  }
}

/** Number of seeded cases per property: 200 by default, `CARDANO_ORACLE_CASES` for the full sweep. */
export function cases(defaultCases = 200): number {
  const env = Number(process.env['CARDANO_ORACLE_CASES']);
  return Number.isInteger(env) && env > 0 ? env : defaultCases;
}
