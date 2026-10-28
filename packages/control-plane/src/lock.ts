/** Serializes work per key; different keys run concurrently. Entries are dropped once their chain is idle. */
export function keyedLock() {
  const tails = new Map<string, Promise<unknown>>();
  return function run<T>(key: string, operation: () => Promise<T>): Promise<T> {
    const next = (tails.get(key) ?? Promise.resolve()).catch(() => undefined).then(operation);
    const tail = next.catch(() => undefined);
    tails.set(key, tail);
    void tail.then(() => { if (tails.get(key) === tail) tails.delete(key); });
    return next;
  };
}

/** A Map bounded by entry count that evicts the least recently used entry. */
export class Lru<K, V> {
  private readonly map = new Map<K, V>();
  constructor(private readonly max: number) {}
  get size(): number { return this.map.size; }
  get(key: K): V | undefined {
    const value = this.map.get(key);
    if (value !== undefined) { this.map.delete(key); this.map.set(key, value); }
    return value;
  }
  has(key: K): boolean { return this.map.has(key); }
  set(key: K, value: V): void {
    this.map.delete(key);
    this.map.set(key, value);
    while (this.map.size > this.max) this.map.delete(this.map.keys().next().value as K);
  }
  delete(key: K): void { this.map.delete(key); }
  clear(): void { this.map.clear(); }
}
