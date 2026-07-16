export class StrictJsonError extends Error {
  constructor(readonly code: "json-invalid" | "json-duplicate-key") {
    super(code === "json-invalid" ? "JSON is invalid" : "JSON contains a duplicate member");
    this.name = "StrictJsonError";
  }
}

class Parser {
  private index = 0;
  private nodes = 0;

  private static readonly MAX_DEPTH = 32;
  private static readonly MAX_NODES = 4_096;
  private static readonly MAX_OBJECT_MEMBERS = 256;
  private static readonly MAX_ARRAY_ITEMS = 1_024;

  constructor(private readonly source: string) {}

  parse(): unknown {
    const value = this.value(0);
    this.space();
    if (this.index !== this.source.length) this.invalid();
    return value;
  }

  private invalid(): never {
    throw new StrictJsonError("json-invalid");
  }

  private space(): void {
    while (this.index < this.source.length && /[\x20\x09\x0a\x0d]/u.test(this.source[this.index]!)) {
      this.index += 1;
    }
  }

  private value(depth: number): unknown {
    this.nodes += 1;
    if (this.nodes > Parser.MAX_NODES || depth > Parser.MAX_DEPTH) this.invalid();
    this.space();
    const token = this.source[this.index];
    if (token === "{") return this.object(depth + 1);
    if (token === "[") return this.array(depth + 1);
    if (token === '"') return this.string();
    if (token === "t") return this.literal("true", true);
    if (token === "f") return this.literal("false", false);
    if (token === "n") return this.literal("null", null);
    if (token === "-" || (token !== undefined && /[0-9]/u.test(token))) return this.number();
    return this.invalid();
  }

  private object(depth: number): Record<string, unknown> {
    if (depth > Parser.MAX_DEPTH) this.invalid();
    this.index += 1;
    const result = Object.create(null) as Record<string, unknown>;
    const keys = new Set<string>();
    this.space();
    if (this.source[this.index] === "}") {
      this.index += 1;
      return result;
    }
    while (true) {
      this.space();
      if (this.source[this.index] !== '"') this.invalid();
      const key = this.string();
      if (keys.has(key)) throw new StrictJsonError("json-duplicate-key");
      keys.add(key);
      if (keys.size > Parser.MAX_OBJECT_MEMBERS) this.invalid();
      this.space();
      if (this.source[this.index] !== ":") this.invalid();
      this.index += 1;
      result[key] = this.value(depth);
      this.space();
      const token = this.source[this.index];
      if (token === "}") {
        this.index += 1;
        return result;
      }
      if (token !== ",") this.invalid();
      this.index += 1;
    }
  }

  private array(depth: number): unknown[] {
    if (depth > Parser.MAX_DEPTH) this.invalid();
    this.index += 1;
    const result: unknown[] = [];
    this.space();
    if (this.source[this.index] === "]") {
      this.index += 1;
      return result;
    }
    while (true) {
      result.push(this.value(depth));
      if (result.length > Parser.MAX_ARRAY_ITEMS) this.invalid();
      this.space();
      const token = this.source[this.index];
      if (token === "]") {
        this.index += 1;
        return result;
      }
      if (token !== ",") this.invalid();
      this.index += 1;
    }
  }

  private string(): string {
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.source.length) {
      const character = this.source.charCodeAt(this.index);
      if (character < 0x20) this.invalid();
      if (!escaped && character === 0x22) {
        this.index += 1;
        try {
          return JSON.parse(this.source.slice(start, this.index)) as string;
        } catch {
          return this.invalid();
        }
      }
      if (!escaped && character === 0x5c) escaped = true;
      else escaped = false;
      this.index += 1;
    }
    return this.invalid();
  }

  private literal<T>(literal: string, value: T): T {
    if (this.source.slice(this.index, this.index + literal.length) !== literal) this.invalid();
    this.index += literal.length;
    return value;
  }

  private number(): number {
    const remainder = this.source.slice(this.index);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(remainder);
    if (match === null) return this.invalid();
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) return this.invalid();
    return value;
  }
}

export function parseStrictJson(source: string): unknown {
  if (Buffer.byteLength(source, "utf8") > 64 * 1024) throw new StrictJsonError("json-invalid");
  return new Parser(source).parse();
}
