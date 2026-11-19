export type CharClass = "alpha" | "digit" | "symbol";

export interface PasswordSegment {
  text: string;
  kind: CharClass;
}

export function classifyChar(ch: string): CharClass {
  if (ch >= "0" && ch <= "9") {
    return "digit";
  }
  if ((ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z")) {
    return "alpha";
  }
  return "symbol";
}

/** Splits a plaintext secret into contiguous `alpha`, `digit`, and `symbol` spans for unambiguous rendering. */
export function tokenizePassword(value: string): PasswordSegment[] {
  const segments: PasswordSegment[] = [];
  let currentKind: CharClass | null = null;
  let buffer = "";

  for (const ch of value) {
    const kind = classifyChar(ch);
    if (kind === currentKind) {
      buffer += ch;
    } else {
      if (currentKind !== null && buffer.length > 0) {
        segments.push({ text: buffer, kind: currentKind });
      }
      currentKind = kind;
      buffer = ch;
    }
  }

  if (currentKind !== null && buffer.length > 0) {
    segments.push({ text: buffer, kind: currentKind });
  }
  return segments;
}
