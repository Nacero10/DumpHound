export type TableRow = readonly string[];
export type SortDirection = "asc" | "desc";

const numericPattern = /^-?\d+(?:[.,]\d+)?$/;

function normalized(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

function numericValue(value: unknown): number {
  return Number.parseFloat(String(value ?? "").trim().replace(",", "."));
}

function isNumericValue(value: unknown): boolean {
  return numericPattern.test(String(value ?? "").trim().replace(",", "."));
}

/** Matches the CSV-filter style expression language used by table column menus. */
export function matchesColumnExpression(value: unknown, expression: string): boolean {
  const query = expression.trim();
  if (!query) return true;

  const range = query.match(/^(-?\d+(?:[.,]\d+)?)\.\.(-?\d+(?:[.,]\d+)?)$/);
  if (range) {
    const number = numericValue(value);
    const lower = numericValue(range[1]);
    const upper = numericValue(range[2]);
    return isNumericValue(value) && Number.isFinite(number) && number >= lower && number <= upper;
  }

  const operator = query.match(/^(>=|<=|!=|>|<|=)\s*(.*)$/);
  if (operator) {
    const [, kind, rawExpected] = operator;
    const expected = rawExpected.trim();
    if (numericPattern.test(expected.replace(",", "."))) {
      const actual = numericValue(value);
      const expectedNumber = numericValue(expected);
      if (!isNumericValue(value) || !Number.isFinite(actual)) return false;
      if (kind === ">") return actual > expectedNumber;
      if (kind === "<") return actual < expectedNumber;
      if (kind === ">=") return actual >= expectedNumber;
      if (kind === "<=") return actual <= expectedNumber;
      if (kind === "=") return actual === expectedNumber;
      return actual !== expectedNumber;
    }
    const actual = normalized(value);
    const expectedText = normalized(expected);
    return kind === "=" ? actual === expectedText : kind === "!=" ? actual !== expectedText : false;
  }

  const terms = normalized(query).split(/\s+/).filter(Boolean);
  const haystack = normalized(value);
  return terms.every((term) => haystack.includes(term));
}

export function matchesGlobalQuery(row: TableRow, query: string): boolean {
  const terms = normalized(query).split(/\s+/).filter(Boolean);
  if (!terms.length) return true;
  const haystack = row.join("\u0001").toLowerCase();
  return terms.every((term) => haystack.includes(term));
}

export function filterRowIndices(
  rows: readonly TableRow[],
  columnFilters: Record<number, string>,
  globalQuery: string,
): number[] {
  const activeFilters = Object.entries(columnFilters).filter(([, value]) => value.trim());
  const result: number[] = [];
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    if (!matchesGlobalQuery(row, globalQuery)) continue;
    if (activeFilters.every(([column, expression]) => matchesColumnExpression(row[Number(column)], expression))) {
      result.push(index);
    }
  }
  return result;
}

export function sortRowIndices(
  rows: readonly TableRow[],
  indices: readonly number[],
  column: number,
  direction: SortDirection,
): number[] {
  const result = [...indices];
  const sample = result.slice(0, 200);
  const numeric = sample.length > 0 && sample.filter((index) => numericPattern.test(String(rows[index][column] ?? "").trim())).length / sample.length > 0.6;
  const multiplier = direction === "asc" ? 1 : -1;
  result.sort((a, b) => {
    const left = rows[a][column] ?? "";
    const right = rows[b][column] ?? "";
    if (numeric) {
      const leftNumber = numericValue(left);
      const rightNumber = numericValue(right);
      if (!Number.isFinite(leftNumber)) return 1;
      if (!Number.isFinite(rightNumber)) return -1;
      return (leftNumber - rightNumber) * multiplier;
    }
    return String(left).localeCompare(String(right), undefined, { numeric: true, sensitivity: "base" }) * multiplier;
  });
  return result;
}
