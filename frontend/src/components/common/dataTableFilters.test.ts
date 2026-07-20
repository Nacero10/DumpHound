import assert from "node:assert/strict";
import test from "node:test";
import {
  filterRowIndices,
  matchesColumnExpression,
  matchesGlobalQuery,
  sortRowIndices,
} from "./dataTableFilters.ts";

test("global search matches every word across different columns", () => {
  const rows = [["linux", "sshd", "10.0.0.5"], ["windows", "explorer", "10.0.0.6"]];

  assert.deepEqual(filterRowIndices(rows, {}, "linux 10.0.0.5"), [0]);
  assert.deepEqual(filterRowIndices(rows, {}, "linux explorer"), []);
  assert.equal(matchesGlobalQuery(rows[0], ""), true);
});

test("column expressions support contains, numeric comparison, equality, and inclusive ranges", () => {
  assert.equal(matchesColumnExpression("Suspicious PowerShell", "power shell"), true);
  assert.equal(matchesColumnExpression("12", ">= 10"), true);
  assert.equal(matchesColumnExpression("12", "< 10"), false);
  assert.equal(matchesColumnExpression("alert", "= ALERT"), true);
  assert.equal(matchesColumnExpression("warn", "!= alert"), true);
  assert.equal(matchesColumnExpression("", "="), true);
  assert.equal(matchesColumnExpression("12", "10..20"), true);
  assert.equal(matchesColumnExpression("21", "10..20"), false);
  assert.equal(matchesColumnExpression("12files", "10..20"), false);
  assert.equal(matchesColumnExpression("12.3.4", ">= 10"), false);
});

test("filtering combines global and per-column rules without mutating rows", () => {
  const rows = [["alert", "12", "hidden module"], ["warn", "8", "unsigned module"]];
  const filters = { 0: "!= info", 1: ">=10" };

  assert.deepEqual(filterRowIndices(rows, filters, "module"), [0]);
  assert.deepEqual(rows, [["alert", "12", "hidden module"], ["warn", "8", "unsigned module"]]);
});

test("sort chooses numeric order when most values are numeric and keeps source rows intact", () => {
  const rows = [["10"], ["2"], ["30"], ["unknown"]];

  assert.deepEqual(sortRowIndices(rows, [0, 1, 2, 3], 0, "asc"), [1, 0, 2, 3]);
  assert.deepEqual(sortRowIndices(rows, [0, 1, 2, 3], 0, "desc"), [2, 0, 1, 3]);
  assert.deepEqual(rows, [["10"], ["2"], ["30"], ["unknown"]]);
});
