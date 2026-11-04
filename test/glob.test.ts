import { describe, expect, it } from "vitest";
import { GlobError, matchGlob, normalizeGlob } from "../src/glob.js";

describe("glob", () => {
  it.each([
    ["**/*", ".env", true],
    ["**/*", "a/b/c.ts", true],
    [".env", "apps/web/.env", true],
    ["config/app.php", "x/config/app.php", false],
    ["**/config/app.php", "x/config/app.php", true],
    ["**/dist/**/*.map", "dist/a.js.map", true],
    ["**/dist/**/*.map", "web/dist/assets/a.js.map", true],
    ["application*.{properties,yml,yaml}", "src/main/resources/application-prod.yml", true],
    [".env{,.*}", ".env", true],
    [".env{,.*}", ".env.local", true],
    [".env{,.*}", ".envrc", false],
    ["app/api/**", "app/api/x/route.ts", true],
    ["app/api/**", "app/page.tsx", false],
    ["*.[jt]s", "a.ts", true],
    ["*.[!j]s", "a.js", false],
    ["한글 폴더/*.ts", "한글 폴더/a.ts", true],
  ])("%s ~ %s → %s", (g, p, want) => {
    expect(matchGlob(normalizeGlob(g), p)).toBe(want);
  });

  it("normalizes backslashes and ./", () => {
    expect(normalizeGlob(".\\src\\**")).toBe("src/**");
  });

  it.each(["../**", "a/../../b", "/etc/**", "C:/x/**", "c:\\x", "~/x"])("rejects %s (AC43)", (g) => {
    expect(() => normalizeGlob(g)).toThrow(GlobError);
  });
});
