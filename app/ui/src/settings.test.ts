import { describe, expect, it } from "vitest";

import { homeOf, serverName, tilde, toggled } from "./settings.ts";

describe("paths", () => {
  it("reads the home folder from the config path and shortens paths under it", () => {
    const home = homeOf("/Users/me/Library/Application Support/ancient-protector/config.toml");
    expect(home).toBe("/Users/me");
    expect(tilde("/Users/me/code", home)).toBe("~/code");
    expect(tilde("/Users/me", home)).toBe("~");
    expect(tilde("/Users/meow/code", home)).toBe("/Users/meow/code");
    expect(tilde("/srv/app", null)).toBe("/srv/app");
    expect(homeOf("/tmp/config.toml")).toBeNull();
  });
});

describe("toggled", () => {
  it("adds at the end and removes in place", () => {
    expect(toggled(["a", "b"], "c")).toEqual(["a", "b", "c"]);
    expect(toggled(["a", "b", "c"], "b")).toEqual(["a", "c"]);
  });
});

describe("serverName", () => {
  it("uses the alias when it is a valid name", () => {
    expect(serverName("web-1")).toBe("web-1");
    expect(serverName("my host")).toBe("");
    expect(serverName("..")).toBe("");
  });
});
