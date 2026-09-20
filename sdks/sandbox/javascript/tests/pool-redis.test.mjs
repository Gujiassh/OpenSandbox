import assert from "node:assert/strict";
import test from "node:test";

import { PoolDestroyState, PoolStateStoreUnavailableException } from "../dist/index.js";
import { RedisPoolStateStore } from "../dist/poolRedis.js";

test("Redis pool support is a loadable subpath with no redis runtime import", async () => {
  const exported = await import("@alibaba-group/opensandbox/pool-redis");
  assert.equal(typeof exported.RedisPoolStateStore, "function");
});

test("RedisPoolStateStore uses one cluster hash slot per encoded pool namespace", async () => {
  const commands = [];
  const client = {
    async sendCommand(command) {
      commands.push(command);
      if (command[0] === "EVAL") return 1;
      if (command[0] === "GET") return null;
      return 0;
    },
  };
  const store = new RedisPoolStateStore({ client, keyPrefix: "test:pool" });

  await store.setMaxIdle("a pool/名称", 3);
  await store.setIdleEntryTtl("a pool/名称", 60);
  assert.equal(await store.getDestroyState("a pool/名称"), PoolDestroyState.ACTIVE);

  const keys = commands
    .flatMap((command) => command[0] === "EVAL" ? command.slice(3, 5) : command.slice(1, 2))
    .filter((value) => value?.startsWith("test:pool:"));
  const hashTags = new Set(keys.map((key) => key.match(/\{[^}]+\}/)?.[0]));
  assert.equal(hashTags.size, 1);
});

test("RedisPoolStateStore maps client failures to pool store failures", async () => {
  const store = new RedisPoolStateStore({
    client: { async sendCommand() { throw new Error("redis unavailable"); } },
  });
  await assert.rejects(store.getDestroyState("pool"), PoolStateStoreUnavailableException);
});
