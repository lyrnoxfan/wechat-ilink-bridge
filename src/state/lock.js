import { mkdir, open, rm, readFile } from "node:fs/promises";
import path from "node:path";
import { WxbError } from "../core/errors.js";
import { accountStatePath, safeAccountId } from "./state-dir.js";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function accountLockPath(stateDir, accountId) {
  return accountStatePath(stateDir, safeAccountId(accountId), ".lock");
}

function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the process exists but we cannot signal it.
    return error?.code === "EPERM";
  }
}

async function isLockStale(lockPath) {
  let raw;
  try {
    raw = await readFile(lockPath, "utf8");
  } catch {
    return true;
  }
  let pid;
  try {
    pid = JSON.parse(raw)?.pid;
  } catch {
    return true;
  }
  return !isPidAlive(pid);
}

export async function acquireAccountLock(stateDir, accountId, options = {}) {
  const timeoutMs = options.timeoutMs ?? 5000;
  const retryDelayMs = options.retryDelayMs ?? 50;
  const lockPath = accountLockPath(stateDir, accountId);
  const deadline = Date.now() + timeoutMs;
  await mkdir(path.dirname(lockPath), { recursive: true });

  while (true) {
    try {
      const handle = await open(lockPath, "wx");
      const payload = {
        pid: process.pid,
        accountId,
        createdAt: new Date().toISOString()
      };
      await handle.writeFile(JSON.stringify(payload), "utf8");

      let released = false;
      return {
        path: lockPath,
        async release() {
          if (released) {
            return;
          }
          released = true;
          await handle.close();
          await rm(lockPath, { force: true });
        }
      };
    } catch (error) {
      if (error.code !== "EEXIST") {
        throw error;
      }

      // A crashed or kill -9'd process leaves its .lock file behind forever.
      // Reclaim it when the recorded pid is gone instead of timing out.
      if (await isLockStale(lockPath)) {
        await rm(lockPath, { force: true });
        continue;
      }

      if (Date.now() >= deadline) {
        throw new WxbError("STATE_LOCK_TIMEOUT", `Timed out waiting for account lock: ${accountId}`, {
          retryable: true,
          details: { accountId, lockPath }
        });
      }

      await sleep(retryDelayMs);
    }
  }
}

export async function withAccountLock(stateDir, accountId, callback, options = {}) {
  const lock = await acquireAccountLock(stateDir, accountId, options);
  try {
    return await callback();
  } finally {
    await lock.release();
  }
}
