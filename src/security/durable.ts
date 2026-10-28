// Flush a file to disk where the platform allows it.
// The Node permission model (used by the release bundle on Node 22.23.4 / 24.22.1 / 26.12.1+) disables fsync and
// fdatasync for every file handle. Inside it, written data is still in the operating system's cache: it survives a
// keysentry crash but not a power loss in the next seconds. Rotation recovery already treats a lost in-flight value
// as an orphan suspect and revokes nothing, so the sandbox costs availability in that rare case, never safety.

let limited = false;

export async function syncFile(handle: { sync(): Promise<void> }): Promise<'synced' | 'unavailable'> {
  try {
    await handle.sync();
    return 'synced';
  } catch (error) {
    const permissionModel = (process as { permission?: unknown }).permission !== undefined;
    if (permissionModel && error instanceof Error && 'code' in error && error.code === 'ERR_ACCESS_DENIED') {
      limited = true;
      return 'unavailable';
    }
    throw error;
  }
}

/** True once a flush was refused by the Node permission model in this process (shown by doctor). */
export function durableSyncLimited(): boolean {
  return limited;
}
