// Child process for the live lock tests. Modes:
//   hold <file> <ms>   acquire, print HELD, release after ms, print RELEASED
//   crash <file>       acquire, print HELD, exit without releasing (a crashed holder)
//   race <file> <ms>   one attempt to acquire a stale lock; hold ms; report as JSON
import { acquireLiveLock } from '../../src/live-lock.mjs';

const [mode, file, argument] = process.argv.slice(2);
if (mode === 'hold') {
  const lease = acquireLiveLock(file, { holder: { purpose: 'child-hold' } });
  process.stdout.write('HELD\n');
  setTimeout(() => { lease.release(); process.stdout.write('RELEASED\n'); }, Number(argument));
} else if (mode === 'crash') {
  acquireLiveLock(file, { holder: { purpose: 'child-crash' } });
  process.stdout.write('HELD\n');
  setTimeout(() => process.exit(3), 50);
} else if (mode === 'race') {
  try {
    const lease = acquireLiveLock(file, { holder: { purpose: 'child-race' }, attempts: 1, busyCode: 'LIVE_RUN_BUSY' });
    const start = Date.now();
    const until = start + Number(argument);
    while (Date.now() < until) { /* hold the lock in real time */ }
    const held = lease.holds();
    const released = lease.release();
    process.stdout.write(`${JSON.stringify({ ok: true, ownerId: lease.ownerId, pid: process.pid, start, end: Date.now(), held, released })}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ ok: false, code: error?.code ?? null, pid: process.pid })}\n`);
  }
} else {
  process.stderr.write('unknown mode\n');
  process.exit(2);
}
