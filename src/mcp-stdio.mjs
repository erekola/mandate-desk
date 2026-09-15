// Shared newline-delimited JSON-RPC transport for local MCP sessions.
// It writes protocol messages to stdout and never emits application logs there.
const MAX_LINE_BYTES = 65536;

export function runMcpStdio(session, { input = process.stdin, output = process.stdout } = {}) {
  let pending = Buffer.alloc(0);
  let discardingOversizedLine = false;
  const write = message => output.write(JSON.stringify(message) + '\n');
  // Replies keep request order even when a session answers asynchronously.
  let queue = Promise.resolve();
  const enqueue = work => { queue = queue.then(work, work); };
  const oversized = () => enqueue(() => write({
    jsonrpc: '2.0',
    id: null,
    error: { code: -32700, message: `Parse error: input line exceeds ${MAX_LINE_BYTES} bytes` }
  }));
  const handle = line => {
    const text = line.toString('utf8');
    if (!text.trim()) return;
    enqueue(async () => {
      let reply;
      try { reply = await session.handle(JSON.parse(text)); }
      catch { reply = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }; }
      if (reply) write(reply);
    });
  };
  input.on('data', chunk => {
    let offset = 0;
    while (offset < chunk.length) {
      if (discardingOversizedLine) {
        const end = chunk.indexOf(0x0a, offset);
        if (end === -1) return;
        discardingOversizedLine = false;
        offset = end + 1;
        continue;
      }
      const end = chunk.indexOf(0x0a, offset);
      if (end !== -1) {
        const part = chunk.subarray(offset, end);
        const rawLength = pending.length + part.length;
        const trailingByte = part.length ? part[part.length - 1] : pending[pending.length - 1];
        const lineLength = rawLength - (trailingByte === 0x0d ? 1 : 0);
        if (lineLength > MAX_LINE_BYTES) oversized();
        else {
          const rawLine = pending.length ? Buffer.concat([pending, part], rawLength) : part;
          handle(trailingByte === 0x0d ? rawLine.subarray(0, -1) : rawLine);
        }
        pending = Buffer.alloc(0);
        offset = end + 1;
        continue;
      }
      const part = chunk.subarray(offset);
      const combinedLength = pending.length + part.length;
      const trailingByte = part.length ? part[part.length - 1] : pending[pending.length - 1];
      const limit = MAX_LINE_BYTES + (trailingByte === 0x0d ? 1 : 0);
      if (combinedLength > limit) {
        oversized();
        pending = Buffer.alloc(0);
        discardingOversizedLine = true;
      } else pending = pending.length ? Buffer.concat([pending, part], combinedLength) : Buffer.from(part);
      return;
    }
  });
}
