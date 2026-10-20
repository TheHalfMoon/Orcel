// The connection's line queue bound (#381 item 3), driven by a scripted
// socket so the number of lines per read chunk is exact.

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";

import { LINE_QUEUE_HIGH, LINE_QUEUE_LOW, SocketConnection, type LineSocket } from "./orceld-transport.js";

/** A socket whose reads are whatever the test emits. */
class ScriptedSocket extends EventEmitter {
  public paused = false;
  public destroyed = false;
  public writable = true;
  public pauses = 0;

  public pause(): this {
    if (!this.paused) this.pauses += 1;
    this.paused = true;
    return this;
  }

  public resume(): this {
    this.paused = false;
    return this;
  }

  public isPaused(): boolean {
    return this.paused;
  }

  public destroy(): this {
    this.destroyed = true;
    this.emit("close");
    return this;
  }

  public write(): boolean {
    return true;
  }
}

function connect(): { socket: ScriptedSocket; connection: SocketConnection } {
  const socket = new ScriptedSocket();
  return { socket, connection: new SocketConnection(socket as unknown as LineSocket) };
}

test("one read chunk of many lines never queues more than LINE_QUEUE_HIGH", async () => {
  const { socket, connection } = connect();
  const lines = Array.from({ length: 1_000 }, (_, n) => `{"n":${n}}`);
  // All 1,000 lines in a single chunk: the old per-chunk check queued all
  // of them before pausing.
  socket.emit("data", Buffer.from(`${lines.join("\n")}\n`));
  assert.equal(connection.queuedLines, LINE_QUEUE_HIGH);
  assert.equal(socket.isPaused(), true);
  socket.emit("end");
  const received: string[] = [];
  let most = 0;
  for await (const line of connection.lines()) {
    received.push(line);
    most = Math.max(most, connection.queuedLines);
    if (received.length === 500) {
      // Bytes of the chunk are still held, so reading stays paused.
      assert.equal(socket.isPaused(), true);
    }
  }
  assert.deepEqual(received, lines);
  assert.ok(most <= LINE_QUEUE_HIGH, `the queue reached ${most}`);
});

test("reading resumes only at the low mark once nothing is held", async () => {
  const { socket, connection } = connect();
  const lines = Array.from({ length: LINE_QUEUE_HIGH + 10 }, (_, n) => `l${n}`);
  socket.emit("data", Buffer.from(`${lines.join("\n")}\n`));
  assert.equal(socket.isPaused(), true);
  const iterator = connection.lines()[Symbol.asyncIterator]();
  let taken = 0;
  while (connection.queuedLines > LINE_QUEUE_LOW + 1) {
    await iterator.next();
    taken += 1;
    assert.equal(socket.isPaused(), true, `resumed early after ${taken} lines`);
  }
  await iterator.next();
  assert.equal(socket.isPaused(), false);
  socket.emit("end");
  for (let result = await iterator.next(); !result.done; result = await iterator.next()) taken += 1;
  assert.equal(taken + 1, lines.length);
});

test("a frame split across reads is joined, and an oversize one still fails", async () => {
  const { socket, connection } = connect();
  socket.emit("data", Buffer.from('{"a":'));
  socket.emit("data", Buffer.from('1}\n{"b":2}\n'));
  socket.emit("end");
  const received: string[] = [];
  for await (const line of connection.lines()) received.push(line);
  assert.deepEqual(received, ['{"a":1}', '{"b":2}']);

  const big = connect();
  big.socket.emit("data", Buffer.alloc(70 * 1024, 0x78));
  assert.equal(big.socket.destroyed, true);
  await assert.rejects(
    (async () => {
      for await (const _line of big.connection.lines()) {
        // nothing is delivered
      }
    })(),
    /FRAME_TOO_LARGE|over 65536 bytes/u,
  );
});
