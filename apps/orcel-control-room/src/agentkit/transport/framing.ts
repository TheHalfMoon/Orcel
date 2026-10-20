// Orcel code (no donor): JSON-lines framing of orcel-app-api/1
// (ORCEL_APP_API_1.md section 3) with the 64 KiB limit applied to incoming
// frames, so the client never buffers more than one frame of unread input.

import { AppApiProtocolError } from "../protocol/errors.js";
import { MAX_FRAME_BYTES } from "../protocol/version.js";

const NEWLINE = 0x0a;
const CARRIAGE_RETURN = 0x0d;

/**
 * Splits a byte stream into lines. A line longer than MAX_FRAME_BYTES,
 * newline included, raises FRAME_TOO_LARGE as soon as the limit is passed,
 * whether or not its newline has arrived. After that the decoder stays
 * failed: the connection must be dropped.
 */
export class LineDecoder {
  private pending: Buffer[] = [];
  private pendingBytes = 0;
  private failed = false;

  public push(chunk: Buffer): string[] {
    if (this.failed) throw tooLarge();
    const lines: string[] = [];
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(NEWLINE, start);
      const end = newline === -1 ? chunk.length : newline;
      const piece = chunk.subarray(start, end);
      // The frame's size is its bytes plus the newline that ends it.
      const size = this.pendingBytes + piece.length + (newline === -1 ? 0 : 1);
      if (size > MAX_FRAME_BYTES) {
        this.failed = true;
        this.pending = [];
        this.pendingBytes = 0;
        throw tooLarge();
      }
      if (newline === -1) {
        this.pending.push(Buffer.from(piece));
        this.pendingBytes += piece.length;
        break;
      }
      let line = Buffer.concat([...this.pending, piece]);
      this.pending = [];
      this.pendingBytes = 0;
      if (line.length > 0 && line[line.length - 1] === CARRIAGE_RETURN) {
        line = line.subarray(0, line.length - 1);
      }
      const text = line.toString("utf8");
      if (text.trim().length > 0) lines.push(text);
      start = newline + 1;
    }
    return lines;
  }

  /** Bytes of a frame whose newline has not arrived yet. */
  public get buffered(): number {
    return this.pendingBytes;
  }
}

function tooLarge(): AppApiProtocolError {
  return new AppApiProtocolError({
    code: "FRAME_TOO_LARGE",
    message: `the server sent a frame over ${MAX_FRAME_BYTES} bytes`,
  });
}
