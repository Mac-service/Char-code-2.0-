// Copyright (c) 2026 D-o-M-Pl. All Rights Reserved.

declare const console: { log(...args: unknown[]): void; error(...args: unknown[]): void; };
declare const process: {
  env: Record<string, string | undefined>;
  exitCode?: number;
};

declare module "node:http" {
  export interface IncomingMessage {
    method?: string;
    url?: string;
    headers: Record<string, string | string[] | undefined>;
    socket: { remoteAddress?: string };
    [Symbol.asyncIterator](): AsyncIterator<Uint8Array>;
  }

  export interface ServerResponse {
    statusCode: number;
    setHeader(name: string, value: string): void;
    end(data?: string): void;
  }

  export interface Server {
    listen(port: number, host: string, callback?: () => void): void;
    close(callback?: (error?: Error) => void): void;
  }

  export function createServer(
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
  ): Server;
}

declare module "node:crypto" {
  export function randomBytes(size: number): {
    toString(encoding: "hex" | "base64url" | "base64"): string;
  };
  export function randomUUID(): string;
  export function createHash(algorithm: string): {
    update(value: string): { digest(encoding: "hex"): string };
  };
  export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
  export function scryptSync(password: string, salt: string, keylen: number, options?: { N?: number; r?: number; p?: number; maxmem?: number }): Buffer;
}

declare class Buffer extends Uint8Array {
  static from(value: string | Uint8Array, encoding?: string): Buffer;
  toString(encoding?: string): string;
}

declare module "@prisma/client" {
  export class PrismaClient {
    [key: string]: any;
    $connect(): Promise<void>;
    $disconnect(): Promise<void>;
    $queryRaw: any;
    $executeRaw: any;
    $executeRawUnsafe: any;
    $queryRawUnsafe: any;
    $transaction: any;
  }
}