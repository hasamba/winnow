// The server itself: a node:http listener on loopback, and the lifecycle around it.
//
// No framework. The whole API is one handler (routes.ts) over twenty endpoints, and this tool
// keeps exactly one runtime dependency — the SQLite driver that holds the evidence.

import { spawn } from "node:child_process";
import { createServer as createHttpServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import { BIND_HOST, DEFAULT_PORT } from "./contract.js";
import { JobRunner } from "./jobs.js";
import { handleRequest, type RouteContext } from "./routes.js";

/** The first port plus this many retries. A busy port is usually yesterday's winnow. */
const PORT_ATTEMPTS = 11;

/**
 * public/ is NOT copied into dist/ — it is served from the package root either way, so this
 * resolves two levels up from this module, which is the root from src/server and from
 * dist/server alike. The same trick as readToolInfo() in export/manifest.ts.
 */
const PUBLIC_DIR = fileURLToPath(new URL("../../public/", import.meta.url));

export function createServer(ctx: RouteContext): Server {
  return createHttpServer((req, res) => {
    // The handler is async, so a rejection it did not catch would otherwise be an unhandled
    // rejection and the socket would hang until the browser gave up. A running judge pass
    // must never be taken down by one bad request.
    void handleRequest(req, res, ctx).catch(() => {
      if (!res.headersSent) {
        res.writeHead(500, {
          "Content-Type": "application/json; charset=utf-8",
          "X-Content-Type-Options": "nosniff",
        });
        res.end(JSON.stringify({ error: "The server failed to handle that request." }));
        return;
      }
      res.destroy();
    });
  });
}

export interface ServeOptions {
  readonly port?: number;
  readonly questionsPath?: string;
  /** Open the dashboard in the default browser once the port is known. */
  readonly open?: boolean;
}

export async function serve(
  opts: ServeOptions = {},
): Promise<{ url: string; close: () => Promise<void> }> {
  const runner = new JobRunner(opts.questionsPath);
  const ctx: RouteContext = {
    runner,
    publicDir: PUBLIC_DIR,
    ...(opts.questionsPath !== undefined ? { questionsPath: opts.questionsPath } : {}),
  };
  const server = createServer(ctx);

  const first = opts.port ?? DEFAULT_PORT;
  // Port 0 means "any free port"; retrying it as 1, 2, 3 would be nonsense.
  const attempts = first === 0 ? 1 : PORT_ATTEMPTS;
  let bound: number | undefined;
  for (let i = 0; i < attempts; i += 1) {
    try {
      bound = await listen(server, first + i);
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EADDRINUSE") throw err;
    }
  }
  if (bound === undefined) {
    throw new Error(
      `Ports ${first} to ${first + attempts - 1} are all in use. ` +
        `Another winnow is probably still running; stop it, or pass --port.`,
    );
  }

  const url = `http://${BIND_HOST}:${bound}`;
  // stderr, not stdout: a caller piping this command's output is after the report, not the
  // banner. And the port is worth saying out loud, because it may not be the one that was asked for.
  process.stderr.write(`winnow dashboard listening on ${url}\n`);
  if (opts.open === true) openBrowser(url);

  return {
    url,
    close: async () => {
      runner.cancel();
      // An open event stream never ends on its own, so close() alone would wait forever.
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      runner.close();
    },
  };
}

/** Bind one port, resolving with the port actually bound (which is what port 0 is for). */
async function listen(server: Server, port: number): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const onError = (err: Error): void => {
      server.removeListener("listening", onListening);
      reject(err);
    };
    const onListening = (): void => {
      server.removeListener("error", onError);
      const address = server.address();
      resolve(typeof address === "object" && address !== null ? address.port : port);
    };
    server.once("error", onError);
    server.once("listening", onListening);
    // BIND_HOST, explicitly and always. listen(port) alone binds every interface, which would
    // hand the whole filesystem — see browse.ts — to anyone who can reach this machine.
    server.listen(port, BIND_HOST);
  });
}

function openBrowser(url: string): void {
  const command =
    process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
  try {
    // Detached and ignored: a headless box with no xdg-open must not take the server with it.
    spawn(command, [url], {
      stdio: "ignore",
      detached: true,
      shell: process.platform === "win32",
    })
      .on("error", () => undefined)
      .unref();
  } catch {
    process.stderr.write(`Could not open a browser. Visit ${url}\n`);
  }
}
