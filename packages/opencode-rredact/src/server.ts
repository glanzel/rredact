import { spawn, type ChildProcess } from "node:child_process"
import { randomBytes } from "node:crypto"
import { setTimeout as delay } from "node:timers/promises"

import { RRedactClient } from "./client.ts"
import type { ResolvedOptions } from "./options.ts"

const LISTENING_PATTERN = /listening on (https?:\/\/\S+)/

function describe(error: unknown): string {
  if (error instanceof Error) return error.message
  return String(error)
}

/**
 * Owns either a spawned `rredact serve` child process or a connection to an
 * external server. A startup failure is remembered so every hook can fail
 * closed with a useful message instead of silently sending plaintext.
 */
export class RRedactRuntime {
  readonly #options: ResolvedOptions
  readonly #cwd: string
  #client: RRedactClient | undefined
  #child: ChildProcess | undefined
  #starting: Promise<void> | undefined
  #failure: string | undefined
  #ready = false
  #stopping = false

  constructor(options: ResolvedOptions, cwd: string) {
    this.#options = options
    this.#cwd = cwd
  }

  get failure(): string | undefined {
    return this.#failure
  }

  start(): Promise<void> {
    this.#starting ??= this.#start()
    return this.#starting
  }

  async client(): Promise<RRedactClient> {
    if (this.#client) return this.#client
    await this.start()
    if (this.#client) return this.#client
    throw new Error(this.#failure ?? "rredact server is not ready")
  }

  async redact(text: string, session: string, path?: string): Promise<string> {
    const client = await this.client()
    const response = await client.redact(text, { session, path })
    return response.text
  }

  async restoreText(text: string, session: string): Promise<string> {
    const client = await this.client()
    const response = await client.restore(text, session)
    return response.text
  }

  async deleteSession(session: string): Promise<void> {
    if (!this.#client) return
    try {
      await this.#client.deleteSession(session)
    } catch (error) {
      console.error(`[rredact] could not delete the session mapping: ${describe(error)}`)
    }
  }

  async stop(): Promise<void> {
    this.#stopping = true
    if (this.#starting) {
      await this.#starting.catch(() => {})
    }
    const child = this.#child
    this.#child = undefined
    this.#client = undefined
    if (!child || child.exitCode !== null || child.signalCode !== null) return

    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        try {
          child.kill("SIGKILL")
        } catch {
          // The process may have exited between the check and the signal.
        }
        resolve()
      }, 2_000)
      child.once("exit", () => {
        clearTimeout(timer)
        resolve()
      })
      try {
        child.kill("SIGTERM")
      } catch {
        clearTimeout(timer)
        resolve()
      }
    })
  }

  async #start(): Promise<void> {
    try {
      if (this.#options.url) {
        const client = new RRedactClient(
          this.#options.url,
          this.#options.token,
          this.#options.requestTimeoutMs,
        )
        await waitForHealth(client, this.#options.startupTimeoutMs)
        this.#client = client
        this.#ready = true
        return
      }

      const client = await this.#spawnServer()
      this.#client = client
      this.#ready = true
    } catch (error) {
      this.#failure = describe(error)
      throw error
    }
  }

  async #spawnServer(): Promise<RRedactClient> {
    const token = this.#options.token ?? randomBytes(32).toString("hex")
    const args = [
      "serve",
      "--host",
      "127.0.0.1",
      "--port",
      "0",
      "--token",
      token,
      ...this.#options.args,
    ]

    const child = spawn(this.#options.binary, args, {
      cwd: this.#cwd,
      env: { ...process.env, ...this.#options.env },
      stdio: ["ignore", "pipe", "pipe"],
    })
    this.#child = child

    child.once("error", (error) => {
      this.#failure = `could not start ${this.#options.binary}: ${describe(error)}`
    })
    child.once("exit", (code, signal) => {
      this.#client = undefined
      if (this.#stopping) return
      const reason = `rredact server exited (code ${code ?? "none"}, signal ${signal ?? "none"})`
      this.#failure = this.#failure ? `${this.#failure}; ${reason}` : reason
      if (this.#ready) {
        console.error(`[rredact] ${reason}; refusing to send unredacted content`)
      }
    })

    const url = await this.#readListeningUrl(child)
    const client = new RRedactClient(url, token, this.#options.requestTimeoutMs)
    await waitForHealth(client, Math.min(this.#options.startupTimeoutMs, 5_000))
    return client
  }

  #readListeningUrl(child: ChildProcess): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let buffer = ""
      let settled = false

      const tail = (): string => {
        const lines = buffer
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean)
          .slice(-3)
          .join(" | ")
        return lines ? ` (${lines.slice(0, 500)})` : ""
      }

      const finish = (error?: Error, url?: string): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        child.stderr?.off("data", onData)
        child.stdout?.off("data", onData)
        child.off("error", onError)
        child.off("exit", onExit)
        // Keep draining the pipes so the child never blocks on a full buffer.
        child.stderr?.resume()
        child.stdout?.resume()
        if (error) reject(error)
        else resolve(url as string)
      }

      const onData = (chunk: Buffer): void => {
        buffer += chunk.toString("utf8")
        if (buffer.length > 64_000) buffer = buffer.slice(-64_000)
        const match = LISTENING_PATTERN.exec(buffer)
        if (match?.[1]) finish(undefined, match[1])
      }

      const onError = (error: Error): void => {
        finish(new Error(`could not start ${this.#options.binary}: ${describe(error)}`))
      }

      const onExit = (code: number | null, signal: NodeJS.Signals | null): void => {
        finish(
          new Error(
            `rredact exited before it was ready (code ${code ?? "none"}, signal ${signal ?? "none"})${tail()}`,
          ),
        )
      }

      const timer = setTimeout(() => {
        finish(
          new Error(
            `rredact did not report an address within ${this.#options.startupTimeoutMs} ms${tail()}`,
          ),
        )
      }, this.#options.startupTimeoutMs)

      child.stderr?.on("data", onData)
      child.stdout?.on("data", onData)
      child.once("error", onError)
      child.once("exit", onExit)
    })
  }
}

async function waitForHealth(client: RRedactClient, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let last: unknown
  while (Date.now() < deadline) {
    try {
      await client.health()
      return
    } catch (error) {
      last = error
    }
    await delay(100)
  }
  throw new Error(`rredact health check failed: ${describe(last)}`)
}
