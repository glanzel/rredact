export interface RedactResponse {
  text: string
  mode?: string
  mapping_stored?: boolean
  findings?: unknown[]
  summary?: unknown
}

export interface RestoreResponse {
  text: string
  restored: number
  unresolved: string[]
}

export interface RedactRequestOptions {
  session?: string
  path?: string
}

function describe(error: unknown): string {
  if (error instanceof Error) {
    if (error.name === "TimeoutError") return "request timed out"
    if (error.name === "AbortError") return "request was aborted"
    return error.message
  }
  return String(error)
}

/**
 * Thin client for the local `rredact serve` HTTP API.
 *
 * The token is only ever sent in the `Authorization` header; it is never put
 * into a URL or an error message.
 */
export class RRedactClient {
  readonly #baseUrl: string
  readonly #token: string | undefined
  readonly #timeoutMs: number

  constructor(baseUrl: string, token: string | undefined, timeoutMs: number) {
    this.#baseUrl = baseUrl.replace(/\/+$/, "")
    this.#token = token
    this.#timeoutMs = timeoutMs
  }

  get baseUrl(): string {
    return this.#baseUrl
  }

  async health(): Promise<void> {
    await this.#request("GET", "/health")
  }

  async redact(text: string, options: RedactRequestOptions = {}): Promise<RedactResponse> {
    const body: Record<string, unknown> = { text }
    if (options.session) body.session = options.session
    if (options.path) body.path = options.path
    const response = await this.#request("POST", "/redact", body)
    if (!isRecord(response) || typeof response.text !== "string") {
      throw new Error("rredact API returned an invalid /redact response")
    }
    return response as unknown as RedactResponse
  }

  async restore(text: string, session?: string): Promise<RestoreResponse> {
    const body: Record<string, unknown> = { text }
    if (session) body.session = session
    const response = await this.#request("POST", "/restore", body)
    if (!isRecord(response) || typeof response.text !== "string") {
      throw new Error("rredact API returned an invalid /restore response")
    }
    return response as unknown as RestoreResponse
  }

  async deleteSession(session: string): Promise<boolean> {
    const response = await this.#request("DELETE", `/sessions/${encodeURIComponent(session)}`)
    return isRecord(response) && response.deleted === true
  }

  async #request(method: string, path: string, body?: unknown): Promise<unknown> {
    const headers: Record<string, string> = {}
    if (this.#token) headers.authorization = `Bearer ${this.#token}`
    if (body !== undefined) headers["content-type"] = "application/json"

    let response: Response
    try {
      response = await fetch(`${this.#baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.#timeoutMs),
      })
    } catch (error) {
      throw new Error(`rredact API ${method} ${path} failed: ${describe(error)}`)
    }

    if (!response.ok) {
      const detail = await response.text().catch(() => "")
      const suffix = detail ? `: ${detail.slice(0, 200)}` : ""
      throw new Error(`rredact API ${method} ${path} returned ${response.status}${suffix}`)
    }

    const text = await response.text()
    if (!text) return undefined
    try {
      return JSON.parse(text)
    } catch {
      throw new Error(`rredact API ${method} ${path} returned invalid JSON`)
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
