import { Global } from "@opencode-ai/core/global"
import path from "path"

export type Rule = {
  name: string
  decision: "ask" | "deny"
  tool?: string
  pattern: string
}

export type Config = {
  enabled: boolean
  rules: Rule[]
}

export type Result = { decision: "allow" | "ask" | "deny"; reason?: string }

const merge = /\b(gh\s+pr\s+merge|git\s+merge\b|auto[ -]?merge)\b/i
const directPush = /\bgit\s+push\b[^\n]*(?:\bmain\b|\bmaster\b)/i
const forcePush = /\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?|-f\b)/i
const bypass = /\b(dangerously[ _-]skip[ _-]permissions|bypass[ _-]permissions|breakglass|allow[ _-]unsafe|no[ _-]sandbox)\b/i
const production = /(?:^|[\s_./:-])(prod|production)(?:$|[\s_./:-])/i
const mutation = /\b(add|append|apply|cancel|close|create|delete|deploy|destroy|disable|dismiss|drop|enable|insert|materialize|merge|modify|move|mute|patch|publish|put|redrive|remove|rename|reopen|reply|reset|resolve|restart|revoke|rm|rotate|scale|schedule|send|set|start|stop|terminate|transition|unmute|update|upload|write)\b/i
const dbWrite = /\b(insert|update|delete|merge|create\s+(?:table|database|schema|index)|alter|drop|truncate|grant|revoke)\b/i
const accessChange = /\b(iam|rbac|permission|policy|role|rolebinding|clusterrole|clusterrolebinding|access|secret|credential|certificate|api[ _-]?key)\b/i
const sharedApply = /\b(helm\s+(?:install|upgrade|uninstall)|kubectl\s+(?:apply|create|delete|patch|replace|scale)|terraform\s+(?:apply|destroy)|pulumi\s+(?:up|destroy)|cdk\s+(?:deploy|destroy))\b/i
const outbound = /\b(comment|reply|send|post|publish|create|update|close|resolve|schedule|share)\b/i
const outboundTool = /^(?:slack|shortcut|notion|gws|datadog|sentra)[ _-]/i
const sentraMutation = /^(?:sentra|dagster|athena)[ _-]/i
const shellOutbound = /\bgh\s+(?:api|issue|pr)\b[^\n]*(?:comment|reviews|replies|issues|pulls)|\b(?:slack|notion|shortcut)\b[^\n]*(?:send|post|comment|create)/i
const attribution = /_Posted by an LLM on behalf of Yael\._/

function normalize(input: unknown) {
  return JSON.stringify(input ?? {}).replace(/[_-]+/g, " ")
}

function matches(pattern: string, value: string) {
  return new RegExp(pattern, "i").test(value)
}

export function classify(input: { tool: string; args: unknown }, rules: ReadonlyArray<Rule> = []): Result {
  const raw = `${input.tool} ${JSON.stringify(input.args ?? {})}`
  const value = `${input.tool.replace(/[_-]+/g, " ")} ${normalize(input.args)}`

  if (merge.test(value)) return { decision: "deny", reason: "Only the user may merge" }
  if (directPush.test(value)) return { decision: "deny", reason: "Direct pushes to main or master are forbidden" }
  if (forcePush.test(raw)) return { decision: "deny", reason: "Force-push is forbidden" }
  if (bypass.test(value)) return { decision: "deny", reason: "Permission and sandbox bypasses are forbidden" }
  if (input.tool === "bash" && shellOutbound.test(raw) && !attribution.test(raw)) {
    return { decision: "deny", reason: "Outbound shell messages must include the LLM attribution" }
  }
  if (input.tool === "bash" && shellOutbound.test(raw)) {
    return { decision: "ask", reason: "Outbound messages and comments require approval" }
  }
  if (production.test(value) && (mutation.test(value) || dbWrite.test(value))) {
    return { decision: "ask", reason: "Production mutation requires approval for this exact action" }
  }
  if (accessChange.test(value) && mutation.test(value)) {
    return { decision: "ask", reason: "Permission or credential changes require approval" }
  }
  if (sharedApply.test(value)) return { decision: "ask", reason: "Shared infrastructure changes require approval" }
  if (sentraMutation.test(input.tool) && mutation.test(value)) {
    return { decision: "ask", reason: "Sentra service mutation requires approval" }
  }
  if (outboundTool.test(input.tool) && outbound.test(value)) {
    return { decision: "ask", reason: "Outbound messages and comments require approval" }
  }

  const custom = rules.findLast((rule) => (!rule.tool || matches(rule.tool, input.tool)) && matches(rule.pattern, raw))
  if (custom) return { decision: custom.decision, reason: custom.name }
  return { decision: "allow" }
}

export function appendAttribution(tool: string, args: Record<string, unknown>) {
  if (!outboundTool.test(tool) || !outbound.test(tool.replace(/[_-]+/g, " "))) return
  const footer = "_Posted by an LLM on behalf of Yael._"
  for (const key of ["message", "text", "comment", "comment_content", "body", "initial_comment"]) {
    const value = args[key]
    if (typeof value !== "string" || value.includes(footer)) continue
    args[key] = `${value.trimEnd()}\n\n${footer}`
  }
}

function isRule(value: unknown): value is Rule {
  if (!value || typeof value !== "object") return false
  const rule = value as Record<string, unknown>
  return typeof rule.name === "string" && ["ask", "deny"].includes(String(rule.decision)) && typeof rule.pattern === "string"
}

export async function load(): Promise<Config> {
  const value = await Bun.file(path.join(Global.Path.config, "action-policy.json"))
    .json()
    .catch(() => ({}))
  if (!value || typeof value !== "object") return { enabled: false, rules: [] }
  const config = value as Record<string, unknown>
  return {
    enabled: config.enabled === true,
    rules: Array.isArray(config.rules) ? config.rules.filter(isRule) : [],
  }
}

export * as ActionPolicy from "./action-policy"
