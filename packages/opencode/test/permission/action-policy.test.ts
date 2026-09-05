import { describe, expect, test } from "bun:test"
import { ActionPolicy } from "../../src/permission/action-policy"

describe("action policy", () => {
  test.each<[string, ActionPolicy.Result["decision"]]>([
    ["git status", "allow"],
    ["aws s3 ls s3://prod-data", "allow"],
    ["SELECT * FROM prod.users", "allow"],
    ["git push origin feature", "allow"],
  ])("allows %s", (command, decision) => {
    expect(ActionPolicy.classify({ tool: "bash", args: { command } }).decision).toBe(decision)
  })

  test.each<[string, ActionPolicy.Result["decision"]]>([
    ["aws s3 rm s3://prod-data/file", "ask"],
    ["redis-cli -h prod SET flag true", "ask"],
    ["psql prod -c 'UPDATE users SET active=false'", "ask"],
    ["helm upgrade api chart -n staging", "ask"],
    ["kubectl create rolebinding admin", "ask"],
  ])("asks for %s", (command, decision) => {
    expect(ActionPolicy.classify({ tool: "bash", args: { command } }).decision).toBe(decision)
  })

  test.each<[string, ActionPolicy.Result["decision"]]>([
    ["gh pr merge 12", "deny"],
    ["git push origin main", "deny"],
    ["git push --force origin feature", "deny"],
    ["claude --dangerously-skip-permissions", "deny"],
  ])("denies %s", (command, decision) => {
    expect(ActionPolicy.classify({ tool: "bash", args: { command } }).decision).toBe(decision)
  })

  test("asks for outbound messages", () => {
    expect(ActionPolicy.classify({ tool: "slack_slack_send_message", args: { message: "hello" } }).decision).toBe("ask")
  })

  test("denies shell comments without attribution", () => {
    expect(
      ActionPolicy.classify({ tool: "bash", args: { command: "gh pr comment 12 --body 'done'" } }),
    ).toEqual({ decision: "deny", reason: "Outbound shell messages must include the LLM attribution" })
  })

  test("asks for attributed shell comments", () => {
    expect(
      ActionPolicy.classify({
        tool: "bash",
        args: { command: "gh pr comment 12 --body 'done _Posted by an LLM on behalf of Yael._'" },
      }).decision,
    ).toBe("ask")
  })

  test("adds attribution once", () => {
    const args = { message: "hello" }
    ActionPolicy.appendAttribution("slack_slack_send_message", args)
    ActionPolicy.appendAttribution("slack_slack_send_message", args)
    expect(args.message).toBe("hello\n\n_Posted by an LLM on behalf of Yael._")
  })

  test("custom rules can add restrictions", () => {
    expect(
      ActionPolicy.classify(
        { tool: "bash", args: { command: "deploy staging" } },
        [{ name: "staging deploy", decision: "deny", tool: "bash", pattern: "deploy staging" }],
      ),
    ).toEqual({ decision: "deny", reason: "staging deploy" })
  })
})
