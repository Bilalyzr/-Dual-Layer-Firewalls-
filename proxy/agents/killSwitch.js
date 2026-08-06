/**
 * EPIC K — System-wide agent kill switch.
 *
 * An emergency halt that, when engaged, refuses ALL agent (Trifecta) actions
 * immediately — no Reader, no Actor, no tool calls. Used during an incident or
 * when a vulnerability is suspected. Toggleable via env (KILL_SWITCH=on) or the
 * /api/response ops endpoint, and every engagement is hash-chained into the
 * audit log (EPIC I).
 */
import { appendAudit } from "../compliance/auditChain.js";

let _engaged = process.env.KILL_SWITCH === "on";

export function killSwitchEngaged() {
  return _engaged;
}

export function engage(reason = "manual") {
  if (!_engaged) {
    _engaged = true;
    appendAudit("kill_switch", { action: "engage", reason });
  }
  return _engaged;
}

export function disengage(reason = "manual") {
  if (_engaged) {
    _engaged = false;
    appendAudit("kill_switch", { action: "disengage", reason });
  }
  return _engaged;
}

/** Middleware-style guard for the orchestrator: throws if the switch is on. */
export function assertAgentsAllowed() {
  if (_engaged) {
    const err = new Error("agent_kill_switch_engaged");
    err.killSwitch = true;
    throw err;
  }
}
