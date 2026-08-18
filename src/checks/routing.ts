/** Common positive-routing language used in skill descriptions. */
const USE_TRIGGER_RE = /\buse(?:\s+(?:it|this(?:\s+skill)?))?\s+(?:when|for)\b/i;
const CONTEXT_TRIGGER_RE = /\b(?:when|before|after|for)\s+\S/i;

/** Common negative-routing language used in skill descriptions. */
const ANTI_TRIGGER_RE =
  /\b(?:do not use|don't use|never use|not for|not to be used|out of scope|stay silent)\b/i;

export function hasPositiveRoutingTrigger(description: string): boolean {
  return USE_TRIGGER_RE.test(description) || CONTEXT_TRIGGER_RE.test(description);
}

export function hasAntiTrigger(description: string): boolean {
  return ANTI_TRIGGER_RE.test(description);
}
