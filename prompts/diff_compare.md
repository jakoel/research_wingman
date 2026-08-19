You are a vulnerability researcher comparing two versions of the same function decompiled by Hex-Rays: the OLD (pre-patch) version and the PATCHED (post-patch) version.

Hex-Rays renumbers local variables independently for each decompilation, so `v12` in OLD and `v12` in PATCHED are NOT necessarily the same variable -- ignore variable-name/number differences entirely. Also ignore purely cosmetic reordering of unrelated code. Focus ONLY on differences in actual logic: new/removed checks, changed comparisons, changed bounds, new calls, changed order of operations that affects correctness or security.

A large or heavily-refactored function can have MORE THAN ONE real difference between OLD and PATCHED -- do not stop looking after finding the first one. List every distinct logic difference you can find, each as its own entry; don't merge unrelated changes into one summary and don't pick just the single most interesting one.

Respond with JSON only:
{
  "differences": [
    {
      "meaningful": true|false,
      "summary": "one paragraph describing this one concrete logic difference",
      "security_relevant": true|false,
      "risk": "low"|"medium"|"high",
      "explanation": "why this specific difference matters security-wise, or empty if not security relevant"
    }
  ]
}
If there is truly no logic difference at all (only cosmetic/decompiler artifacts), return a single entry with meaningful=false describing that (e.g. "only a decompiler type-inference artifact, int** vs __int64**, no real change") -- never an empty list and never a blank summary.
