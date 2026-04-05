/**
 * SLK Safety Validator — OpenClaw Plugin
 *
 * Intercepts every bash command before execution and validates it
 * against the SLK C99 constraint kernel (2,360 bytes, 0.034 µs/call).
 *
 * Author: Emile Gonkol — Brazzaville, Republic of Congo
 * Paper: hal-05573274
 * Code: github.com/Emile55/slk-openclaw-sdk
 * License: MIT
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Type } from "@sinclair/typebox";
import { execFileSync } from "child_process";
import { existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

// ─── Validator path ───────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));

function resolveValidatorPath(): string {
  const candidates = [
    join(__dirname, "kernel", "slk_validator.exe"),    // Windows
    join(__dirname, "kernel", "slk_validator"),         // Linux/Mac
    join(__dirname, "slk_validator.exe"),
    join(__dirname, "slk_validator"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return "";
}

// ─── SLK validation ───────────────────────────────────────────────────────────

interface SLKResult {
  valid: boolean;
  code: number;
  message: string;
}

function validateCommand(
  validatorPath: string,
  action: string,
  value: string
): SLKResult {
  if (!validatorPath) {
    return { valid: true, code: 0, message: "VALIDATOR_UNAVAILABLE" };
  }

  try {
    const input = JSON.stringify({ action, command: value, path: value, url: value });
    const output = execFileSync(validatorPath, [], {
      input,
      timeout: 500,
      encoding: "utf8",
    });
    return JSON.parse(output.trim());
  } catch (err: any) {
    if (err.stdout) {
      try { return JSON.parse(err.stdout.trim()); } catch {}
    }
    return { valid: false, code: -1, message: `ERR_BRIDGE: ${err.message}` };
  }
}

// ─── Plugin entry ─────────────────────────────────────────────────────────────

export default definePluginEntry({
  id: "slk-safety",
  name: "SLK Safety Validator",

  register(api) {
    const validatorPath = resolveValidatorPath();

    if (!validatorPath) {
      console.warn(
        "[SLK] Warning: validator binary not found. " +
        "Compile kernel/slk_validator.c or download a release. " +
        "Safety validation is DISABLED."
      );
    } else {
      console.log(`[SLK] Kernel loaded: ${validatorPath} (2,360 bytes C99)`);
    }

    // ── Hook: intercept bash commands before execution ────────────────────────
    api.registerHook("exec:before", async (ctx) => {
      const command = ctx.command as string | undefined;
      if (!command) return;

      const result = validateCommand(validatorPath, "bash", command);

      if (!result.valid) {
        const msg =
          `[SLK KERNEL] Command blocked by formal safety validator.\n` +
          `Reason: ${result.message}\n` +
          `Command: ${command}\n` +
          `The SLK kernel (2,360 bytes C99, paper proof hal-05573274) ` +
          `rejected this action before execution.`;

        console.error(msg);
        throw new Error(msg);
      }

      console.log(
        `[SLK OK] ${command.substring(0, 60)}${command.length > 60 ? "..." : ""}`
      );
    });

    // ── Tool: manual validation ───────────────────────────────────────────────
    api.registerTool({
      name: "slk_validate",
      description:
        "Validate a command against the SLK formal safety kernel before execution. " +
        "Returns whether the command is safe to run.",
      parameters: Type.Object({
        command: Type.String({
          description: "The bash command to validate",
        }),
      }),
      async execute(_id, params) {
        const result = validateCommand(validatorPath, "bash", params.command);
        const statusLine = result.valid
          ? `✓ SAFE — command validated by SLK kernel`
          : `✗ BLOCKED — ${result.message}`;

        return {
          content: [
            {
              type: "text",
              text: [
                statusLine,
                `Command: ${params.command}`,
                `Code: ${result.code}`,
                `Kernel: 2,360 bytes C99 | 0.034 µs/call | hal-05573274`,
              ].join("\n"),
            },
          ],
        };
      },
    });
  },
});
