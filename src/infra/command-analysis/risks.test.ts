import { describe, expect, it } from "vitest";
import {
  buildCommandPayloadCandidates,
  detectCarriedShellBuiltinArgv,
  detectCommandCarrierArgv,
  detectEnvSplitStringFlag,
  detectInlineEvalArgv,
  detectInlineEvalInSegments,
  detectShellWrapperThroughCarrierArgv,
} from "./risks.js";

describe("command-analysis risks", () => {
  it("detects inline eval through transparent carriers", () => {
    expect(detectInlineEvalArgv(["python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["sudo", "python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["sudo", "-u", "root", "python3", "-c", "print(1)"])?.flag).toBe(
      "-c",
    );
    expect(detectInlineEvalArgv(["sudo", "-uroot", "python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["sudo", "-EH", "python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["sudo", "-i", "python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["sudo", "-s", "python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["sudo", "-k", "python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(
      detectInlineEvalArgv(["sudo", "--reset-timestamp", "python3", "-c", "print(1)"])?.flag,
    ).toBe("-c");
    expect(
      detectInlineEvalArgv(["sudo", "--command-timeout=1", "python3", "-c", "print(1)"])?.flag,
    ).toBe("-c");
    expect(detectInlineEvalArgv(["sudo", "--chroot=/", "python3", "-c", "print(1)"])?.flag).toBe(
      "-c",
    );
    expect(
      detectInlineEvalArgv(["sudo", "PYTHONPATH=/tmp", "python3", "-c", "print(1)"])?.flag,
    ).toBe("-c");
    expect(
      detectInlineEvalArgv(["sudo", "-u", "root", "PYTHONPATH=/tmp", "python3", "-c", "print(1)"])
        ?.flag,
    ).toBe("-c");
    expect(
      detectInlineEvalArgv(["sudo", "--", "PYTHONPATH=/tmp", "python3", "-c", "print(1)"])?.flag,
    ).toBe("-c");
    expect(detectInlineEvalArgv(["sudo", "--shell", "python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["sudo", "-Eu", "root", "python3", "-c", "print(1)"])?.flag).toBe(
      "-c",
    );
    expect(detectInlineEvalArgv(["doas", "-uroot", "python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["env", "sudo", "python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(
      detectInlineEvalArgv(["env", "env", "env", "env", "env", "env", "python3", "-c", "print(1)"])
        ?.flag,
    ).toBe("-c");
    expect(detectInlineEvalArgv(["env", "-iSpython3 -c 'print(1)'"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["env", "-iS", "python3 -c 'print(1)'"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["env", "-S", "python3 -c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["env", "-iSpython3 -c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["env", "-P", "/usr/bin", "python3", "-c", "print(1)"])?.flag).toBe(
      "-c",
    );
    expect(detectInlineEvalArgv(["exec", "python3", "-c", "print(1)"])?.flag).toBe("-c");
    expect(detectInlineEvalArgv(["exec", "-a", "py", "python3", "-c", "print(1)"])?.flag).toBe(
      "-c",
    );
    expect(detectInlineEvalArgv(["command", "node", "--eval", "1"])?.flag).toBe("--eval");
    expect(detectInlineEvalArgv(["env", "-S", 'python3 -c "print(1)"'])?.flag).toBe("-c");
    expect(
      detectInlineEvalArgv(["sh", "-lc", '$0 "$@"', "find", ".", "-exec", "id", "{}", ";"])?.flag,
    ).toBe("-exec");
    expect(
      detectInlineEvalArgv(["bash", "-c", 'exec -- "$0" "$@"', "xargs", "sh", "-c", "id"])?.flag,
    ).toBe("<command>");
    expect(
      detectInlineEvalArgv(["env", "sh", "-lc", '$0 "$@"', "find", ".", "-okdir", "id", "{}", ";"])
        ?.flag,
    ).toBe("-okdir");
    expect(
      detectInlineEvalArgv(["sudo", "sh", "-lc", '$0 "$@"', "find", ".", "-exec", "id", "{}", ";"])
        ?.flag,
    ).toBe("-exec");
    expect(
      detectInlineEvalArgv([
        "command",
        "sh",
        "-lc",
        '$0 "$@"',
        "find",
        ".",
        "-execdir",
        "id",
        "{}",
        ";",
      ])?.flag,
    ).toBe("-execdir");
    expect(
      detectInlineEvalArgv(["sh", "-lc", '$0 "$1" "$2"', "find", ".", "-exec", "id", "{}", ";"])
        ?.flag,
    ).toBe("-exec");
    expect(detectInlineEvalArgv(["python3", "script.py"])).toBeNull();
  });

  it("keeps carrier inline eval detection command-boundary aware", () => {
    expect(detectInlineEvalArgv(["command", "echo", "python3", "-c", "print(1)"])).toBeNull();
    expect(detectInlineEvalArgv(["sudo", "echo", "python3", "-c", "print(1)"])).toBeNull();
    expect(
      detectInlineEvalArgv(["sudo", "FOO=bar", "echo", "python3", "-c", "print(1)"]),
    ).toBeNull();
    expect(detectInlineEvalArgv(["env", "-S", 'echo python3 -c "print(1)"'])).toBeNull();
    expect(detectInlineEvalArgv(["command", "-v", "python3", "-c", "print(1)"])).toBeNull();
    expect(detectInlineEvalArgv(["sh", "-lc", '$0 "$@"', "find", ".", "-name", "*.ts"])).toBeNull();
    expect(detectInlineEvalArgv(["sh", "-lc", 'echo "$0"; "$@"', "find", ".", "-exec"])).toBeNull();
    expect(
      detectInlineEvalArgv(["sh", "-lc", '$0 "$1"', "find", ".", "-exec", "id", "{}", ";"]),
    ).toBeNull();
    expect(
      detectInlineEvalArgv(["sh", "-lc", '$0 "$*"', "find", ".", "-exec", "id", "{}", ";"]),
    ).toBeNull();
  });

  it("detects command carriers", () => {
    expect(detectCommandCarrierArgv(["find", ".", "-exec", "rm", "{}", ";"])).toEqual([
      { command: "find", flag: "-exec" },
    ]);
    expect(detectCommandCarrierArgv(["xargs", "-I{}", "sh", "-c", "id"])).toEqual([
      { command: "xargs" },
    ]);
    expect(detectCommandCarrierArgv(["env", "-S", "sh -c id"])).toEqual([
      { command: "env", flag: "-S" },
    ]);
  });

  it("detects env split-string flag forms", () => {
    expect(detectEnvSplitStringFlag(["env", "-S", "sh -c id"])).toBe("-S");
    expect(detectEnvSplitStringFlag(["env", "-Ssh -c id"])).toBe("-S");
    expect(detectEnvSplitStringFlag(["env", "-iS", "sh -c id"])).toBe("-S");
    expect(detectEnvSplitStringFlag(["env", "-iSsh -c id"])).toBe("-S");
    expect(detectEnvSplitStringFlag(["env", "-is", "sh -c id"])).toBe("-s");
    expect(detectEnvSplitStringFlag(["env", "--split-string=sh -c id"])).toBe("--split-string");
    expect(detectEnvSplitStringFlag(["env", "sh", "-c", "id"])).toBeNull();
    expect(detectEnvSplitStringFlag(["env", "-XSsh -c id"])).toBeNull();
  });

  it("detects shell wrappers carried through prefix commands", () => {
    const hit = detectShellWrapperThroughCarrierArgv(
      ["sudo", "bash", "-lc", "id"],
      (argv, startIndex) => argv[startIndex] === "-lc",
    );
    expect(hit).toBe("sudo");
    expect(
      detectShellWrapperThroughCarrierArgv(
        ["sudo", "-uroot", "bash", "-lc", "id"],
        (argv, startIndex) => argv[startIndex] === "-lc",
      ),
    ).toBe("sudo");
    expect(
      detectShellWrapperThroughCarrierArgv(
        ["sudo", "-EH", "bash", "-lc", "id"],
        (argv, startIndex) => argv[startIndex] === "-lc",
      ),
    ).toBe("sudo");
    expect(
      detectShellWrapperThroughCarrierArgv(
        ["exec", "bash", "-lc", "id"],
        (argv, startIndex) => argv[startIndex] === "-lc",
      ),
    ).toBe("exec");
    expect(
      detectShellWrapperThroughCarrierArgv(
        ["sudo", "echo", "bash", "-lc", "id"],
        (argv, startIndex) => argv[startIndex] === "-lc",
      ),
    ).toBeNull();
  });

  it("detects carried eval and source builtins", () => {
    expect(detectCarriedShellBuiltinArgv(["builtin", "eval", "echo hi"])).toEqual({
      kind: "eval",
    });
    expect(detectCarriedShellBuiltinArgv(["command", "source", "./env.sh"])).toEqual({
      kind: "source",
      command: "source",
    });
    expect(detectCarriedShellBuiltinArgv(["exec", "eval", "echo hi"])).toEqual({
      kind: "eval",
    });
    expect(detectCarriedShellBuiltinArgv(["exec", "source", "./env.sh"])).toEqual({
      kind: "source",
      command: "source",
    });
    expect(detectCarriedShellBuiltinArgv(["command", "echo", "eval"])).toBeNull();
  });

  it("builds executable payload candidates through carriers and shell wrappers", () => {
    expect(buildCommandPayloadCandidates(["FOO=1", "sudo", "-E", "/usr/bin/id", "abc"])).toEqual([
      "/usr/bin/id abc",
    ]);
    expect(buildCommandPayloadCandidates(["sudo", "-EH", "/usr/bin/id", "abc"])).toEqual([
      "/usr/bin/id abc",
    ]);
    expect(buildCommandPayloadCandidates(["sudo", "-i", "/usr/bin/id", "abc"])).toEqual([
      "/usr/bin/id abc",
    ]);
    expect(buildCommandPayloadCandidates(["sudo", "-s", "/usr/bin/id", "abc"])).toEqual([
      "/usr/bin/id abc",
    ]);
    expect(buildCommandPayloadCandidates(["sudo", "-k", "/usr/bin/id", "abc"])).toEqual([
      "/usr/bin/id abc",
    ]);
    expect(
      buildCommandPayloadCandidates(["sudo", "--reset-timestamp", "/usr/bin/id", "abc"]),
    ).toEqual(["/usr/bin/id abc"]);
    expect(
      buildCommandPayloadCandidates(["sudo", "--command-timeout=1", "/usr/bin/id", "abc"]),
    ).toEqual(["/usr/bin/id abc"]);
    expect(buildCommandPayloadCandidates(["sudo", "OPENCLAW_ENV=1", "/usr/bin/id", "abc"])).toEqual(
      ["/usr/bin/id abc"],
    );
    expect(buildCommandPayloadCandidates(["sudo", "--shell", "/usr/bin/id", "abc"])).toEqual([
      "/usr/bin/id abc",
    ]);
    expect(
      buildCommandPayloadCandidates(["sudo", "--preserve-groups", "/usr/bin/id", "abc"]),
    ).toEqual(["/usr/bin/id abc"]);
    expect(
      buildCommandPayloadCandidates(["sudo", "-uroot", "bash", "-lc", "/usr/bin/id abc"]),
    ).toEqual(["bash -lc /usr/bin/id abc", "/usr/bin/id abc"]);
    expect(
      buildCommandPayloadCandidates(["doas", "-uroot", "bash", "-lc", "/usr/bin/id abc"]),
    ).toEqual(["bash -lc /usr/bin/id abc", "/usr/bin/id abc"]);
    expect(buildCommandPayloadCandidates(["env", "-S", "bash -lc '/usr/bin/id abc'"])).toEqual([
      "bash -lc /usr/bin/id abc",
      "/usr/bin/id abc",
    ]);
    expect(buildCommandPayloadCandidates(["env", "-S", "bash -lc", "/usr/bin/id abc"])).toEqual([
      "bash -lc /usr/bin/id abc",
      "/usr/bin/id abc",
    ]);
    expect(buildCommandPayloadCandidates(["env", "-iSbash -lc", "/usr/bin/id abc"])).toEqual([
      "bash -lc /usr/bin/id abc",
      "/usr/bin/id abc",
    ]);
    expect(buildCommandPayloadCandidates(["env", "-P", "/usr/bin", "/usr/bin/id", "abc"])).toEqual([
      "/usr/bin/id abc",
    ]);
    expect(buildCommandPayloadCandidates(["exec", "-a", "openclaw", "/usr/bin/id", "abc"])).toEqual(
      ["/usr/bin/id abc"],
    );
    expect(buildCommandPayloadCandidates(["command", "-v", "/usr/bin/id"])).toEqual([
      "command -v /usr/bin/id",
    ]);
    expect(
      buildCommandPayloadCandidates([
        "env",
        "env",
        "env",
        "env",
        "env",
        "env",
        "openclaw",
        "channels",
        "login",
        "--channel",
        "whatsapp",
      ]),
    ).toContain("openclaw channels login --channel whatsapp");
  });

  it("checks both effective and original argv for segment inline eval", () => {
    const hit = detectInlineEvalInSegments([
      {
        raw: "sudo python3 -c 'print(1)'",
        argv: ["sudo", "python3", "-c", "print(1)"],
        resolution: {
          execution: {
            rawExecutable: "sudo",
            executableName: "sudo",
          },
          policy: {
            rawExecutable: "sudo",
            executableName: "sudo",
          },
          effectiveArgv: ["sudo", "python3", "-c", "print(1)"],
        },
      },
    ]);
    expect(hit?.normalizedExecutable).toBe("python3");
  });
});
