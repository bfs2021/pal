import { homedir } from "node:os";

/**
 * Commands that always go to the owner in Auto mode, before and whatever a decision model would say. A deterministic
 * guard against obvious mistakes and prompt-injected commands, not a sandbox: anything it misses still runs as the
 * Pal host user once approved.
 */
const RULES: readonly { reason: string; test: (command: string) => boolean }[] = [
  {
    reason: "changes privileges",
    test: (command) => /(?:^|[\s;&|(`])(?:[^\s;&|()`]*\/)?(?:sudo|doas|su|pkexec|run0)(?=$|[\s;&|)])/.test(command),
  },
  { reason: "pushes with Git", test: (command) => /\bgit\b[^;&|\n]*\spush\b/.test(command) },
  {
    reason: "publishes a package",
    test: (command) =>
      /\b(?:npm|pnpm|yarn|bun|cargo|poetry|uv)\b[^;&|\n]*\spublish\b|\btwine\s+upload\b|\bgem\s+push\b|\b(?:docker|podman)\s+push\b|\bgh\s+release\s+create\b/.test(
        command,
      ),
  },
  { reason: "deletes recursively outside the folder", test: recursiveDelete },
  {
    reason: "runs a downloaded script",
    test: (command) =>
      /\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:\S*\/)?(?:sh|bash|zsh|dash|ksh|fish|python3?|node|perl|ruby)\b/.test(
        command,
      ) || /\b(?:sh|bash|zsh)\b[^;&|\n]*(?:<\(|\$\()\s*(?:curl|wget)\b/.test(command),
  },
  {
    reason: "touches SSH keys or credentials",
    test: (command) =>
      /(?:^|[\s"'=:/])\.(?:ssh|aws)(?:\/|\s|$)|(?:^|[\s"'=:/<>])\.env(?:\.(?!example\b|sample\b|template\b)[\w-]+)*(?=$|[\s"';&|)<>])|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.netrc\b|\.gnupg\b|\.docker\/config\.json|\.kube\/config|\.config\/gh\b|\.git-credentials\b|\.npmrc\b|\.pypirc\b|\bsecurity\s+(?:find|dump)-\w+/.test(
        command,
      ),
  },
  {
    reason: "changes the system or its services",
    test: (command) =>
      /\b(?:systemctl|launchctl|service|shutdown|reboot|halt|poweroff|mkfs(?:\.\w+)?)\b|\bdd\b[^;&|\n]*\bof=\/dev\//.test(
        command,
      ),
  },
];

/**
 * Conservative: a path counts as outside unless it is plain and relative with no `cd` before it. `rm` fed by `xargs`
 * or without a target, and `find -delete` or `find -exec rm` from such a path, count too.
 */
function recursiveDelete(command: string): boolean {
  let moved = false;
  const outside = (word: string) => moved || word === "" || /^[/~]|(?:^|\/)\.\.(?:\/|$)|[$`]/.test(word);
  for (const segment of command.split(/[;&|\n]+/)) {
    const words = segment
      .trim()
      .split(/\s+/)
      .map((word) => word.replace(/^[("'`{]+|["'`)}]+$/g, ""));
    const at = words.findIndex((word) => /(?:^|\/)rm$/.test(word));
    const find = words.findIndex((word) => /(?:^|\/)find$/.test(word));
    moved ||= words.slice(0, at === -1 ? undefined : at).some((word) => word === "cd" || word === "pushd");
    if (find !== -1 && (at === -1 || find < at)) {
      if (at === -1 && !words.includes("-delete")) continue;
      const options = words.findIndex((word, index) => index > find && /^[-(!]/.test(word));
      const starts = words.slice(find + 1, options === -1 ? undefined : options);
      if (starts.length === 0 ? moved : starts.some(outside)) return true;
      continue;
    }
    if (at === -1) continue;
    const rest = words.slice(at + 1);
    if (!rest.some((word) => /^-[a-zA-Z]*[rR]/.test(word) || word === "--recursive")) continue;
    const targets = rest.filter((word) => !word.startsWith("-"));
    const fed = words.slice(0, at).some((word) => /(?:^|\/)xargs$/.test(word));
    if (fed || targets.length === 0 || targets.some(outside)) return true;
  }
  return false;
}

/** The command as the shell reads its words: quotes and backslash escapes removed, `~` and `$HOME` expanded. */
function unquoted(command: string, home: string): string {
  return command
    .replace(/\\(.)/g, "$1")
    .replace(/["']/g, "")
    .replace(/(^|[\s=:;&|(`])(?:~|\$HOME\b|\$\{HOME\})(?=\/|$|[\s;&|)])/g, `$1${home}`);
}

/** Why `command` must ask the owner even in Auto; undefined when the decision model may judge it. */
export function alwaysAsks(command: string, privatePaths: readonly string[], home = homedir()): string | undefined {
  const forms = [command, unquoted(command, home)];
  if (privatePaths.some((path) => path !== "" && forms.some((form) => form.includes(path))))
    return "touches Pal's own data";
  return RULES.find((rule) => forms.some((form) => rule.test(form)))?.reason;
}
