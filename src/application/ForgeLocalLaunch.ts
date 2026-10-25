import { fileURLToPath } from "node:url";

/** Public launcher, independent of cwd, PATH, and an enclosing npm invocation. */
export const FORGE_LOCAL_ENTRYPOINT = fileURLToPath(
  new URL("../../scripts/rea.mjs", import.meta.url),
);

export const forgeLocalCommand = (
  arguments_: readonly string[] = [],
): readonly string[] => [
  process.execPath,
  FORGE_LOCAL_ENTRYPOINT,
  ...arguments_,
];

/** Machine paths belong only in the explicitly installed private skill. */
export const bindForgeLocalSkill = (content: string): string => {
  const command = forgeLocalCommand();
  const powershell = command
    .map((argument) => `'${argument.replaceAll("'", "''")}'`)
    .join(" ");
  const posix = command
    .map((argument) => `'${argument.replaceAll("'", `'"'"'`)}'`)
    .join(" ");
  return content
    .replaceAll("{{REA_FORGE_ARGV_PREFIX}}", JSON.stringify(command))
    .replaceAll("{{REA_FORGE_POWERSHELL_PREFIX}}", `& ${powershell}`)
    .replaceAll("{{REA_FORGE_POSIX_PREFIX}}", posix);
};
