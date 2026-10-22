/*
 * One-shot offline CyberChef engine adapter for REA Forge.
 *
 * This file intentionally imports only the named, locally audited operation
 * classes below.  It does not import CyberChef's generated all-operation Node
 * API because that surface contains network-capable and otherwise unapproved
 * operations.  The only process capability is one JSON request on stdin and
 * one JSON response on stdout. Only the configured module loader reads source
 * files; recipes expose no file, network, command or listener API.
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// Module selection is fixed here, never supplied by a recipe. Operator-owned
// entry hashes are checked before importing the installed engine's modules.
const root = process.env.REA_FORGE_CYBERCHEF_ROOT;
const pins = JSON.parse(
  await readFile(process.env.REA_FORGE_CYBERCHEF_ENTRY_PINS, "utf8"),
);
async function load(relative) {
  const path = join(root, relative);
  const bytes = await readFile(path);
  if (createHash("sha256").update(bytes).digest("hex") !== pins[relative])
    throw new Error("CyberChef entry source identity drifted");
  return (await import(pathToFileURL(path).href)).default;
}
const Dish = await load("src/core/Dish.mjs");
const Utils = await load("src/core/Utils.mjs");
const [
  FromBase64,
  ToBase64,
  FromHex,
  ToHex,
  URLDecode,
  URLEncode,
  EncodeText,
  DecodeText,
  Gzip,
  Gunzip,
  ZlibDeflate,
  ZlibInflate,
  SHA2,
  HMAC,
  CRCChecksum,
  XOR,
  AESEncrypt,
  AESDecrypt,
  JSONBeautify,
  JSONMinify,
] = await Promise.all(
  [
    "FromBase64",
    "ToBase64",
    "FromHex",
    "ToHex",
    "URLDecode",
    "URLEncode",
    "EncodeText",
    "DecodeText",
    "Gzip",
    "Gunzip",
    "ZlibDeflate",
    "ZlibInflate",
    "SHA2",
    "HMAC",
    "CRCChecksum",
    "XOR",
    "AESEncrypt",
    "AESDecrypt",
    "JSONBeautify",
    "JSONMinify",
  ].map((name) => load(`src/core/operations/${name}.mjs`)),
);

const MAX_REQUEST_BYTES = 12 * 1024 * 1024;
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_STEPS = 16;
const MAX_ARGUMENT_STRING_BYTES = 8192;

const OPERATION_CLASSES = Object.freeze({
  "From Base64": FromBase64,
  "To Base64": ToBase64,
  "From Hex": FromHex,
  "To Hex": ToHex,
  "URL Decode": URLDecode,
  "URL Encode": URLEncode,
  "Encode text": EncodeText,
  "Decode text": DecodeText,
  Gzip: Gzip,
  Gunzip: Gunzip,
  "Zlib Deflate": ZlibDeflate,
  "Zlib Inflate": ZlibInflate,
  SHA2: SHA2,
  HMAC: HMAC,
  "CRC Checksum": CRCChecksum,
  XOR: XOR,
  "AES Encrypt": AESEncrypt,
  "AES Decrypt": AESDecrypt,
  "JSON Beautify": JSONBeautify,
  "JSON Minify": JSONMinify,
});

function fail(message) {
  throw new Error(message);
}

function defaultValue(arg) {
  if (arg.type === "option")
    return Array.isArray(arg.value)
      ? arg.value[arg.defaultIndex ?? 0]
      : arg.value;
  if (arg.type === "editableOption")
    return typeof arg.value === "string"
      ? arg.value
      : arg.value[arg.defaultIndex ?? 0].value;
  if (arg.type === "toggleString")
    return { string: "", option: arg.toggleValues[0] };
  if (arg.type === "argSelector") return arg.value[0].name;
  return arg.value;
}

function argumentSummary(arg) {
  const result = { name: arg.name, type: arg.type, default: defaultValue(arg) };
  if (arg.type === "option") result.options = arg.value;
  if (arg.type === "editableOption")
    result.options = arg.value.map((item) => item.value);
  if (arg.type === "toggleString") result.options = arg.toggleValues;
  if (arg.type === "argSelector")
    result.options = arg.value.map((item) => item.name);
  if (typeof arg.min === "number") result.minimum = arg.min;
  return result;
}

function ensureBoundedJson(value, depth = 0) {
  if (depth > 5) fail("recipe argument nesting exceeded the fixed bound");
  if (value === null || typeof value === "boolean" || typeof value === "number")
    return;
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_ARGUMENT_STRING_BYTES)
      fail("recipe argument string exceeded the fixed bound");
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 32)
      fail("recipe argument array exceeded the fixed bound");
    value.forEach((item) => ensureBoundedJson(item, depth + 1));
    return;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length > 12)
      fail("recipe argument object exceeded the fixed bound");
    keys.forEach((key) => {
      if (Buffer.byteLength(key, "utf8") > 128)
        fail("recipe argument key exceeded the fixed bound");
      ensureBoundedJson(value[key], depth + 1);
    });
    return;
  }
  fail("recipe argument has an unsupported type");
}

function validateKnownKeyArguments(name, args) {
  if (
    name === "AES Encrypt" ||
    name === "AES Decrypt" ||
    name === "HMAC" ||
    name === "XOR"
  ) {
    const key = args[0];
    if (
      !key ||
      typeof key !== "object" ||
      typeof key.string !== "string" ||
      typeof key.option !== "string" ||
      !key.string.length
    ) {
      fail(`${name} requires an explicit non-empty known key`);
    }
  }
  if (name === "AES Encrypt" || name === "AES Decrypt") {
    const allowedModes = new Set([
      "CBC",
      "CFB",
      "OFB",
      "CTR",
      "GCM",
      "ECB",
      "CBC/NoPadding",
      "ECB/NoPadding",
    ]);
    const modeIndex = name === "AES Encrypt" ? 2 : 3;
    if (!allowedModes.has(args[modeIndex]))
      fail("AES mode is not in the audited known-parameter catalog");
  }
}

function normaliseRecipe(recipe) {
  if (!Array.isArray(recipe) || recipe.length < 1 || recipe.length > MAX_STEPS)
    fail("recipe must contain from 1 through 16 steps");
  return recipe.map((step, index) => {
    if (
      !step ||
      typeof step !== "object" ||
      Array.isArray(step) ||
      Object.keys(step).some((key) => key !== "name" && key !== "args")
    ) {
      fail(`recipe step ${index} has an invalid shape`);
    }
    if (
      typeof step.name !== "string" ||
      !Object.hasOwn(OPERATION_CLASSES, step.name)
    )
      fail(`recipe step ${index} is not an audited operation`);
    if (step.args !== undefined && !Array.isArray(step.args))
      fail(`recipe step ${index} args must be an array when present`);
    const instance = new OPERATION_CLASSES[step.name]();
    const args =
      step.args === undefined || step.args.length === 0
        ? instance.args.map(defaultValue)
        : step.args;
    if (args.length !== instance.args.length)
      fail(`recipe step ${index} has the wrong argument count`);
    ensureBoundedJson(args);
    validateKnownKeyArguments(step.name, args);
    instance.validateIngredients(args);
    if (step.name === "To Base64" || step.name === "From Base64") {
      if (typeof args[0] !== "string") fail("Base64 alphabet must be a string");
      const length = Utils.expandAlphRange(args[0]).length;
      if (length !== 64 && length !== 65)
        fail(
          "Base64 alphabet must expand to 64 symbols, optionally followed by padding",
        );
    }
    instance.args.forEach((argument, position) => {
      if (
        argument.type === "toggleString" &&
        (!args[position] ||
          typeof args[position].string !== "string" ||
          !argument.toggleValues.includes(args[position].option))
      )
        fail(
          `recipe step ${index} has an invalid ${argument.name} representation`,
        );
    });
    return { name: step.name, args: args };
  });
}

async function runRecipe(input, recipe) {
  let dish = new Dish(new Uint8Array(input), Dish.BYTE_ARRAY);
  const normalised = normaliseRecipe(recipe);
  for (const step of normalised) {
    const operation = new OPERATION_CLASSES[step.name]();
    const operationInput = dish.get(operation.inputType);
    const result = await operation.run(operationInput, step.args);
    dish = new Dish({ value: result, type: operation.outputType });
  }
  const output = dish.get(Dish.ARRAY_BUFFER);
  const bytes = Buffer.from(output);
  if (bytes.length > MAX_OUTPUT_BYTES)
    fail("recipe output exceeded the fixed 16 MiB bound");
  return {
    recipe: normalised,
    output_base64: bytes.toString("base64"),
    output_type: Dish.enumLookup(dish.type),
    output_bytes: bytes.length,
  };
}

function magicCandidates(input) {
  const bytes = Buffer.from(input);
  const text = bytes.toString("utf8");
  const candidates = [];
  const add = (label, basis) =>
    candidates.push({ label, basis, confidence: "candidate_only" });
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b)
    add("Gunzip", "input starts with the gzip magic bytes 1f8b");
  if (
    bytes.length >= 2 &&
    bytes[0] === 0x78 &&
    [0x01, 0x5e, 0x9c, 0xda].includes(bytes[1])
  )
    add("Zlib Inflate", "input starts with a common zlib header");
  if (
    /^\s*(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\s*$/.test(
      text,
    )
  )
    add("From Base64", "text matches the RFC 4648 Base64 shape");
  if (
    /^\s*(?:0x)?[0-9a-fA-F]{2}(?:[\s,:;-]*(?:0x)?[0-9a-fA-F]{2})*\s*$/.test(
      text,
    )
  )
    add("From Hex", "text matches a bounded hexadecimal-byte shape");
  if (/%[0-9a-fA-F]{2}/.test(text))
    add("URL Decode", "text contains percent-encoded byte escapes");
  try {
    JSON.parse(text);
    add("JSON Beautify", "input parses as JSON");
  } catch (_) {
    /* a non-JSON input is ordinary */
  }
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a)
    add(
      "PE/COFF signature",
      "input starts with MZ; use native static analysis for PE conclusions",
    );
  if (
    bytes.length >= 4 &&
    bytes.slice(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))
  )
    add(
      "ZIP container signature",
      "input starts with PK\\x03\\x04; container parsing is outside this bounded Magic surface",
    );
  return {
    candidates,
    input_bytes: bytes.length,
    note: "Candidate labels are local heuristics only. They do not prove an algorithm, recover an unknown key, or execute a candidate recipe.",
  };
}

function catalog() {
  return Object.entries(OPERATION_CLASSES).map(([name, Klass]) => {
    const instance = new Klass();
    return {
      name,
      input_type: instance.inputType,
      output_type: instance.outputType,
      arguments: instance.args.map(argumentSummary),
    };
  });
}

async function handle(request) {
  if (!request || typeof request !== "object" || Array.isArray(request))
    fail("request must be an object");
  if (request.action === "catalog") return { operations: catalog() };
  if (request.action === "validate_recipe")
    return { recipe: normaliseRecipe(request.recipe) };
  if (request.action !== "run_recipe" && request.action !== "magic_candidates")
    fail("worker action is not registered");
  if (typeof request.input_base64 !== "string")
    fail("input_base64 is required");
  const input = Buffer.from(request.input_base64, "base64");
  if (input.toString("base64") !== request.input_base64)
    fail("input_base64 must use canonical Base64 encoding");
  if (input.length > MAX_INPUT_BYTES)
    fail("input exceeded the fixed 8 MiB bound");
  if (request.action === "magic_candidates") return magicCandidates(input);
  return runRecipe(input, request.recipe);
}

async function main() {
  const chunks = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    total += chunk.length;
    if (total > MAX_REQUEST_BYTES)
      fail("request exceeded the fixed byte bound");
    chunks.push(chunk);
  }
  const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const result = await handle(request);
  process.stdout.write(JSON.stringify({ ok: true, result }) + "\n");
}

main().catch((cause) => {
  process.stdout.write(
    JSON.stringify({
      ok: false,
      error: String(cause instanceof Error ? cause.message : cause).slice(
        0,
        512,
      ),
    }) + "\n",
  );
  process.exitCode = 1;
});
