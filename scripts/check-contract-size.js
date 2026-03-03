/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");

const CONTRACT_SOURCE = process.env.CONTRACT_SOURCE || "InstitutionalStablecoinBridge.sol";
const CONTRACT_NAME = process.env.CONTRACT_NAME || "InstitutionalStablecoinBridge";
const MAX_DEPLOYED_CODE_BYTES = Number(process.env.MAX_DEPLOYED_CODE_BYTES || "24576");

function hexByteLen(hex) {
  if (!hex || hex === "0x") return 0;
  if (!hex.startsWith("0x")) {
    throw new Error("Expected hex string with 0x prefix");
  }
  return (hex.length - 2) / 2;
}

function kib(bytes) {
  return (bytes / 1024).toFixed(3);
}

function main() {
  if (!Number.isFinite(MAX_DEPLOYED_CODE_BYTES) || MAX_DEPLOYED_CODE_BYTES <= 0) {
    throw new Error("MAX_DEPLOYED_CODE_BYTES must be a positive integer");
  }

  const artifactPath = path.join(
    __dirname,
    "..",
    "artifacts",
    "contracts",
    CONTRACT_SOURCE,
    `${CONTRACT_NAME}.json`
  );

  if (!fs.existsSync(artifactPath)) {
    throw new Error(`Artifact not found: ${artifactPath}. Run 'hardhat compile' first.`);
  }

  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const deployed = artifact.deployedBytecode || "0x";
  const initcode = artifact.bytecode || "0x";

  const deployedBytes = hexByteLen(deployed);
  const initcodeBytes = hexByteLen(initcode);

  const summary = [
    `[size-check] ${CONTRACT_NAME}`,
    `deployed=${deployedBytes} bytes (${kib(deployedBytes)} KiB)`,
    `initcode=${initcodeBytes} bytes (${kib(initcodeBytes)} KiB)`,
    `max=${MAX_DEPLOYED_CODE_BYTES} bytes (${kib(MAX_DEPLOYED_CODE_BYTES)} KiB)`,
  ].join(" | ");
  console.log(summary);

  if (deployedBytes > MAX_DEPLOYED_CODE_BYTES) {
    const over = deployedBytes - MAX_DEPLOYED_CODE_BYTES;
    console.error(
      `[size-check] FAIL: ${CONTRACT_NAME} exceeds EIP-170 deployable bytecode limit by ${over} bytes`
    );
    process.exit(1);
  }

  const remaining = MAX_DEPLOYED_CODE_BYTES - deployedBytes;
  console.log(`[size-check] PASS: ${remaining} bytes headroom remaining`);
}

try {
  main();
} catch (err) {
  console.error(`[size-check] ERROR: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
