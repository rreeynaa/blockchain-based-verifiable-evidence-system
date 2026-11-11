// Deploys EvidenceRegistry and writes {address, abi, chainId, ...} to a shared file
// that the Python backend reads (DEPLOYMENT_FILE, default ./shared/deployment.json).
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

async function main() {
  const { ethers, artifacts } = hre;
  // Account #0 = admin + backend signer (demo). Account #1 = auditor role holder.
  const [admin, auditor] = await ethers.getSigners();

  const Registry = await ethers.getContractFactory("EvidenceRegistry");
  const registry = await Registry.deploy(admin.address);
  await registry.waitForDeployment();

  // The backend signs with the admin key, so it also needs INVESTIGATOR_ROLE to register.
  await (await registry.grantRole(await registry.INVESTIGATOR_ROLE(), admin.address)).wait();
  await (await registry.grantRole(await registry.AUDITOR_ROLE(), auditor.address)).wait();

  const address = await registry.getAddress();
  const artifact = await artifacts.readArtifact("EvidenceRegistry");
  const net = await ethers.provider.getNetwork();
  const out = {
    address,
    abi: artifact.abi,
    chainId: Number(net.chainId),
    deployer: admin.address,
    deployedAt: new Date().toISOString(),
  };

  const file = process.env.DEPLOYMENT_FILE || path.join(__dirname, "..", "shared", "deployment.json");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(out, null, 2));
  console.log(`EvidenceRegistry deployed at ${address} (chainId ${out.chainId})`);
  console.log(`Deployment info written to ${file}`);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
