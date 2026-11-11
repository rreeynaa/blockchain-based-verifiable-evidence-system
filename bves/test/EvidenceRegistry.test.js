const { expect } = require("chai");
const { ethers } = require("hardhat");

const h = (s) => ethers.keccak256(ethers.toUtf8Bytes(s));

describe("EvidenceRegistry", () => {
  let reg, admin, inv, inv2, aud, outsider;
  let INV, AUD, ADMIN;

  beforeEach(async () => {
    [admin, inv, inv2, aud, outsider] = await ethers.getSigners();
    reg = await (await ethers.getContractFactory("EvidenceRegistry")).deploy(admin.address);
    INV = await reg.INVESTIGATOR_ROLE();
    AUD = await reg.AUDITOR_ROLE();
    ADMIN = await reg.ADMIN_ROLE();
    await reg.connect(admin).grantRole(INV, inv.address);
    await reg.connect(admin).grantRole(INV, inv2.address);
    await reg.connect(admin).grantRole(AUD, aud.address);
  });

  const files = [h("f1"), h("f2"), h("f3")];
  const cids = ["bafy1", "bafy2", "bafy3"];
  const root = h("root-1");

  describe("access control", () => {
    it("admin holds ADMIN_ROLE; outsiders hold nothing", async () => {
      expect(await reg.hasRole(ADMIN, admin.address)).to.equal(true);
      expect(await reg.hasRole(INV, outsider.address)).to.equal(false);
    });

    it("only investigators can register", async () => {
      for (const s of [aud, outsider]) {
        await expect(reg.connect(s).registerBatch("c", root, files, cids)).to.be.revertedWithCustomError(
          reg,
          "AccessControlUnauthorizedAccount"
        );
      }
      await expect(reg.connect(inv).registerBatch("c", root, files, cids)).to.emit(reg, "BatchRegistered");
    });

    it("only admin can grant roles", async () => {
      await expect(reg.connect(inv).grantRole(INV, outsider.address)).to.be.revertedWithCustomError(
        reg,
        "AccessControlUnauthorizedAccount"
      );
      await reg.connect(admin).grantRole(INV, outsider.address);
      expect(await reg.hasRole(INV, outsider.address)).to.equal(true);
    });

    it("revoked investigator can no longer register", async () => {
      await reg.connect(admin).revokeRole(INV, inv.address);
      await expect(reg.connect(inv).registerBatch("c", root, files, cids)).to.be.reverted;
    });
  });

  describe("registerBatch", () => {
    it("stores batch, files and emits events", async () => {
      await expect(reg.connect(inv).registerBatch("CASE-1", root, files, cids))
        .to.emit(reg, "BatchRegistered")
        .withArgs(1, root, inv.address, "CASE-1", 3);
      const b = await reg.getBatch(1);
      expect(b.merkleRoot).to.equal(root);
      expect(b.submitter).to.equal(inv.address);
      expect(b.caseId).to.equal("CASE-1");
      expect(b.fileCount).to.equal(3n);
      expect(b.timestamp).to.be.gt(0n);
      const f = await reg.getFile(1, 1);
      expect(f.fileHash).to.equal(files[1]);
      expect(f.cid).to.equal("bafy2");
      expect(f.batchId).to.equal(1n);
      expect((await reg.getFiles(1)).length).to.equal(3);
      expect(await reg.batchCount()).to.equal(1n);
    });

    it("rejects duplicate Merkle roots", async () => {
      await reg.connect(inv).registerBatch("c", root, files, cids);
      await expect(reg.connect(inv2).registerBatch("c2", root, [h("x")], ["cid"])).to.be.revertedWith(
        "EvidenceRegistry: duplicate root"
      );
    });

    it("rejects malformed input", async () => {
      await expect(reg.connect(inv).registerBatch("c", ethers.ZeroHash, files, cids)).to.be.revertedWith(
        "EvidenceRegistry: empty root"
      );
      await expect(reg.connect(inv).registerBatch("c", root, [], [])).to.be.revertedWith(
        "EvidenceRegistry: no files"
      );
      await expect(reg.connect(inv).registerBatch("c", root, files, ["a"])).to.be.revertedWith(
        "EvidenceRegistry: length mismatch"
      );
      await expect(
        reg.connect(inv).registerBatch("c", root, [files[0], files[0]], ["a", "b"])
      ).to.be.revertedWith("EvidenceRegistry: duplicate file in batch");
    });

    it("verifyFileHash / verifyRoot", async () => {
      await reg.connect(inv).registerBatch("c", root, files, cids);
      expect(await reg.verifyFileHash(1, files[2])).to.equal(true);
      expect(await reg.verifyFileHash(1, h("other"))).to.equal(false);
      expect(await reg.verifyFileHash(99, files[0])).to.equal(false);
      expect(await reg.verifyRoot(1, root)).to.equal(true);
      expect(await reg.verifyRoot(1, h("nope"))).to.equal(false);
      expect(await reg.verifyRoot(0, root)).to.equal(false);
      expect(await reg.batchIdForRoot(root)).to.equal(1n);
    });

    it("unknown batch reads revert", async () => {
      await expect(reg.getBatch(1)).to.be.revertedWith("EvidenceRegistry: unknown batch");
      await expect(reg.getCustodyLog(0)).to.be.revertedWith("EvidenceRegistry: unknown batch");
    });

    it("is append-only: no mutator beyond register/transfer/role mgmt", async () => {
      const mutators = reg.interface.fragments
        .filter((f) => f.type === "function" && !["view", "pure"].includes(f.stateMutability))
        .map((f) => f.name)
        .sort();
      expect(mutators).to.deep.equal(
        ["grantRole", "registerBatch", "renounceRole", "revokeRole", "transferCustody"].sort()
      );
    });

    it("existing batch data is unchanged by later registrations", async () => {
      await reg.connect(inv).registerBatch("c", root, files, cids);
      await reg.connect(inv).registerBatch("c2", h("root-2"), [h("z")], ["cz"]);
      const b = await reg.getBatch(1);
      expect(b.merkleRoot).to.equal(root);
      expect(b.fileCount).to.equal(3n);
    });
  });

  describe("custody trail", () => {
    beforeEach(async () => {
      await reg.connect(inv).registerBatch("c", root, files, cids);
    });

    it("starts with the registration entry", async () => {
      const log = await reg.getCustodyLog(1);
      expect(log.length).to.equal(1);
      expect(log[0].from).to.equal(ethers.ZeroAddress);
      expect(log[0].to).to.equal(inv.address);
      expect(await reg.currentCustodian(1)).to.equal(inv.address);
    });

    it("records transfers in order and emits events", async () => {
      await expect(reg.connect(inv).transferCustody(1, inv2.address, "handover to forensics"))
        .to.emit(reg, "CustodyTransferred")
        .withArgs(1, inv.address, inv2.address, "handover to forensics");
      await reg.connect(inv2).transferCustody(1, inv.address, "returned");
      const log = await reg.getCustodyLog(1);
      expect(log.length).to.equal(3);
      expect(log[1].from).to.equal(inv.address);
      expect(log[1].to).to.equal(inv2.address);
      expect(log[1].reason).to.equal("handover to forensics");
      expect(log[2].to).to.equal(inv.address);
      expect(await reg.currentCustodian(1)).to.equal(inv.address);
    });

    it("only the current custodian (or admin) may transfer", async () => {
      await expect(reg.connect(inv2).transferCustody(1, aud.address, "x")).to.be.revertedWith(
        "EvidenceRegistry: not authorised"
      );
      await expect(reg.connect(aud).transferCustody(1, aud.address, "x")).to.be.revertedWith(
        "EvidenceRegistry: not authorised"
      );
      await expect(reg.connect(admin).transferCustody(1, inv2.address, "admin override")).to.emit(
        reg,
        "CustodyTransferred"
      );
    });

    it("rejects zero address, self-transfer and unknown batch", async () => {
      await expect(reg.connect(inv).transferCustody(1, ethers.ZeroAddress, "x")).to.be.revertedWith(
        "EvidenceRegistry: zero custodian"
      );
      await expect(reg.connect(inv).transferCustody(1, inv.address, "x")).to.be.revertedWith(
        "EvidenceRegistry: already custodian"
      );
      await expect(reg.connect(inv).transferCustody(5, inv2.address, "x")).to.be.revertedWith(
        "EvidenceRegistry: unknown batch"
      );
    });

    it("revoked custodian cannot transfer", async () => {
      await reg.connect(admin).revokeRole(INV, inv.address);
      await expect(reg.connect(inv).transferCustody(1, inv2.address, "x")).to.be.revertedWith(
        "EvidenceRegistry: not authorised"
      );
    });
  });
});
