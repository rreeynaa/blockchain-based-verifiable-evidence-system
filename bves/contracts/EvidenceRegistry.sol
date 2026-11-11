// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title EvidenceRegistry
 * @notice Append-only registry anchoring Merkle roots of cloud-intrusion log
 *         batches, plus a per-batch chain-of-custody log.
 * @dev There are intentionally NO update or delete functions for batches,
 *      files, or custody entries. Only new records can be appended.
 */
contract EvidenceRegistry is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant INVESTIGATOR_ROLE = keccak256("INVESTIGATOR_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    uint256 public constant MAX_FILES_PER_BATCH = 256;

    struct Batch {
        bytes32 merkleRoot;
        uint256 timestamp;
        address submitter;
        string caseId;
        uint256 fileCount;
    }

    struct FileRecord {
        bytes32 fileHash;
        string cid;
        uint256 batchId;
    }

    struct CustodyEntry {
        address from;
        address to;
        string reason;
        uint256 timestamp;
    }

    uint256 private _batchCount;
    mapping(uint256 => Batch) private _batches;
    mapping(uint256 => FileRecord[]) private _files;
    mapping(uint256 => mapping(bytes32 => bool)) private _fileInBatch;
    mapping(bytes32 => uint256) private _rootToBatch;
    mapping(uint256 => address) private _custodian;
    mapping(uint256 => CustodyEntry[]) private _custody;

    event BatchRegistered(
        uint256 indexed batchId,
        bytes32 indexed merkleRoot,
        address indexed submitter,
        string caseId,
        uint256 fileCount
    );
    event CustodyTransferred(
        uint256 indexed batchId,
        address indexed from,
        address indexed to,
        string reason
    );

    constructor(address admin) {
        require(admin != address(0), "EvidenceRegistry: zero admin");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        // ADMIN_ROLE holders manage the operational roles.
        _setRoleAdmin(INVESTIGATOR_ROLE, ADMIN_ROLE);
        _setRoleAdmin(AUDITOR_ROLE, ADMIN_ROLE);
    }

    // ------------------------------------------------------------------ write

    function registerBatch(
        string calldata caseId,
        bytes32 merkleRoot,
        bytes32[] calldata fileHashes,
        string[] calldata cids
    ) external onlyRole(INVESTIGATOR_ROLE) returns (uint256 batchId) {
        require(merkleRoot != bytes32(0), "EvidenceRegistry: empty root");
        require(fileHashes.length > 0, "EvidenceRegistry: no files");
        require(fileHashes.length <= MAX_FILES_PER_BATCH, "EvidenceRegistry: batch too large");
        require(fileHashes.length == cids.length, "EvidenceRegistry: length mismatch");
        require(_rootToBatch[merkleRoot] == 0, "EvidenceRegistry: duplicate root");

        batchId = ++_batchCount;
        _rootToBatch[merkleRoot] = batchId;
        _batches[batchId] = Batch({
            merkleRoot: merkleRoot,
            timestamp: block.timestamp,
            submitter: msg.sender,
            caseId: caseId,
            fileCount: fileHashes.length
        });

        for (uint256 i = 0; i < fileHashes.length; i++) {
            require(fileHashes[i] != bytes32(0), "EvidenceRegistry: empty file hash");
            require(!_fileInBatch[batchId][fileHashes[i]], "EvidenceRegistry: duplicate file in batch");
            _fileInBatch[batchId][fileHashes[i]] = true;
            _files[batchId].push(FileRecord(fileHashes[i], cids[i], batchId));
        }

        _custodian[batchId] = msg.sender;
        _custody[batchId].push(CustodyEntry(address(0), msg.sender, "Initial registration", block.timestamp));

        emit BatchRegistered(batchId, merkleRoot, msg.sender, caseId, fileHashes.length);
        emit CustodyTransferred(batchId, address(0), msg.sender, "Initial registration");
    }

    /// @notice Hand custody to another address. Callable by the current
    ///         custodian (if still an investigator) or by an ADMIN_ROLE holder.
    function transferCustody(
        uint256 batchId,
        address newCustodian,
        string calldata reason
    ) external {
        require(_exists(batchId), "EvidenceRegistry: unknown batch");
        require(newCustodian != address(0), "EvidenceRegistry: zero custodian");
        address current = _custodian[batchId];
        require(newCustodian != current, "EvidenceRegistry: already custodian");
        bool isCustodian = msg.sender == current && hasRole(INVESTIGATOR_ROLE, msg.sender);
        require(isCustodian || hasRole(ADMIN_ROLE, msg.sender), "EvidenceRegistry: not authorised");

        _custodian[batchId] = newCustodian;
        _custody[batchId].push(CustodyEntry(current, newCustodian, reason, block.timestamp));
        emit CustodyTransferred(batchId, current, newCustodian, reason);
    }

    // ------------------------------------------------------------------- read

    function batchCount() external view returns (uint256) {
        return _batchCount;
    }

    function getBatch(uint256 batchId) external view returns (Batch memory) {
        require(_exists(batchId), "EvidenceRegistry: unknown batch");
        return _batches[batchId];
    }

    function getFile(uint256 batchId, uint256 index) external view returns (FileRecord memory) {
        require(_exists(batchId), "EvidenceRegistry: unknown batch");
        require(index < _files[batchId].length, "EvidenceRegistry: file index out of range");
        return _files[batchId][index];
    }

    function getFiles(uint256 batchId) external view returns (FileRecord[] memory) {
        require(_exists(batchId), "EvidenceRegistry: unknown batch");
        return _files[batchId];
    }

    function getCustodyLog(uint256 batchId) external view returns (CustodyEntry[] memory) {
        require(_exists(batchId), "EvidenceRegistry: unknown batch");
        return _custody[batchId];
    }

    function currentCustodian(uint256 batchId) external view returns (address) {
        require(_exists(batchId), "EvidenceRegistry: unknown batch");
        return _custodian[batchId];
    }

    function batchIdForRoot(bytes32 root) external view returns (uint256) {
        return _rootToBatch[root];
    }

    function verifyFileHash(uint256 batchId, bytes32 fileHash) external view returns (bool) {
        return _exists(batchId) && _fileInBatch[batchId][fileHash];
    }

    function verifyRoot(uint256 batchId, bytes32 root) external view returns (bool) {
        return _exists(batchId) && _batches[batchId].merkleRoot == root;
    }

    function _exists(uint256 batchId) private view returns (bool) {
        return batchId != 0 && batchId <= _batchCount;
    }
}
