// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VaccineLedger
 * @notice On-chain anchor for VChain cold-chain telemetry.
 *
 * The Python gateway in this repository is the executable reference
 * implementation. This contract is the deployment target for a permissioned
 * EVM network: it stores Merkle roots of signed reading digests, enforces a
 * validator quorum, verifies inclusion proofs and permanently records
 * excursions. Hashing matches `vchain/crypto.py`:
 *
 *   leaf  = sha256(0x00 || digest)
 *   node  = sha256(0x01 || left || right)
 *   odd nodes are duplicated before pairing
 */
contract VaccineLedger {
    struct Batch {
        bytes32 merkleRoot;
        uint32 readingCount;
        int32 minTempCenti;
        int32 maxTempCenti;
        uint32 excursionCount;
        uint64 anchoredAt;
        address submitter;
        uint32 attestations;
        bool finalized;
    }

    error NotOwner();
    error NotValidator();
    error AlreadyValidator();
    error InvalidQuorum();
    error EmptyBatch();
    error DuplicateReading(bytes32 digest);
    error UnknownBatch(uint256 batchIndex);
    error BatchAlreadyFinalized(uint256 batchIndex);
    error InvalidProofLength();
    error InvalidTemperatureRange();

    event BatchAnchored(
        uint256 indexed batchIndex,
        bytes32 indexed merkleRoot,
        uint32 readingCount,
        int32 minTempCenti,
        int32 maxTempCenti,
        uint32 excursionCount,
        address indexed submitter
    );
    event BatchAttested(uint256 indexed batchIndex, address indexed validator, uint32 attestations);
    event BatchFinalized(uint256 indexed batchIndex, bytes32 indexed merkleRoot);
    event ReadingCommitted(uint256 indexed batchIndex, bytes32 indexed digest);
    event ExcursionRecorded(
        uint256 indexed batchIndex,
        bytes32 indexed digest,
        int32 observedTempCenti,
        string reason
    );
    event ValidatorChanged(address indexed validator, bool allowed);
    event QuorumChanged(uint256 quorum);

    address public immutable owner;
    bytes32 public constant GENESIS_PARENT = bytes32(0);
    uint256 public quorum;
    uint256 public validatorCount;
    uint256 public batchCount;

    mapping(address => bool) public isValidator;
    mapping(uint256 => Batch) public batches;
    mapping(uint256 => mapping(address => bool)) public attestedBy;
    mapping(bytes32 => uint256) public readingBatch; // digest => batch index (0 = absent)
    mapping(bytes32 => bool) public excursionSeen;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyValidator() {
        if (!isValidator[msg.sender]) revert NotValidator();
        _;
    }

    constructor(address[] memory initialValidators, uint256 quorum_) {
        owner = msg.sender;
        if (quorum_ == 0 || quorum_ > initialValidators.length) revert InvalidQuorum();
        quorum = quorum_;
        validatorCount = initialValidators.length;
        for (uint256 i = 0; i < initialValidators.length; i++) {
            isValidator[initialValidators[i]] = true;
            emit ValidatorChanged(initialValidators[i], true);
        }
    }

    // ------------------------------------------------------------------ admin
    function setValidator(address validator, bool allowed) external onlyOwner {
        if (allowed && isValidator[validator]) revert AlreadyValidator();
        isValidator[validator] = allowed;
        emit ValidatorChanged(validator, allowed);
    }

    function setQuorum(uint256 quorum_) external onlyOwner {
        if (quorum_ == 0 || quorum_ > 64) revert InvalidQuorum();
        quorum = quorum_;
        emit QuorumChanged(quorum_);
    }

    // ---------------------------------------------------------------- anchor
    /**
     * @notice Anchor a batch and commit the individual reading digests.
     * @dev Reverts on duplicate digests across the whole ledger, which makes a
     *      replay visible even if the off-chain gateway were compromised.
     */
    function anchorBatch(
        bytes32 merkleRoot,
        bytes32[] calldata digests,
        int32 minTempCenti,
        int32 maxTempCenti,
        uint32 excursionCount
    ) external onlyValidator returns (uint256 batchIndex) {
        if (digests.length == 0) revert EmptyBatch();
        if (minTempCenti >= maxTempCenti) revert InvalidTemperatureRange();

        batchIndex = ++batchCount;
        batches[batchIndex] = Batch({
            merkleRoot: merkleRoot,
            readingCount: uint32(digests.length),
            minTempCenti: minTempCenti,
            maxTempCenti: maxTempCenti,
            excursionCount: excursionCount,
            anchoredAt: uint64(block.timestamp),
            submitter: msg.sender,
            attestations: 0,
            finalized: false
        });

        for (uint256 i = 0; i < digests.length; i++) {
            bytes32 digest = digests[i];
            if (readingBatch[digest] != 0) revert DuplicateReading(digest);
            readingBatch[digest] = batchIndex;
            emit ReadingCommitted(batchIndex, digest);
        }

        emit BatchAnchored(
            batchIndex,
            merkleRoot,
            uint32(digests.length),
            minTempCenti,
            maxTempCenti,
            excursionCount,
            msg.sender
        );
        _attest(batchIndex);
    }

    /// @notice Independent validators attest an anchored batch until quorum.
    function attest(uint256 batchIndex) external onlyValidator {
        Batch storage batch = batches[batchIndex];
        if (batch.merkleRoot == bytes32(0)) revert UnknownBatch(batchIndex);
        if (batch.finalized) revert BatchAlreadyFinalized(batchIndex);
        _attest(batchIndex);
    }

    function _attest(uint256 batchIndex) internal {
        Batch storage batch = batches[batchIndex];
        if (attestedBy[batchIndex][msg.sender]) return;
        attestedBy[batchIndex][msg.sender] = true;
        batch.attestations += 1;
        emit BatchAttested(batchIndex, msg.sender, batch.attestations);
        if (batch.attestations >= quorum) {
            batch.finalized = true;
            emit BatchFinalized(batchIndex, batch.merkleRoot);
        }
    }

    // ----------------------------------------------------------------- proofs
    /**
     * @notice Verify a reading digest against a batch Merkle root.
     * @param leftFlags True when the sibling at that step is the left node.
     */
    function verifyReading(
        uint256 batchIndex,
        bytes32 digest,
        bytes32[] calldata proof,
        bool[] calldata leftFlags
    ) public view returns (bool) {
        Batch storage batch = batches[batchIndex];
        if (batch.merkleRoot == bytes32(0)) return false;
        if (proof.length != leftFlags.length) revert InvalidProofLength();

        bytes32 node = sha256(abi.encodePacked(bytes1(0x00), digest));
        for (uint256 i = 0; i < proof.length; i++) {
            if (leftFlags[i]) {
                node = sha256(abi.encodePacked(bytes1(0x01), proof[i], node));
            } else {
                node = sha256(abi.encodePacked(bytes1(0x01), node, proof[i]));
            }
        }
        return node == batch.merkleRoot;
    }

    function isReadingCommitted(bytes32 digest) external view returns (bool) {
        return readingBatch[digest] != 0;
    }

    // -------------------------------------------------------------- excursions
    function recordExcursion(
        uint256 batchIndex,
        bytes32 digest,
        int32 observedTempCenti,
        string calldata reason
    ) external onlyValidator {
        if (readingBatch[digest] != batchIndex) revert UnknownBatch(batchIndex);
        bytes32 key = keccak256(abi.encodePacked(batchIndex, digest, observedTempCenti));
        if (excursionSeen[key]) return;
        excursionSeen[key] = true;
        emit ExcursionRecorded(batchIndex, digest, observedTempCenti, reason);
    }

    // ------------------------------------------------------------------ views
    function batchAttestations(uint256 batchIndex) external view returns (uint32) {
        return batches[batchIndex].attestations;
    }

    function isFinalized(uint256 batchIndex) external view returns (bool) {
        return batches[batchIndex].finalized;
    }
}
