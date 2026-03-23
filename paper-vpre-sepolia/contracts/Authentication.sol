// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./OwnableLite.sol";

contract Authentication is OwnableLite {
    struct Submission {
        address seller;
        uint256 sellerPk;
        bytes encryptedFKeyForEvaluator;
        bytes32 dataDescriptionHash;
        bool exists;
    }

    struct Product {
        address seller;
        bytes encryptedFKeyForSeller;
        bytes32 dataDescriptionHash;
        string dataAddress;
        uint64 authenticatedAt;
        bool exists;
    }

    mapping(bytes32 => Submission) public submissions;
    mapping(uint256 => Product) public products;
    mapping(address => bool) public evaluators;

    uint256 private _uidNonce;

    event EvaluatorUpdated(address indexed evaluator, bool enabled);
    event SubmittedForAuthentication(
        bytes32 indexed submissionId,
        address indexed seller,
        uint256 sellerPk,
        bytes32 dataDescriptionHash
    );
    event ProductAuthenticated(
        uint256 indexed uid,
        bytes32 indexed submissionId,
        address indexed seller,
        bytes32 dataDescriptionHash,
        string dataAddress
    );

    modifier onlyEvaluator() {
        require(evaluators[msg.sender], "not evaluator");
        _;
    }

    constructor(address initialOwner, address initialEvaluator) OwnableLite(initialOwner) {
        require(initialEvaluator != address(0), "zero evaluator");
        evaluators[initialEvaluator] = true;
        emit EvaluatorUpdated(initialEvaluator, true);
    }

    function setEvaluator(address evaluator, bool enabled) external onlyOwner {
        require(evaluator != address(0), "zero evaluator");
        evaluators[evaluator] = enabled;
        emit EvaluatorUpdated(evaluator, enabled);
    }

    function submitForAuthentication(
        bytes32 submissionId,
        uint256 sellerPk,
        bytes calldata encryptedFKeyForEvaluator,
        bytes32 dataDescriptionHash
    ) external {
        require(submissionId != bytes32(0), "zero submissionId");
        require(sellerPk != 0, "zero sellerPk");
        require(encryptedFKeyForEvaluator.length != 0, "empty Cfk");
        require(dataDescriptionHash != bytes32(0), "empty DD hash");
        require(!submissions[submissionId].exists, "submission exists");

        submissions[submissionId] = Submission({
            seller: msg.sender,
            sellerPk: sellerPk,
            encryptedFKeyForEvaluator: encryptedFKeyForEvaluator,
            dataDescriptionHash: dataDescriptionHash,
            exists: true
        });

        emit SubmittedForAuthentication(submissionId, msg.sender, sellerPk, dataDescriptionHash);
    }

    function authenticateData(
        bytes32 submissionId,
        bytes calldata encryptedFKeyForSeller,
        string calldata dataAddress
    ) external onlyEvaluator returns (uint256 uid) {
        Submission memory sub = submissions[submissionId];
        require(sub.exists, "missing submission");
        require(encryptedFKeyForSeller.length != 0, "empty Ckey");
        require(bytes(dataAddress).length != 0, "empty DAddr");

        _uidNonce += 1;
        uid = uint256(keccak256(abi.encodePacked(block.chainid, submissionId, _uidNonce, sub.seller, dataAddress)));
        require(!products[uid].exists, "uid collision");

        products[uid] = Product({
            seller: sub.seller,
            encryptedFKeyForSeller: encryptedFKeyForSeller,
            dataDescriptionHash: sub.dataDescriptionHash,
            dataAddress: dataAddress,
            authenticatedAt: uint64(block.timestamp),
            exists: true
        });

        emit ProductAuthenticated(uid, submissionId, sub.seller, sub.dataDescriptionHash, dataAddress);
    }

    function ownerOfProduct(uint256 uid) external view returns (address) {
        Product memory p = products[uid];
        require(p.exists, "unknown uid");
        return p.seller;
    }

    function getProduct(uint256 uid) external view returns (Product memory) {
        Product memory p = products[uid];
        require(p.exists, "unknown uid");
        return p;
    }
}
