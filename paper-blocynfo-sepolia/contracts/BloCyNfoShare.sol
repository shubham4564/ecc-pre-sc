// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./OwnableLite.sol";

contract BloCyNfoShare is OwnableLite {
    struct ParamsRecord {
        bytes32 paramsHash;
        string paramsUri;
        uint64 updatedAt;
        bool exists;
    }

    struct Organization {
        bytes32 orgId;
        uint256 publicKey;
        bytes32 credentialsHash;
        bytes32 attrSetHash;
        bytes32 signedPubKeyHash;
        bool registered;
        bool approved;
        bool isQueryEnabled;
        uint64 registeredAt;
    }

    struct CTIRecord {
        bytes32 ctiId;
        address owner;
        bytes32 ctiHash;
        bytes32 policyHash;
        string ctiUri;
        uint64 createdAt;
        bool exists;
    }

    struct ReKeyRecord {
        bytes32 reKeyHash;
        bytes encryptedReKey;
        uint64 createdAt;
        bool active;
    }

    ParamsRecord private _params;

    mapping(address => Organization) public organizations;
    mapping(bytes32 => CTIRecord) public ctiRecords;
    mapping(bytes32 => mapping(address => ReKeyRecord)) public reKeys;

    event ParamsStored(bytes32 indexed paramsHash, string paramsUri);
    event OrganizationRegistrationRequested(address indexed org, bytes32 indexed orgId, bytes32 credentialsHash);
    event OrganizationApproved(address indexed org, bool approved, bool isQueryEnabled);
    event QueryPublicKeyUpdated(address indexed org, uint256 publicKey, bytes32 signedPubKeyHash);
    event CTIHashStored(bytes32 indexed ctiId, address indexed owner, bytes32 ctiHash, bytes32 policyHash, string ctiUri);
    event ReKeyStored(bytes32 indexed ctiId, address indexed owner, address indexed queryOrg, bytes32 reKeyHash);
    event ReKeyRevoked(bytes32 indexed ctiId, address indexed owner, address indexed queryOrg);

    modifier onlyApprovedOrg() {
        require(organizations[msg.sender].approved, "org not approved");
        _;
    }

    constructor(address initialOwner) OwnableLite(initialOwner) {}

    function storeParams(bytes32 paramsHash, string calldata paramsUri) external onlyOwner {
        require(paramsHash != bytes32(0), "empty params hash");
        _params = ParamsRecord({
            paramsHash: paramsHash,
            paramsUri: paramsUri,
            updatedAt: uint64(block.timestamp),
            exists: true
        });
        emit ParamsStored(paramsHash, paramsUri);
    }

    function retrieveParams() external view returns (ParamsRecord memory) {
        require(_params.exists, "params missing");
        return _params;
    }

    function orgRegistration(
        bytes32 orgId,
        uint256 publicKey,
        bytes32 credentialsHash,
        bytes32 attrSetHash
    ) external {
        require(orgId != bytes32(0), "empty orgId");
        require(publicKey != 0, "empty public key");
        require(credentialsHash != bytes32(0), "empty creds hash");

        Organization storage org = organizations[msg.sender];
        org.orgId = orgId;
        org.publicKey = publicKey;
        org.credentialsHash = credentialsHash;
        org.attrSetHash = attrSetHash;
        org.registered = true;
        org.registeredAt = uint64(block.timestamp);

        emit OrganizationRegistrationRequested(msg.sender, orgId, credentialsHash);
    }

    function approveOrganization(address orgAddr, bool approved, bool isQueryEnabled) external onlyOwner {
        Organization storage org = organizations[orgAddr];
        require(org.registered, "org not registered");
        org.approved = approved;
        org.isQueryEnabled = isQueryEnabled;
        emit OrganizationApproved(orgAddr, approved, isQueryEnabled);
    }

    function regPubKey(uint256 publicKey, bytes32 signedPubKeyHash) external onlyApprovedOrg {
        require(publicKey != 0, "empty public key");
        require(signedPubKeyHash != bytes32(0), "empty signed key hash");

        Organization storage org = organizations[msg.sender];
        require(org.isQueryEnabled, "query role disabled");

        org.publicKey = publicKey;
        org.signedPubKeyHash = signedPubKeyHash;

        emit QueryPublicKeyUpdated(msg.sender, publicKey, signedPubKeyHash);
    }

    function hashCTI(
        bytes32 ctiId,
        bytes32 ctiHash,
        bytes32 policyHash,
        string calldata ctiUri
    ) external onlyApprovedOrg {
        require(ctiId != bytes32(0), "empty ctiId");
        require(ctiHash != bytes32(0), "empty cti hash");
        require(policyHash != bytes32(0), "empty policy hash");

        CTIRecord storage rec = ctiRecords[ctiId];
        require(!rec.exists, "cti already exists");

        ctiRecords[ctiId] = CTIRecord({
            ctiId: ctiId,
            owner: msg.sender,
            ctiHash: ctiHash,
            policyHash: policyHash,
            ctiUri: ctiUri,
            createdAt: uint64(block.timestamp),
            exists: true
        });

        emit CTIHashStored(ctiId, msg.sender, ctiHash, policyHash, ctiUri);
    }

    function storeReKey(
        bytes32 ctiId,
        address queryOrg,
        bytes32 reKeyHash,
        bytes calldata encryptedReKey
    ) external onlyApprovedOrg {
        require(queryOrg != address(0), "zero query org");
        require(reKeyHash != bytes32(0), "empty rekey hash");
        require(encryptedReKey.length != 0, "empty rekey");

        CTIRecord memory rec = ctiRecords[ctiId];
        require(rec.exists, "cti missing");
        require(rec.owner == msg.sender, "not cti owner");

        Organization memory qo = organizations[queryOrg];
        require(qo.approved, "query org not approved");
        require(qo.isQueryEnabled, "query role disabled");

        reKeys[ctiId][queryOrg] = ReKeyRecord({
            reKeyHash: reKeyHash,
            encryptedReKey: encryptedReKey,
            createdAt: uint64(block.timestamp),
            active: true
        });

        emit ReKeyStored(ctiId, msg.sender, queryOrg, reKeyHash);
    }

    function revokeReKey(bytes32 ctiId, address queryOrg) external {
        CTIRecord memory rec = ctiRecords[ctiId];
        require(rec.exists, "cti missing");
        require(rec.owner == msg.sender, "not cti owner");

        ReKeyRecord storage rk = reKeys[ctiId][queryOrg];
        require(rk.active, "rekey not active");

        rk.active = false;
        emit ReKeyRevoked(ctiId, msg.sender, queryOrg);
    }

    function verify(
        bytes32 ctiId,
        address queryOrg,
        bytes32 claimedCtiHash,
        bytes32 claimedReKeyHash
    ) external view returns (bool) {
        CTIRecord memory rec = ctiRecords[ctiId];
        if (!rec.exists) {
            return false;
        }
        if (rec.ctiHash != claimedCtiHash) {
            return false;
        }

        Organization memory qo = organizations[queryOrg];
        if (!qo.approved || !qo.isQueryEnabled) {
            return false;
        }

        ReKeyRecord memory rk = reKeys[ctiId][queryOrg];
        if (!rk.active) {
            return false;
        }

        return rk.reKeyHash == claimedReKeyHash;
    }

    function getReKeyBlob(bytes32 ctiId, address queryOrg) external view returns (bytes memory) {
        ReKeyRecord memory rk = reKeys[ctiId][queryOrg];
        require(rk.active, "rekey inactive");
        return rk.encryptedReKey;
    }
}
