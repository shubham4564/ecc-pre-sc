// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IoTAnonymousPRE {
    struct OwnerInfo {
        bool exists;
        address ownerAddr;
    }

    struct DeviceInfo {
        bool exists;
        bytes32 ownerPseudo;
        address deviceAddr;
        bool approved;
    }

    struct DataGrant {
        bool exists;
        bytes32 ownerPseudo;
        bytes32 devicePseudo;
        bytes32 ciphertextHash;
        bytes32 policyHash;
        bytes32 rekeyCommitment;
        bool rekeySubmitted;
    }

    struct RequestInfo {
        bool exists;
        bytes32 dataId;
        address requester;
        bytes32 nonce;
        bool approved;
        bytes32 transformedCipherHash;
    }

    mapping(bytes32 => OwnerInfo) public owners;
    mapping(address => bytes32) public ownerPseudoByAddr;

    mapping(bytes32 => DeviceInfo) public devices;
    mapping(address => bytes32) public devicePseudoByAddr;

    mapping(bytes32 => DataGrant) public grants;
    mapping(bytes32 => RequestInfo) public requests;

    event OwnerRegistered(bytes32 indexed ownerPseudo, address indexed ownerAddr);
    event DeviceRegistered(bytes32 indexed devicePseudo, bytes32 indexed ownerPseudo, address indexed deviceAddr);
    event DataAuthorized(bytes32 indexed dataId, bytes32 indexed ownerPseudo, bytes32 indexed devicePseudo);
    event ReKeySubmitted(bytes32 indexed dataId, bytes32 rekeyCommitment);
    event ReEncryptionRequested(bytes32 indexed requestId, bytes32 indexed dataId, address indexed requester);
    event ReEncryptionApproved(bytes32 indexed requestId, bytes32 transformedCipherHash);

    modifier onlyOwnerPseudo(bytes32 ownerPseudo) {
        require(owners[ownerPseudo].exists, "owner missing");
        require(owners[ownerPseudo].ownerAddr == msg.sender, "not owner");
        _;
    }

    function registerOwner(bytes32 ownerPseudo) external {
        require(ownerPseudo != bytes32(0), "bad pseudo");
        require(!owners[ownerPseudo].exists, "owner exists");
        require(ownerPseudoByAddr[msg.sender] == bytes32(0), "addr bound");

        owners[ownerPseudo] = OwnerInfo({exists: true, ownerAddr: msg.sender});
        ownerPseudoByAddr[msg.sender] = ownerPseudo;

        emit OwnerRegistered(ownerPseudo, msg.sender);
    }

    function registerDevice(bytes32 ownerPseudo, bytes32 devicePseudo, address deviceAddr)
        external
        onlyOwnerPseudo(ownerPseudo)
    {
        require(devicePseudo != bytes32(0), "bad device pseudo");
        require(deviceAddr != address(0), "bad device addr");
        require(!devices[devicePseudo].exists, "device exists");

        devices[devicePseudo] = DeviceInfo({
            exists: true,
            ownerPseudo: ownerPseudo,
            deviceAddr: deviceAddr,
            approved: true
        });
        devicePseudoByAddr[deviceAddr] = devicePseudo;

        emit DeviceRegistered(devicePseudo, ownerPseudo, deviceAddr);
    }

    function authorizeData(bytes32 devicePseudo, bytes32 ciphertextHash, bytes32 policyHash)
        external
        returns (bytes32 dataId)
    {
        bytes32 ownerPseudo = ownerPseudoByAddr[msg.sender];
        require(ownerPseudo != bytes32(0), "owner addr unknown");
        require(devices[devicePseudo].exists, "device missing");
        require(devices[devicePseudo].ownerPseudo == ownerPseudo, "device-owner mismatch");
        require(devices[devicePseudo].approved, "device not approved");

        dataId = keccak256(abi.encodePacked(ownerPseudo, devicePseudo, ciphertextHash, policyHash));
        require(!grants[dataId].exists, "grant exists");

        grants[dataId] = DataGrant({
            exists: true,
            ownerPseudo: ownerPseudo,
            devicePseudo: devicePseudo,
            ciphertextHash: ciphertextHash,
            policyHash: policyHash,
            rekeyCommitment: bytes32(0),
            rekeySubmitted: false
        });

        emit DataAuthorized(dataId, ownerPseudo, devicePseudo);
    }

    function submitReKey(bytes32 dataId, bytes32 rekeyCommitment) external {
        DataGrant storage g = grants[dataId];
        require(g.exists, "grant missing");
        require(ownerPseudoByAddr[msg.sender] == g.ownerPseudo, "not grant owner");
        require(rekeyCommitment != bytes32(0), "bad commitment");

        g.rekeyCommitment = rekeyCommitment;
        g.rekeySubmitted = true;

        emit ReKeySubmitted(dataId, rekeyCommitment);
    }

    function requestReEncryption(bytes32 dataId, bytes32 nonce)
        external
        returns (bytes32 requestId)
    {
        DataGrant storage g = grants[dataId];
        require(g.exists, "grant missing");
        require(g.rekeySubmitted, "rekey missing");

        bytes32 devicePseudo = devicePseudoByAddr[msg.sender];
        require(devicePseudo != bytes32(0), "device addr unknown");
        require(devicePseudo == g.devicePseudo, "device mismatch");

        requestId = keccak256(abi.encodePacked(dataId, msg.sender, nonce));
        require(!requests[requestId].exists, "request exists");

        requests[requestId] = RequestInfo({
            exists: true,
            dataId: dataId,
            requester: msg.sender,
            nonce: nonce,
            approved: false,
            transformedCipherHash: bytes32(0)
        });

        emit ReEncryptionRequested(requestId, dataId, msg.sender);
    }

    function approveReEncryption(bytes32 requestId, bytes32 transformedCipherHash) external {
        RequestInfo storage r = requests[requestId];
        require(r.exists, "request missing");
        DataGrant storage g = grants[r.dataId];
        require(g.exists, "grant missing");
        require(ownerPseudoByAddr[msg.sender] == g.ownerPseudo, "not grant owner");

        r.approved = true;
        r.transformedCipherHash = transformedCipherHash;

        emit ReEncryptionApproved(requestId, transformedCipherHash);
    }

    function verifyAccess(bytes32 requestId, bytes32 expectedTransformedCipherHash) external view returns (bool) {
        RequestInfo storage r = requests[requestId];
        if (!r.exists || !r.approved) {
            return false;
        }
        return r.transformedCipherHash == expectedTransformedCipherHash;
    }
}
