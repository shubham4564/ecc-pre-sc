// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BloomFilter.sol";

contract SENSHSearchableEncryption {
    struct EncryptedData {
        bytes32 label;
        bytes32 encryptedValue;
        bool exists;
        uint256 timestamp;
    }

    struct TokenInfo {
        uint256 version;
        uint256 count;
        bytes32 tokenValue;
    }

    address public owner;
    BloomFilter public authorizedUsersFilter;
    BloomFilter public labelsFilter;

    uint256 public currentVersion;
    uint256 public obfuscationFactor;
    bytes32 public searchResult;

    address[] private authorizedAddresses;
    bytes32[] private allLabels;

    mapping(address => bool) public isAuthorized;
    mapping(bytes32 => EncryptedData) public LEDD;
    mapping(bytes32 => TokenInfo) public tokens;

    event UserAuthorized(address indexed user);
    event UserRevoked(address indexed user);
    event LabelGenerated(bytes32 indexed label, bytes32 encryptedValue);
    event LabelUpdated(bytes32 indexed label, bytes32 encryptedValue);
    event TokenGenerated(bytes32 indexed label, bytes32 tokenValue, uint256 version, uint256 count);
    event SearchExecuted(bytes32 indexed label, address indexed requester, bytes32 encryptedValue);

    modifier onlyOwner() {
        require(msg.sender == owner, "Owner only");
        _;
    }

    modifier onlyAuthorized() {
        require(isAuthorized[msg.sender], "Unauthorized");
        _;
    }

    constructor(address owner_, uint256 filterBits, uint256 hashFunctions) {
        require(owner_ != address(0), "Bad owner");
        owner = owner_;
        currentVersion = 1;
        obfuscationFactor = 5;

        authorizedUsersFilter = new BloomFilter(address(this), filterBits, hashFunctions);
        labelsFilter = new BloomFilter(address(this), filterBits, hashFunctions);

        _authorize(owner_);
    }

    function _userHash(address user) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(user));
    }

    function _authorize(address user) internal {
        bytes32 userHash = _userHash(user);
        if (!isAuthorized[user]) {
            isAuthorized[user] = true;
            authorizedAddresses.push(user);
            authorizedUsersFilter.add(userHash);
            emit UserAuthorized(user);
        }
    }

    function authorizeUser(address user) external onlyOwner {
        require(user != address(0), "Bad user");
        _authorize(user);
    }

    function revokeUser(address user) external onlyOwner {
        require(isAuthorized[user], "Not authorized");
        isAuthorized[user] = false;

        bytes32 userHash = _userHash(user);
        authorizedUsersFilter.remove(userHash);

        uint256 len = authorizedAddresses.length;
        for (uint256 i = 0; i < len; i++) {
            if (authorizedAddresses[i] == user) {
                authorizedAddresses[i] = authorizedAddresses[len - 1];
                authorizedAddresses.pop();
                break;
            }
        }

        emit UserRevoked(user);
    }

    function getAuthorizedUsers() external view returns (address[] memory) {
        return authorizedAddresses;
    }

    function setObfuscationFactor(uint256 factor) external onlyOwner {
        require(factor > 0 && factor <= 64, "Invalid factor");
        obfuscationFactor = factor;
    }

    function incrementVersion() external onlyOwner {
        currentVersion += 1;
    }

    function generateLabel(string calldata K, string calldata Endata, bytes32 REndata)
        external
        onlyAuthorized
        returns (bytes32)
    {
        bytes32 k1 = keccak256(abi.encodePacked(K, "k1"));
        bytes32 label = keccak256(abi.encodePacked(k1, Endata));

        if (!LEDD[label].exists) {
            allLabels.push(label);
            labelsFilter.add(label);
        }

        LEDD[label] = EncryptedData({
            label: label,
            encryptedValue: REndata,
            exists: true,
            timestamp: block.timestamp
        });

        emit LabelGenerated(label, REndata);
        return label;
    }

    function updateLabel(bytes32 label, bytes32 newEncryptedValue) external onlyAuthorized {
        require(LEDD[label].exists, "Label missing");
        LEDD[label].encryptedValue = newEncryptedValue;
        LEDD[label].timestamp = block.timestamp;
        emit LabelUpdated(label, newEncryptedValue);
    }

    function generateToken(bytes32 label) external onlyAuthorized returns (bytes32) {
        require(LEDD[label].exists, "Label missing");

        TokenInfo storage token = tokens[label];
        token.count += 1;

        bytes32 k2 = keccak256(abi.encodePacked(label, "k2"));
        token.version = currentVersion;
        token.tokenValue = keccak256(abi.encodePacked(label, currentVersion, token.count, k2));

        emit TokenGenerated(label, token.tokenValue, token.version, token.count);
        return token.tokenValue;
    }

    function search(bytes32 label) external onlyAuthorized returns (bytes32[] memory results, bytes32 matchedCiphertext) {
        require(labelsFilter.exists(label), "Label absent in filter");

        results = new bytes32[](obfuscationFactor);
        results[0] = LEDD[label].exists ? label : bytes32(0);

        for (uint256 i = 1; i < obfuscationFactor; i++) {
            results[i] = keccak256(abi.encodePacked(label, i, block.timestamp, block.prevrandao));
        }

        searchResult = LEDD[label].encryptedValue;
        emit SearchExecuted(label, msg.sender, searchResult);
        return (results, searchResult);
    }

    function getResult() external view returns (bytes32) {
        return searchResult;
    }

    function getAllLabels() external view returns (bytes32[] memory) {
        return allLabels;
    }

    function removeLabel(bytes32 label) external onlyOwner {
        if (LEDD[label].exists) {
            labelsFilter.remove(label);
            delete LEDD[label];
        }
    }
}
