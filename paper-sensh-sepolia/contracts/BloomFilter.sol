// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BloomFilter {
    uint256 public constant FILTER_WORD_SIZE = 256;

    address public immutable controller;
    uint256 public immutable bitArrayLength;
    uint256 public immutable numHashes;

    uint256[] private bitArray;

    modifier onlyController() {
        require(msg.sender == controller, "Controller only");
        _;
    }

    constructor(address controller_, uint256 bitArrayLength_, uint256 numHashes_) {
        require(controller_ != address(0), "Bad controller");
        require(bitArrayLength_ >= 256, "Length too small");
        require(numHashes_ > 0, "Hashes must be > 0");

        controller = controller_;
        bitArrayLength = bitArrayLength_;
        numHashes = numHashes_;
        uint256 wordCount = (bitArrayLength_ + FILTER_WORD_SIZE - 1) / FILTER_WORD_SIZE;
        bitArray = new uint256[](wordCount);
    }

    function hash(bytes32 element, uint256 seed) public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(element, seed))) % bitArrayLength;
    }

    function add(bytes32 element) external onlyController {
        for (uint256 i = 0; i < numHashes; i++) {
            uint256 index = hash(element, i);
            uint256 word = index / FILTER_WORD_SIZE;
            uint256 offset = index % FILTER_WORD_SIZE;
            bitArray[word] |= (uint256(1) << offset);
        }
    }

    function exists(bytes32 element) public view returns (bool) {
        for (uint256 i = 0; i < numHashes; i++) {
            uint256 index = hash(element, i);
            uint256 word = index / FILTER_WORD_SIZE;
            uint256 offset = index % FILTER_WORD_SIZE;
            if ((bitArray[word] & (uint256(1) << offset)) == 0) {
                return false;
            }
        }
        return true;
    }

    function remove(bytes32 element) external onlyController {
        for (uint256 i = 0; i < numHashes; i++) {
            uint256 index = hash(element, i);
            uint256 word = index / FILTER_WORD_SIZE;
            uint256 offset = index % FILTER_WORD_SIZE;
            bitArray[word] &= ~(uint256(1) << offset);
        }
    }
}
