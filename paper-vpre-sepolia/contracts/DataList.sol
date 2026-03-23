// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./OwnableLite.sol";

interface IAuthentication {
    function ownerOfProduct(uint256 uid) external view returns (address);
}

contract DataList is OwnableLite {
    struct Listing {
        uint256 uid;
        address seller;
        uint256 priceWei;
        uint64 listedAt;
        bool listed;
        bool locked;
    }

    IAuthentication public immutable authentication;
    address public tradingContract;

    mapping(uint256 => Listing) public listings;

    event TradingContractSet(address indexed tradingContract);
    event DataListed(uint256 indexed uid, address indexed seller, uint256 priceWei);
    event ListingLockUpdated(uint256 indexed uid, bool locked);
    event ListingUpdated(uint256 indexed uid, uint256 newPriceWei, bool listed);

    modifier onlyTrading() {
        require(msg.sender == tradingContract, "only trading");
        _;
    }

    constructor(address initialOwner, address authenticationAddress) OwnableLite(initialOwner) {
        require(authenticationAddress != address(0), "zero auth");
        authentication = IAuthentication(authenticationAddress);
    }

    function setTradingContract(address tradingContract_) external onlyOwner {
        require(tradingContract_ != address(0), "zero trading");
        tradingContract = tradingContract_;
        emit TradingContractSet(tradingContract_);
    }

    function listData(uint256 uid, uint256 priceWei) external {
        require(priceWei > 0, "price 0");

        address seller = authentication.ownerOfProduct(uid);
        require(seller == msg.sender, "not owner");

        Listing storage l = listings[uid];
        require(!l.locked, "active trade lock");

        l.uid = uid;
        l.seller = seller;
        l.priceWei = priceWei;
        l.listedAt = uint64(block.timestamp);
        l.listed = true;

        emit DataListed(uid, seller, priceWei);
    }

    function setListed(uint256 uid, bool listed) external {
        Listing storage l = listings[uid];
        require(l.seller == msg.sender, "not seller");
        require(!l.locked, "active trade lock");
        l.listed = listed;
        emit ListingUpdated(uid, l.priceWei, listed);
    }

    function updatePrice(uint256 uid, uint256 newPriceWei) external {
        Listing storage l = listings[uid];
        require(l.seller == msg.sender, "not seller");
        require(!l.locked, "active trade lock");
        require(l.listed, "not listed");
        require(newPriceWei > 0, "price 0");

        l.priceWei = newPriceWei;
        emit ListingUpdated(uid, newPriceWei, true);
    }

    function setLock(uint256 uid, bool locked) external onlyTrading {
        Listing storage l = listings[uid];
        require(l.listed, "not listed");
        l.locked = locked;
        emit ListingLockUpdated(uid, locked);
    }

    function getListing(uint256 uid) external view returns (Listing memory) {
        Listing memory l = listings[uid];
        require(l.seller != address(0), "unknown uid");
        return l;
    }
}
