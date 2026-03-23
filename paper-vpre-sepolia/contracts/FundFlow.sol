// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./OwnableLite.sol";

interface IDataList {
    struct Listing {
        uint256 uid;
        address seller;
        uint256 priceWei;
        uint64 listedAt;
        bool listed;
        bool locked;
    }

    function getListing(uint256 uid) external view returns (Listing memory);
    function setLock(uint256 uid, bool locked) external;
}

contract FundFlow is OwnableLite {
    struct Escrow {
        uint256 uid;
        address buyer;
        address seller;
        uint256 amountWei;
        uint64 depositedAt;
        uint64 deadline;
        bool released;
        bool withdrawn;
        bool exists;
    }

    IDataList public immutable dataList;
    address public tradingContract;
    uint64 public immutable tradeWindowSeconds;

    mapping(uint256 => Escrow) public escrows;

    event TradingContractSet(address indexed tradingContract);
    event Deposited(uint256 indexed uid, address indexed buyer, address indexed seller, uint256 amountWei, uint256 deadline);
    event Released(uint256 indexed uid, address indexed seller, uint256 amountWei);
    event Withdrawn(uint256 indexed uid, address indexed buyer, uint256 amountWei);

    modifier onlyTrading() {
        require(msg.sender == tradingContract, "only trading");
        _;
    }

    constructor(address initialOwner, address dataListAddress, uint64 tradeWindowSeconds_) OwnableLite(initialOwner) {
        require(dataListAddress != address(0), "zero dataList");
        require(tradeWindowSeconds_ > 0, "window 0");
        dataList = IDataList(dataListAddress);
        tradeWindowSeconds = tradeWindowSeconds_;
    }

    function setTradingContract(address tradingContract_) external onlyOwner {
        require(tradingContract_ != address(0), "zero trading");
        tradingContract = tradingContract_;
        emit TradingContractSet(tradingContract_);
    }

    function deposit(uint256 uid) external payable {
        Escrow storage esc = escrows[uid];
        require(!esc.exists || esc.released || esc.withdrawn, "trade locked");

        IDataList.Listing memory listing = dataList.getListing(uid);
        require(listing.listed, "not listed");
        require(!listing.locked, "already locked");
        require(msg.value == listing.priceWei, "price mismatch");

        uint64 nowTs = uint64(block.timestamp);
        escrows[uid] = Escrow({
            uid: uid,
            buyer: msg.sender,
            seller: listing.seller,
            amountWei: msg.value,
            depositedAt: nowTs,
            deadline: nowTs + tradeWindowSeconds,
            released: false,
            withdrawn: false,
            exists: true
        });

        dataList.setLock(uid, true);

        emit Deposited(uid, msg.sender, listing.seller, msg.value, nowTs + tradeWindowSeconds);
    }

    function releaseToSeller(uint256 uid) external onlyTrading {
        Escrow storage esc = escrows[uid];
        require(esc.exists, "no escrow");
        require(!esc.released, "already released");
        require(!esc.withdrawn, "already withdrawn");

        esc.released = true;
        dataList.setLock(uid, false);

        (bool ok, ) = esc.seller.call{value: esc.amountWei}("");
        require(ok, "transfer failed");

        emit Released(uid, esc.seller, esc.amountWei);
    }

    function withdraw(uint256 uid) external {
        Escrow storage esc = escrows[uid];
        require(esc.exists, "no escrow");
        require(msg.sender == esc.buyer, "not buyer");
        require(!esc.released, "already released");
        require(!esc.withdrawn, "already withdrawn");
        require(block.timestamp > esc.deadline, "window not expired");

        esc.withdrawn = true;
        dataList.setLock(uid, false);

        (bool ok, ) = esc.buyer.call{value: esc.amountWei}("");
        require(ok, "refund failed");

        emit Withdrawn(uid, esc.buyer, esc.amountWei);
    }

    function getEscrow(uint256 uid) external view returns (Escrow memory) {
        Escrow memory esc = escrows[uid];
        require(esc.exists, "no escrow");
        return esc;
    }
}
