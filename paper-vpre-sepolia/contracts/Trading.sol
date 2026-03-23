// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./OwnableLite.sol";
import "./ModExp.sol";

interface IFundFlow {
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

    function getEscrow(uint256 uid) external view returns (Escrow memory);
    function releaseToSeller(uint256 uid) external;
}

contract Trading is OwnableLite {
    using ModExp for uint256;

    struct TradeState {
        uint256 uid;
        address seller;
        address buyer;
        uint256 sellerPk;
        uint256 dbPk;
        uint256 pke;
        bytes32 cmit;
        uint256 vk;
        uint256 rk;
        bool cmitSubmitted;
        bool vkSubmitted;
        bool settled;
    }

    // Engineering choice: finite multiplicative subgroup model for on-chain g^x checks.
    uint256 public constant PRIME_MODULUS = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant GENERATOR = 5;

    IFundFlow public immutable fundFlow;

    mapping(uint256 => TradeState) public trades;

    event CommitmentSubmitted(uint256 indexed uid, address indexed seller, uint256 pke, bytes32 cmit);
    event VerificationKeySubmitted(uint256 indexed uid, address indexed buyer, uint256 vk, bool cmitCheckPassed);
    event TradeSettled(uint256 indexed uid, uint256 rk, uint256 gPowRk);

    constructor(address initialOwner, address fundFlowAddress) OwnableLite(initialOwner) {
        require(fundFlowAddress != address(0), "zero fundflow");
        fundFlow = IFundFlow(fundFlowAddress);
    }

    function submitCmit(
        uint256 uid,
        uint256 sellerPk,
        uint256 dbPk,
        uint256 pke,
        bytes32 cmit
    ) external {
        require(cmit != bytes32(0), "empty cmit");
        require(sellerPk != 0 && dbPk != 0 && pke != 0, "zero key");

        IFundFlow.Escrow memory esc = fundFlow.getEscrow(uid);
        require(esc.exists, "no escrow");
        require(msg.sender == esc.seller, "not seller");
        require(block.timestamp <= esc.deadline, "window expired");

        TradeState storage t = trades[uid];
        require(!t.settled, "already settled");

        t.uid = uid;
        t.seller = esc.seller;
        t.buyer = esc.buyer;
        t.sellerPk = sellerPk;
        t.dbPk = dbPk;
        t.pke = pke;
        t.cmit = cmit;
        t.cmitSubmitted = true;

        emit CommitmentSubmitted(uid, msg.sender, pke, cmit);
    }

    function submitVK(uint256 uid, uint256 vk) external {
        TradeState storage t = trades[uid];
        require(t.cmitSubmitted, "cmit missing");
        require(!t.settled, "already settled");

        IFundFlow.Escrow memory esc = fundFlow.getEscrow(uid);
        require(esc.exists, "no escrow");
        require(msg.sender == esc.buyer, "not buyer");
        require(block.timestamp <= esc.deadline, "window expired");

        bool cmitCheck = keccak256(abi.encodePacked(vk)) == t.cmit;
        require(cmitCheck, "invalid vk for cmit");

        t.vk = vk;
        t.vkSubmitted = true;

        emit VerificationKeySubmitted(uid, msg.sender, vk, true);
    }

    function settlement(uint256 uid, uint256 rk) external {
        TradeState storage t = trades[uid];
        require(t.cmitSubmitted, "cmit missing");
        require(t.vkSubmitted, "vk missing");
        require(!t.settled, "already settled");
        require(msg.sender == t.seller, "not seller");

        IFundFlow.Escrow memory esc = fundFlow.getEscrow(uid);
        require(esc.exists, "no escrow");
        require(block.timestamp <= esc.deadline, "window expired");

        uint256 gPowRk = GENERATOR.modExp(rk, PRIME_MODULUS);
        require(keccak256(abi.encodePacked(gPowRk)) == t.cmit, "rk does not match cmit");

        t.rk = rk;
        t.settled = true;

        fundFlow.releaseToSeller(uid);

        emit TradeSettled(uid, rk, gPowRk);
    }
}
