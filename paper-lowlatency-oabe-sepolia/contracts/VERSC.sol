// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VERSC {
    struct CipherMeta {
        bytes32 cTag;
        bytes32 h2R;
        bool exists;
        uint64 createdAt;
        address uploader;
    }

    address public owner;
    bytes32 public immutable phi;
    bytes32 public immutable varphi;

    mapping(bytes32 => CipherMeta) public cipherMetaByTag;

    event CipherMetaStored(bytes32 indexed mtag, bytes32 cTag, bytes32 h2R);
    event ConformEvaluated(bytes32 indexed mtag, bool ok);

    modifier onlyOwner() {
        require(msg.sender == owner, "Owner only");
        _;
    }

    constructor(address owner_, bytes32 phi_, bytes32 varphi_) {
        require(owner_ != address(0), "Bad owner");
        owner = owner_;
        phi = phi_;
        varphi = varphi_;
    }

    function registerCipherMeta(bytes32 mtag, bytes32 cTag, bytes32 h2R) external onlyOwner {
        require(mtag != bytes32(0), "Bad mtag");
        require(cTag != bytes32(0), "Bad cTag");

        cipherMetaByTag[mtag] = CipherMeta({
            cTag: cTag,
            h2R: h2R,
            exists: true,
            createdAt: uint64(block.timestamp),
            uploader: msg.sender
        });

        emit CipherMetaStored(mtag, cTag, h2R);
    }

    // Paper-mapped consistency condition: Ctag = phi xor varphi xor H2(m') xor H2(R)
    function conformVerify(bytes32 mtag, bytes32 h2m, bytes32 h2r) public view returns (bool) {
        CipherMeta memory meta = cipherMetaByTag[mtag];
        if (!meta.exists) {
            return false;
        }
        if (meta.h2R != h2r) {
            return false;
        }

        bytes32 computed = phi ^ varphi ^ h2m ^ h2r;
        return computed == meta.cTag;
    }

    function conformVerifyTx(bytes32 mtag, bytes32 h2m, bytes32 h2r) external returns (bool) {
        bool ok = conformVerify(mtag, h2m, h2r);
        emit ConformEvaluated(mtag, ok);
        return ok;
    }
}
