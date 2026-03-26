// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ACCSC {
    struct PunishInfo {
        uint256 clo;
        uint64 falseTime;
        uint8 falseNum;
    }

    struct TagPolicy {
        bytes32 rDigest;
        bool exists;
    }

    address public owner;
    uint256 public userNum;
    uint256 public arrNum;

    mapping(address => PunishInfo) public punish;
    mapping(bytes32 => uint8[]) private _tagPolicies;
    mapping(bytes32 => TagPolicy) public tagPolicies;

    event TagPolicyStored(bytes32 indexed mtag, uint256 attrCount, bytes32 rDigest);
    event AccessEvaluated(bytes32 indexed mtag, address indexed user, uint256 indexed userId, uint8 decisionCode);

    modifier onlyOwner() {
        require(msg.sender == owner, "Owner only");
        _;
    }

    constructor(address owner_, uint256 userNum_, uint256 arrNum_) {
        require(owner_ != address(0), "Bad owner");
        owner = owner_;
        userNum = userNum_;
        arrNum = arrNum_;
    }

    function setTagPolicy(bytes32 mtag, uint8[] calldata polCloud, bytes32 rDigest) external onlyOwner {
        require(mtag != bytes32(0), "Bad mtag");
        require(polCloud.length > 0, "Empty policy");

        delete _tagPolicies[mtag];
        for (uint256 i = 0; i < polCloud.length; i++) {
            _tagPolicies[mtag].push(polCloud[i]);
        }
        tagPolicies[mtag] = TagPolicy({rDigest: rDigest, exists: true});
        arrNum = polCloud.length;

        emit TagPolicyStored(mtag, polCloud.length, rDigest);
    }

    function getTagPolicy(bytes32 mtag) external view returns (uint8[] memory, bytes32, bool) {
        TagPolicy memory p = tagPolicies[mtag];
        return (_tagPolicies[mtag], p.rDigest, p.exists);
    }

    function _arrPolicyVerifyCode(bytes32 mtag, uint8[] calldata arrUser, uint256 userId, address userAdd)
        internal
        returns (uint8)
    {
        require(tagPolicies[mtag].exists, "Unknown tag");
        require(userAdd != address(0), "Bad address");

        punish[userAdd].clo = userId;

        if (punish[userAdd].falseTime != 0 && punishment(userAdd)) {
            return 2; // punish
        }

        uint8[] storage polCloud = _tagPolicies[mtag];
        require(arrUser.length == polCloud.length, "Length mismatch");

        uint256 result = 0;
        for (uint256 i = 0; i < polCloud.length; i++) {
            if (polCloud[i] == 1 && arrUser[i] == 0) {
                result += 1;
            }
        }

        if (result == 0) {
            return 1; // right
        }

        punish[userAdd].falseTime = uint64(block.timestamp);
        return 0; // wrong
    }

    // Paper-mapped function name and output style.
    function arrPolicyVerify(bytes32 mtag, uint8[] calldata arrUser, uint256 userId, address userAdd)
        external
        returns (string memory access)
    {
        uint8 code = _arrPolicyVerifyCode(mtag, arrUser, userId, userAdd);
        emit AccessEvaluated(mtag, userAdd, userId, code);

        if (code == 2) {
            return "punish";
        }
        if (code == 1) {
            return "right";
        }
        return "wrong";
    }

    function arrPolicyVerifyCode(bytes32 mtag, uint8[] calldata arrUser, uint256 userId, address userAdd)
        external
        returns (uint8)
    {
        uint8 code = _arrPolicyVerifyCode(mtag, arrUser, userId, userAdd);
        emit AccessEvaluated(mtag, userAdd, userId, code);
        return code;
    }

    // Paper-mapped logic: if falseCount > 3 within 1 minute then punish.
    function punishment(address userAdd) public returns (bool isPenalty) {
        uint256 nowTime = block.timestamp;

        if (nowTime - punish[userAdd].falseTime > 1 minutes) {
            punish[userAdd].falseTime = uint64(nowTime);
            punish[userAdd].falseNum = 1;
            return false;
        }

        if (punish[userAdd].falseNum > 3) {
            return true;
        }

        punish[userAdd].falseNum = punish[userAdd].falseNum + 1;
        return false;
    }
}
