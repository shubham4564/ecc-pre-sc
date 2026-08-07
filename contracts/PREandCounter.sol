// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;
pragma abicoder v2; 

import "./EllipticCurve.sol";
import "./FastEcMul.sol";

contract PRE
{
    // SECP256k1 curve constants
    uint public constant PRIME_FIELD_MODULUS  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint public constant CURVE_ORDER  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint public constant GENERATOR_X = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
    uint public constant GENERATOR_Y = 32670510020758816978083085130507043184471273380659243275938904335757337482424;
    uint public constant LAMBDA = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72;
    uint public constant BETA = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee;

    // Ciphertext values

    uint private immutable c1X;
    uint private immutable c1Y;
    uint private immutable c2X;
    uint private immutable c2Y;
    bytes private c3;
    uint private immutable c4X;
    uint private immutable c4Y;
    uint private immutable c5TimesP;
    uint private immutable hash;    
    address public immutable serviceProviderAdmin;
    bool private immutable countingEnabled;
    mapping(bytes32 => bool) private usedProofNonces;

    // Address for the counting contract
    Counter public immutable countingContract;

    // Constructor to initialize PRE contract
    constructor
    (
        uint _c1X,
        uint _c1Y,
        uint _c2X,
        uint _c2Y,
        bytes memory _c3,
        uint _c4X,
        uint _c4Y,
        uint _c5TimesP,
        address _serviceProviderAdmin,
        address[] memory _allowedAddresses,
        bool _countingEnabled
    ) 
    {
        require(_serviceProviderAdmin != address(0), "Zero admin");
        c1X = _c1X;
        c1Y = _c1Y;
        c2X = _c2X;
        c2Y = _c2Y;
        c3 = _c3;
        c4X = _c4X;
        c4Y = _c4Y;
        c5TimesP = _c5TimesP;
        hash = uint256(keccak256(abi.encodePacked(_c1X, _c2X, _c3, _c4X))) % CURVE_ORDER;
        serviceProviderAdmin = _serviceProviderAdmin;
        countingEnabled = _countingEnabled;
        countingContract = new Counter(address(this), _serviceProviderAdmin, _allowedAddresses);
    }

    // Lattice ZKP Constants (Fiat-Shamir with Rejection Sampling over Matrix Group)
    uint256 public constant LATTICE_Q = 8380417;
    int256 public constant LATTICE_B = 1048575;
    uint256 public constant LATTICE_CHALLENGE_Q = 256;

    // Public matrix A (2 x 4)
    uint256 public constant A00 = 175421;
    uint256 public constant A01 = 894125;
    uint256 public constant A02 = 645123;
    uint256 public constant A03 = 912401;

    uint256 public constant A10 = 451204;
    uint256 public constant A11 = 781203;
    uint256 public constant A12 = 314159;
    uint256 public constant A13 = 271828;

    struct ReEncryptInputs {
        uint rk1;
        uint rk2;
        uint rk3;
        uint256[] commitment; // Vector W (length 2)
        int256[] response;    // Vector Z (length 4)
        uint nonce;
        uint expiry;
    }

    function verifyLatticeZKP(
        ReEncryptInputs memory params,
        uint proofPublicKey0,
        uint proofPublicKey1
    ) public view returns (bool) {
        if (params.commitment.length != 2 || params.response.length != 4) {
            return false;
        }

        // 1. Norm bound check: ||Z||_inf <= LATTICE_B
        for (uint i = 0; i < 4; i++) {
            int256 zVal = params.response[i];
            int256 absZ = zVal < 0 ? -zVal : zVal;
            if (absZ > LATTICE_B) {
                return false;
            }
        }

        // 2. Compute Challenge c
        uint256 c = uint256(
            keccak256(
                abi.encodePacked(
                    address(this),
                    msg.sender,
                    params.rk1,
                    params.rk2,
                    params.rk3,
                    params.commitment[0],
                    params.commitment[1],
                    proofPublicKey0,
                    proofPublicKey1,
                    params.nonce,
                    params.expiry
                )
            )
        ) % LATTICE_CHALLENGE_Q;

        int256 qInt = int256(LATTICE_Q);

        // 3. Compute LHS = A * Z mod Q
        int256 rawLhs0 = (int256(A00) * params.response[0] + int256(A01) * params.response[1] + int256(A02) * params.response[2] + int256(A03) * params.response[3]) % qInt;
        int256 rawLhs1 = (int256(A10) * params.response[0] + int256(A11) * params.response[1] + int256(A12) * params.response[2] + int256(A13) * params.response[3]) % qInt;

        uint256 lhs0 = uint256((rawLhs0 % qInt + qInt) % qInt);
        uint256 lhs1 = uint256((rawLhs1 % qInt + qInt) % qInt);

        // 4. Compute RHS = W + c * T mod Q
        uint256 rhs0 = (params.commitment[0] + c * proofPublicKey0) % LATTICE_Q;
        uint256 rhs1 = (params.commitment[1] + c * proofPublicKey1) % LATTICE_Q;

        return (lhs0 == rhs0 && lhs1 == rhs1);
    }

    function verifyLatticeZKP(ReEncryptInputs memory params) public view returns (bool) {
        (uint pub0, uint pub1, bool isSet) = countingContract.getProofPublicKey(msg.sender);
        if (!isSet) return false;
        return verifyLatticeZKP(params, pub0, pub1);
    }

    function verifyZKProof(ReEncryptInputs memory params) public view returns (bool) {
        return verifyLatticeZKP(params);
    }

    function reEncrypt(ReEncryptInputs memory params)
        public
        returns (uint, uint, bytes memory, uint)
    {
        require(countingContract.isAllowed(msg.sender), "Unauthorized service provider");
        require(params.expiry == 0 || block.timestamp <= params.expiry, "Proof expired");

        bytes32 nonceKey = keccak256(abi.encodePacked(msg.sender, params.nonce));
        require(!usedProofNonces[nonceKey], "Nonce already used");

        (uint pub0, uint pub1, bool isSet) = countingContract.getProofPublicKey(msg.sender);
        require(isSet, "Proof public key not set");

        require(
            verifyLatticeZKP(params, pub0, pub1),
            "Proof verification failed"
        );

        usedProofNonces[nonceKey] = true;

        // Perform re-encryption
        (uint _c1prime, uint _c2prime, uint _c4prime) = performReEncryption(params.rk1, params.rk2, params.rk3);

        return (_c1prime, _c2prime, c3, _c4prime);
    }

    function performReEncryption(uint _rk1, uint _rk2, uint _rk3) internal returns (uint, uint, uint) {
        uint __ = c2X;
        uint _c1prime;
        uint _c2prime;
        uint _c4prime;
        int256 a;
        int256 b;

        uint256[4] memory points = [__, c2Y, 0, 0];

        (a, b) = FastEcMul.decomposeScalar(hash, CURVE_ORDER, LAMBDA);

        int256[4] memory scalars = [a, b, 0, 0];

        (__, _c1prime) = FastEcMul.ecSimMul(scalars, points, 0, BETA, PRIME_FIELD_MODULUS);
        (_c4prime, _c2prime) = EllipticCurve.ecAdd(__, _c1prime, c4X, c4Y, 0, PRIME_FIELD_MODULUS);

        require(c5TimesP == _c4prime, "c5P != c4 + h3(c1, c2, c3, c4)c2");
        if (countingEnabled) {
            countingContract.increment(msg.sender);
        }

        points[0] = c1X;
        points[1] = c1Y;
        (scalars[0], scalars[1]) = FastEcMul.decomposeScalar(_rk1, CURVE_ORDER, LAMBDA);
        (_c1prime, __) = FastEcMul.ecSimMul(scalars, points, 0, BETA, PRIME_FIELD_MODULUS); // RK1 * C1

        (scalars[0], scalars[1]) = FastEcMul.decomposeScalar(_rk2, CURVE_ORDER, LAMBDA);
        (_c2prime, __) = FastEcMul.ecSimMul(scalars, points, 0, BETA, PRIME_FIELD_MODULUS); // RK2 * C1

        (scalars[0], scalars[1]) = FastEcMul.decomposeScalar(_rk3, CURVE_ORDER, LAMBDA);
        (_c4prime, __) = FastEcMul.ecSimMul(scalars, points, 0, BETA, PRIME_FIELD_MODULUS); // RK3 * C1

        return (_c1prime, _c2prime, _c4prime);
    }
}

contract Counter
{
    struct ProofPublicKey {
        uint x;
        uint y;
        bool isSet;
    }

    address private immutable owner;
    address public admin;
    mapping(address => bool) private allowedAddresses;
    mapping(address => ProofPublicKey) private proofPublicKeys;
    mapping(address => uint) public addressCounts;

    event AllowedAddressAdded(address indexed account);
    event AllowedAddressRemoved(address indexed account);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event ProofPublicKeySet(address indexed account, uint indexed x, uint indexed y);
    event ProofPublicKeyCleared(address indexed account);

    modifier onlyAdmin()
    {
        require(msg.sender == admin, "Invalid admin");
        _;
    }

    // Initialize owner and allowed addresses
    constructor(address _owner, address _admin, address[] memory _allowedAddresses)  
    {
        require(_owner != address(0), "Zero address");
        require(_admin != address(0), "Zero admin");
        owner = _owner;
        admin = _admin;

        // Cache the length of _allowedAddresses
        uint256 allowedAddressesLength = _allowedAddresses.length;
        for (uint i = 0; i < allowedAddressesLength; i++) {
            _setAllowedAddress(_allowedAddresses[i], true);
        }
    }

    function _setAllowedAddress(address account, bool allowed) internal
    {
        require(account != address(0), "Zero address");
        allowedAddresses[account] = allowed;
    }

    function _setProofPublicKey(address account, uint pubX, uint pubY) internal
    {
        require(account != address(0), "Zero address");
        require(pubX != 0 && pubY != 0, "Zero proof key");
        proofPublicKeys[account] = ProofPublicKey({x: pubX, y: pubY, isSet: true});
    }

    function isAllowed(address account) public view returns (bool)
    {
        return allowedAddresses[account];
    }

    function addAllowedAddress(address account) external onlyAdmin
    {
        require(!allowedAddresses[account], "Already allowed");
        _setAllowedAddress(account, true);
        emit AllowedAddressAdded(account);
    }

    function setProofPublicKey(address account, uint pubX, uint pubY) external onlyAdmin
    {
        require(allowedAddresses[account], "Address not allowed");
        _setProofPublicKey(account, pubX, pubY);
        emit ProofPublicKeySet(account, pubX, pubY);
    }

    function getProofPublicKey(address account) external view returns (uint, uint, bool)
    {
        ProofPublicKey memory key = proofPublicKeys[account];
        return (key.x, key.y, key.isSet);
    }

    function removeAllowedAddress(address account) external onlyAdmin
    {
        require(allowedAddresses[account], "Address not allowed");
        _setAllowedAddress(account, false);
        delete proofPublicKeys[account];
        emit AllowedAddressRemoved(account);
        emit ProofPublicKeyCleared(account);
    }

    function transferAdmin(address newAdmin) external onlyAdmin
    {
        require(newAdmin != address(0), "Zero admin");
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    // Increment the count
    function increment(address user) public
    {
        require(msg.sender == owner, "Invalid sender");
        require(isAllowed(user), "Invalid user");
        addressCounts[user]++;
    }

    // Request the count
    function getCount(address user) public view returns (uint)
    {
        return addressCounts[user];
    }
}
