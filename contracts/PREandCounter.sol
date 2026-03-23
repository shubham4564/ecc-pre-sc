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

    function extendedEuclid(int256 e, int256 m) internal pure returns (int256) {
        // Extended Euclidean Algorithm for modular inverse
        int256[3] memory u = [int256(1), int256(0), m];
        int256[3] memory v = [int256(0), int256(1), e];

        while (v[2] != 0) {
            int256 q = u[2] / v[2];
            int256 temp0 = u[0] - q * v[0];
            int256 temp1 = u[1] - q * v[1];
            int256 temp2 = u[2] - q * v[2];

            (u[0], u[1], u[2]) = (v[0], v[1], v[2]);
            (v[0], v[1], v[2]) = (temp0, temp1, temp2);
        }

        if (u[1] < 0) {
            return u[1] + m;
        } else {
            return u[1];
        }
    }
    function modExp(int256 base, int256 exp, int256 m) internal pure returns (int256) {
        // Handle negative exponents by computing inverse later
        bool negativeExp = exp < 0;
        if (negativeExp) {
            exp = -exp;
        }

        // Convert to positive domain
        int256 b = base % m;
        if (b < 0) {
            b += m;
        }

        uint256 e = uint256(exp);
        int256 result = 1;
        while (e > 0) {
            if ((e & 1) == 1) {
                result = (result * b) % m;
            }
            b = (b * b) % m;
            e >>= 1;
        }

        if (negativeExp) {
            result = extendedEuclid(result, m);
        }
        return result;
    }

    function computeVals(int256 base1, int256 base2, int256 exp, int256 w)
    internal pure returns (int256, int256)
    {
        // If exp < 0 => compute pow(base, -exp, w) and take inverse
        if (exp < 0) {
            int256 absExp = -exp;
            int256 valA = modExp(base1, absExp, w);
            int256 valB = modExp(base2, absExp, w);
            valA = extendedEuclid(valA, w);
            valB = extendedEuclid(valB, w);

            return (valA, valB);
        } else {
            // exp >= 0
            int256 valA = modExp(base1, exp, w);
            int256 valB = modExp(base2, exp, w);
            return (valA, valB);
        }
    }


    function verifyProof(int256 i, int256 o, int256 y, int256 z, int256 w, int256 alpha, int256 gamma) pure internal returns (bool)
    {

        int256 gamma_;
        (int256 val1, int256 val2) = computeVals(i, o, alpha, w);
        (int256 val3, int256 val4) = computeVals(y, z, gamma, w);

        int256 A_ = (val1 * val3) % w;
        int256 B_ = (val2 * val4) % w;

        bytes32 hash2 = keccak256(abi.encodePacked(y, z, A_, B_));
        gamma_ = int256(uint256(hash2) % uint256(w));

        if(gamma == gamma_) {
            return true;
        }else {
            return false;
        }
    }


    struct ReEncryptInputs {
        uint rk1;
        uint rk2;
        uint rk3;
        int256 i;
        int256 o;
        int256 y;
        int256 z;
        int256 w;
        int256 alpha;
        int256 gamma;
    }

    function reEncrypt(ReEncryptInputs memory params)
        public
        returns (uint, uint, bytes memory, uint)
    {
        require(countingContract.isAllowed(msg.sender), "Unauthorized service provider");
        require(
            verifyProof(params.i, params.o, params.y, params.z, params.w, params.alpha, params.gamma),
            "Proof verification failed"
        );

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
