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
    mapping(address => mapping(uint256 => bool)) public usedUserNonces;

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

    // Schnorr ZKP Constants
    // -------------------------------------------------------------------------
    // Curve parameters are SECP256k1, defined above.
    
    struct ReEncryptInputs {
        uint256 rk1;
        uint256 rk2;
        uint256 rk3;
        uint256 commitmentX;  // Schnorr commitment W_x
        uint256 commitmentY;  // Schnorr commitment W_y
        uint256 response;     // Schnorr response z
        uint256 nonce;        // SP Nonce
        uint256 expiry;       // SP Expiry
        // User Intent & Authorization Fields:
        address userPublicKey;
        uint256 userNonce;
        uint256 userExpiry;
        bytes userSignature;  // ECDSA Signature (r, s, v)
    }

    function verifyUserIntent(ReEncryptInputs memory params) public view returns (bool) {
        if (params.userExpiry != 0 && block.timestamp > params.userExpiry) return false;
        if (params.userPublicKey == address(0)) return false;
        if (params.userSignature.length != 65) return false;

        bytes32 token = keccak256(
            abi.encodePacked(address(this), msg.sender, params.userNonce, params.userExpiry)
        );
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", token)
        );
        address recovered = recoverSigner(ethSignedMessageHash, params.userSignature);
        return (recovered == params.userPublicKey);
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _sig) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_sig);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function computeSchnorrChallenge(
        ReEncryptInputs memory params,
        uint proofPublicKeyX,
        uint proofPublicKeyY
    ) internal view returns (uint256) {
        bytes32 userToken = keccak256(abi.encodePacked(address(this), msg.sender, params.userNonce, params.userExpiry));
        bytes32 h1 = keccak256(
            abi.encodePacked(
                address(this),
                msg.sender,
                params.rk1,
                params.rk2,
                params.rk3,
                params.commitmentX,
                params.commitmentY
            )
        );
        bytes32 h2 = keccak256(
            abi.encodePacked(
                proofPublicKeyX,
                proofPublicKeyY,
                params.userPublicKey,
                userToken,
                params.userSignature,
                params.nonce,
                params.expiry
            )
        );
        return uint256(keccak256(abi.encodePacked(h1, h2))) % CURVE_ORDER;
    }

    function verifySchnorrZKP(
        ReEncryptInputs memory params,
        uint proofPublicKeyX,
        uint proofPublicKeyY
    ) public view returns (bool) {
        // 1. Verify W is on curve
        if (!EllipticCurve.isOnCurve(params.commitmentX, params.commitmentY, 0, 7, PRIME_FIELD_MODULUS)) {
            return false;
        }

        // 2. Compute Challenge c
        uint256 c = computeSchnorrChallenge(params, proofPublicKeyX, proofPublicKeyY);
        require(c != 0, "Invalid challenge");

        // 3. Verify z * G == W + c * T using ecrecover trick (~3000 gas instead of ~80000 gas)
        // W = z*G - c*T
        // Q = r^-1 (s*W - h*G)
        // To recover Q = T, we need s = -r/c (mod q) and h = z*s (mod q)
        uint256 r = params.commitmentX % CURVE_ORDER;
        require(r != 0, "Invalid r");
        
        uint256 invC = EllipticCurve.invMod(c, CURVE_ORDER);
        
        // s = -r * invC (mod CURVE_ORDER)
        uint256 minusR = CURVE_ORDER - r;
        uint256 s = mulmod(minusR, invC, CURVE_ORDER);
        
        // h = z * s (mod CURVE_ORDER)
        uint256 h = mulmod(params.response, s, CURVE_ORDER);
        
        // v = 27 + (Wy % 2)
        uint8 v = uint8(27 + (params.commitmentY % 2));
        
        address recovered = ecrecover(bytes32(h), v, bytes32(r), bytes32(s));
        address expectedAddress = address(uint160(uint256(keccak256(abi.encodePacked(proofPublicKeyX, proofPublicKeyY)))));
        
        return (recovered != address(0) && recovered == expectedAddress);
    }

    function verifySchnorrZKP(ReEncryptInputs memory params) public view returns (bool) {
        (uint pub0, uint pub1, bool isSet) = countingContract.getProofPublicKey(msg.sender);
        if (!isSet) return false;
        return verifySchnorrZKP(params, pub0, pub1);
    }

    function verifyZKProof(ReEncryptInputs memory params) public view returns (bool) {
        return verifySchnorrZKP(params);
    }

    function reEncrypt(ReEncryptInputs memory params)
        public
        returns (uint, uint, bytes memory, uint)
    {
        require(countingContract.isAllowed(msg.sender), "Unauthorized service provider");
        require(params.expiry == 0 || block.timestamp <= params.expiry, "Proof expired");

        // 1. Verify User Intent & Signature
        require(verifyUserIntent(params), "User intent verification failed");

        // 2. User Replay Protection
        require(!usedUserNonces[params.userPublicKey][params.userNonce], "User nonce already used");

        // 3. SP Nonce Replay Protection
        bytes32 nonceKey = keccak256(abi.encodePacked(msg.sender, params.nonce));
        require(!usedProofNonces[nonceKey], "SP nonce already used");

        (uint pub0, uint pub1, bool isSet) = countingContract.getProofPublicKey(msg.sender);
        require(isSet, "Proof public key not set");

        require(
            verifySchnorrZKP(params, pub0, pub1),
            "Proof verification failed"
        );

        usedUserNonces[params.userPublicKey][params.userNonce] = true;
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
