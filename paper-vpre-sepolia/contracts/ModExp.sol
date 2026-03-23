// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library ModExp {
    function modExp(uint256 base, uint256 exponent, uint256 modulus) internal view returns (uint256 result) {
        if (modulus == 1) {
            return 0;
        }

        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), base, exponent, modulus);
        bytes memory output = new bytes(32);

        bool success;
        assembly {
            success := staticcall(gas(), 0x05, add(input, 0x20), mload(input), add(output, 0x20), 32)
        }
        require(success, "modexp failed");

        assembly {
            result := mload(add(output, 0x20))
        }
    }
}
