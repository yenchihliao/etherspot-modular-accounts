// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IValidator} from "ERC7579/interfaces/IERC7579Module.sol";

interface IResourceLockValidator is IValidator {
    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event RLV_ValidatorEnabled(address indexed scw, address indexed owner);
    event RLV_ValidatorDisabled(address indexed scw);
    event RLV_NonceUpdated(address indexed smartAccount, uint256 newNonce);
}
