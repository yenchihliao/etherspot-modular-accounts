// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IMSA} from "ERC7579/interfaces/IMSA.sol";
import {IAccessController} from "./IAccessController.sol";

interface IModularEtherspotWallet is IMSA, IAccessController {
    error OnlyProxy();
}
