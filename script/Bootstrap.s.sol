// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {Bootstrap} from "../src/utils/Bootstrap.sol";

/**
 * @author Etherspot.
 * @title BootstrapScript.
 * @dev Deployment script for Bootstrap.
 */
contract BootstrapScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        console2.log("Starting deployment sequence...");

        /*//////////////////////////////////////////////////////////////
                              Deploy Bootstrap
        //////////////////////////////////////////////////////////////*/

        console2.log("Deploying Bootstrap...");

        Bootstrap Bootstrap = new Bootstrap();

        console2.log("Bootstrap deployed at address", address(Bootstrap));
        console2.log("Finished deployment sequence!");

        vm.stopBroadcast();
    }
}
