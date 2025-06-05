// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {HookMultiPlexer} from "../src/modules/hooks/HookMultiPlexer.sol";
import {CredibleAccountModule} from "../src/modules/validators/CredibleAccountModule.sol";

/**
 * @author Etherspot.
 * @title HookMultiPlexerScript.
 * @dev Deployment script for HookMultiPlexer and CAM.
 */
contract HookMultiPlexerScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        console2.log("Starting deployment sequence...");

        /*//////////////////////////////////////////////////////////////
                              Deploy HookMultiPlexer
        //////////////////////////////////////////////////////////////*/

        console2.log("Deploying HookMultiPlexer...");

        HookMultiPlexer hmp = new HookMultiPlexer();

        console2.log("HookMultiPlexer deployed at address", address(hmp));

        /*//////////////////////////////////////////////////////////////
                          Deploy CredibleAccountModule
        //////////////////////////////////////////////////////////////*/

        console2.log("Deploying CredibleAccountModule...");

        CredibleAccountModule cam = new CredibleAccountModule(address(hmp));

        console2.log("CredibleAccountModule deployed at address", address(cam));
        console2.log("Finished deployment sequence!");

        vm.stopBroadcast();
    }
}
