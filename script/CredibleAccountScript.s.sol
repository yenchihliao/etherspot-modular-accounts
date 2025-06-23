// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {HookMultiPlexer} from "../src/modules/hooks/HookMultiPlexer.sol";
import {CredibleAccountModule} from "../src/modules/validators/CredibleAccountModule.sol";
import {ResourceLockValidator} from "../src/modules/validators/ResourceLockValidator.sol";

contract CredibleAccountSetupScript is Script {
    bytes32 public immutable SALT = bytes32(abi.encodePacked("ModularEtherspotWallet:Create2:salt"));
    bytes32 public immutable TEST_SALT = bytes32(abi.encodePacked("ModularEtherspotWallet:Create2:test_salt"));
    address public constant DEPLOYER = 0x09FD4F6088f2025427AB1e89257A44747081Ed59;
    address public constant EXPECTED_MULTIPLEXER_ADDRESS = 0x0000000000000000000000000000000000000000;
    address public constant EXPECTED_CA_MODULE_ADDRESS = 0x0000000000000000000000000000000000000000;
    address public constant EXPECTED_RESOURCE_LOCK_VALIDATOR_ADDRESS = 0x0000000000000000000000000000000000000000;
    address public constant DEPLOYED_HOOK_MULTIPLEXER_ADDRESS = 0xDcA918dd23456d321282DF9507F6C09A50522136;

    function run() external {
        HookMultiPlexer hookMultiPlexer;
        CredibleAccountModule credibleAccountModule;
        ResourceLockValidator resourceLockValidator;
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        /*//////////////////////////////////////////////////////////////
                            Starting Deployment
        //////////////////////////////////////////////////////////////*/

        console2.log("Starting deployment sequence...");

        /*//////////////////////////////////////////////////////////////
                            Deploy HookMultiPlexer
        //////////////////////////////////////////////////////////////*/

        // console2.log("Deploying HookMultiPlexer...");
        // // if (EXPECTED_MULTIPLEXER_ADDRESS.code.length == 0) {
        // hookMultiPlexer = new HookMultiPlexer();
        // // if (address(hookMultiPlexer) != EXPECTED_MULTIPLEXER_ADDRESS) {
        // //     revert("Unexpected HookMultiPlexer address!!!");
        // // } else {
        // console2.log("HookMultiPlexer deployed at address", address(hookMultiPlexer));
        // //     }
        // // } else {
        // //     console2.log("HookMultiPlexer already deployed at address", EXPECTED_MULTIPLEXER_ADDRESS);
        // // }

        /*//////////////////////////////////////////////////////////////
                      Deploy CredibleAccountModule
        //////////////////////////////////////////////////////////////*/

        console2.log("Deploying CredibleAccountModule...");
        // if (EXPECTED_CA_MODULE_ADDRESS.code.length == 0) {
        credibleAccountModule = new CredibleAccountModule{salt: TEST_SALT}(DEPLOYER, DEPLOYED_HOOK_MULTIPLEXER_ADDRESS);
        // if (address(credibleAccountModule) != EXPECTED_CA_MODULE_ADDRESS) {
        //     revert("Unexpected CredibleAccountModule address!!!");
        // } else {
        console2.log("CredibleAccountModule deployed at address", address(credibleAccountModule));
        //     }
        // } else {
        //     console2.log("CredibleAccountModule already deployed at address", EXPECTED_VALIDATOR_ADDRESS);
        // }

        /*//////////////////////////////////////////////////////////////
                        Deploy ResourceLockValidator
        //////////////////////////////////////////////////////////////*/

        // console2.log("Deploying ResourceLockValidator...");
        // // if (EXPECTED_RESOURCE_LOCK_VALIDATOR.code.length == 0) {
        // resourceLockValidator = new ResourceLockValidator{salt: TEST_SALT}();
        // // if (address(resourceLockValidator) != EXPECTED_RESOURCE_LOCK_VALIDATOR) {
        // //     revert("Unexpected ResourceLockValidator address!!!");
        // // } else {
        // console2.log("ResourceLockValidator deployed at address", address(resourceLockValidator));
        // //     }
        // // } else {
        // //     console2.log("ResourceLockValidator already deployed at address", EXPECTED_RESOURCE_LOCK_VALIDATOR);
        // // }

        /*//////////////////////////////////////////////////////////////
                              Finishing Deployment
        //////////////////////////////////////////////////////////////*/
        console2.log("Finished deployment sequence!");

        vm.stopBroadcast();
    }
}
