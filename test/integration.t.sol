// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import {ModularEtherspotWallet} from "../src/wallet/ModularEtherspotWallet.sol";
import {SessionKeyValidator} from "../src/modules/validators/SessionKeyValidator.sol";
import {MultipleOwnerECDSAValidator} from "../src/modules/validators/MultipleOwnerECDSAValidator.sol";
import {CredibleAccountModule} from "../src/modules/validators/CredibleAccountModule.sol";
import {TestERC20} from "../src/test/TestERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Permission, ParamCondition, SessionData, ExecutionValidation} from "../src/common/Structs.sol";
import "../src/common/Constants.sol";

import "ERC7579/interfaces/IERC7579Account.sol";
import {ModeLib} from "../src/ERC7579/libs/ModeLib.sol";
import {ExecutionLib} from "../src/ERC7579/libs/ExecutionLib.sol";
import {PackedUserOperation} from "ERC4337/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "ERC4337/interfaces/IEntryPoint.sol";
import {ECDSA} from "solady/src/utils/ECDSA.sol";
import "ERC7579/test/dependencies/EntryPoint.sol";
import {EntryPointSimulationsPatch} from "ERC7579/test/dependencies/EntryPoint.sol";

contract IntegrationTest is Test {
    struct User {
        address payable pub;
        uint256 priv;
    }

    ModularEtherspotWallet public walletSingleton;
    User public user1;
    User public user2;
    User public user3;
    address payable public beneficiary;
    TestERC20 internal usdt;

    // Multiple validation modules for testing
    SessionKeyValidator internal sessionKeyValidator;
    MultipleOwnerECDSAValidator internal multipleOwnerValidator;
    CredibleAccountModule internal credibleAccountValidator;
    address internal constant ENTRYPOINT_7 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    IEntryPoint internal entrypoint = IEntryPoint(ENTRYPOINT_7);

    // Minimal setup for 7702 delegated contract
    function setUp() public {
        // Prepare contracts
        deployCodeTo("src/ERC7579/test/dependencies/EntryPoint.sol:EntryPointSimulationsPatch", "", ENTRYPOINT_7); // Deploy entrypoint
        walletSingleton = new ModularEtherspotWallet(); // Deploy wallet for 7702

        usdt = new TestERC20();

        // Prepare EOAs first (needed for validatorC constructor)
        user1 = _createUser("EOA1");
        user2 = _createUser("EOA2");
        user3 = _createUser("EOA3");
        beneficiary = payable(makeAddr("Beneficiary"));

        // Deploy multiple validation modules
        sessionKeyValidator = new SessionKeyValidator();
        multipleOwnerValidator = new MultipleOwnerECDSAValidator();
        // credibleAccountValidator = new CredibleAccountModule(user1.pub, address(0));

        // 7702 delegation
        _createSimple7702Wallet(user1);
        _createSimple7702Wallet(user2);

        // PREMISE: Install different validation modules on different users
        // User1: Install SessionKeyValidator and MultipleOwnerECDSAValidator
        vm.prank(user1.pub);
        ModularEtherspotWallet(payable(user1.pub)).installModule(MODULE_TYPE_VALIDATOR, address(sessionKeyValidator), "");
        assertEq(ModularEtherspotWallet(payable(user1.pub)).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(sessionKeyValidator), ""), true);
        vm.prank(user1.pub);
        ModularEtherspotWallet(payable(user1.pub)).installModule(MODULE_TYPE_VALIDATOR, address(multipleOwnerValidator), "");
        assertEq(ModularEtherspotWallet(payable(user1.pub)).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(multipleOwnerValidator), ""), true);

        // User2: Install MultipleOwnerECDSAValidator and CredibleAccountModule
        vm.prank(user2.pub);
        ModularEtherspotWallet(payable(user2.pub)).installModule(MODULE_TYPE_VALIDATOR, address(multipleOwnerValidator), "");
        assertEq(ModularEtherspotWallet(payable(user2.pub)).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(multipleOwnerValidator), ""), true);
        // vm.prank(user2.pub);
        // ModularEtherspotWallet(payable(user2.pub)).installModule(MODULE_TYPE_VALIDATOR, address(credibleAccountValidator), "");
    }

    /// @notice Regular EOA behavior still works (ERC20)
    function test_EOABehavior() public {
        // prebalance user1 and user2
        uint256 user1Balance = user1.pub.balance;
        uint256 user2Balance = user2.pub.balance;
        uint256 user1UsdtBalance = usdt.balanceOf(user1.pub);
        uint256 user2UsdtBalance = usdt.balanceOf(user2.pub);

        // user1 send 1 ether to user2
        vm.prank(user1.pub);
        payable(user2.pub).transfer(1 ether);
        assertEq(user1.pub.balance, user1Balance - 1 ether);
        assertEq(user2.pub.balance, user2Balance + 1 ether);

        // user2 approve user1 to spend 1 usdt
        vm.prank(user2.pub);
        usdt.approve(user1.pub, 1e6);
        assertEq(usdt.allowance(user2.pub, user1.pub), 1e6);

        // user1 transfer user2 usdt to user1
        vm.prank(user1.pub);
        usdt.transferFrom(user2.pub, user1.pub, 1e6);
        assertEq(usdt.balanceOf(user1.pub), user1UsdtBalance + 1e6);
        assertEq(usdt.balanceOf(user2.pub), user2UsdtBalance - 1e6);
        assertEq(usdt.allowance(user2.pub, user1.pub), 0);
    }

    // Permit usdt.approve to grantee_
    function _useSessionKeyValidator(User memory granter_, address grantee_) internal {
        // Set up user3 as a session key with validity period
        SessionData memory _sessionData = SessionData({
            sessionKey: grantee_,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            live: true
        });
        vm.prank(granter_.pub);
        sessionKeyValidator.enableSessionKey(_sessionData, new Permission[](0));

        // Add permission for user3 to call approve on USDT
        Permission memory approvePerm = Permission({
            target: address(usdt),
            selector: IERC20.approve.selector,
            payableLimit: 0,
            uses: 2,
            paramConditions: new ParamCondition[](0)
        });
        vm.prank(granter_.pub);
        sessionKeyValidator.addPermission(grantee_, approvePerm);
    }

    /// @notice Test installing multiple modules and executing operations with session keys
    function test_useMultipleValidators() public {
        User memory user4 = _createUser("EOA4");

        // Test 1: Grant access to user3 using SessionKeyValidator
        _useSessionKeyValidator(user1, user3.pub);

        // Prepare calldata
        bytes memory callData = abi.encodeWithSelector(IERC20.approve.selector, user4.pub, 1e6);
        bytes memory executionData = ExecutionLib.encodeSingle(address(usdt), 0, callData);
        bytes memory opCalldata = abi.encodeCall(
            IERC7579Account.execute,
            (ModeLib.encodeSimpleSingle(), executionData)
        );

        // Prepare execValidations (required by SessionKeyValidator)
        ExecutionValidation[] memory execValidations = new ExecutionValidation[](1);
        execValidations[0] = ExecutionValidation({
            validAfter: uint48(block.timestamp+1 hours),
            validUntil: uint48(block.timestamp + 3 hours)
        });
        vm.warp(block.timestamp+2 hours);

        // Prepare opCall
        PackedUserOperation memory op1 = _createUserOp(address(user1.pub), address(sessionKeyValidator));
        op1.callData = opCalldata;
        bytes32 hash1 = entrypoint.getUserOpHash(op1);
        bytes memory signature1 = _ethSign(hash1, user3);
        op1.signature = abi.encodePacked(signature1, abi.encode(execValidations));

        // Execute the operation with SessionKeyValidator
        _executeUserOp(op1);

        // Check that the approval worked
        assertEq(usdt.allowance(user1.pub, user4.pub), 1e6);

        // Test 2: Grant access to user2 to use MultipleOwnerECDSAValidator
        vm.prank(user1.pub);
        ModularEtherspotWallet(payable(user1.pub)).addOwner(user2.pub);

        // Prepare calldata
        bytes memory callData2 = abi.encodeWithSelector(IERC20.transfer.selector, user2.pub, 1e6);
        bytes memory executionData2 = ExecutionLib.encodeSingle(address(usdt), 0, callData2);
        bytes memory opCalldata2 = abi.encodeCall(
            IERC7579Account.execute,
            (ModeLib.encodeSimpleSingle(), executionData2)
        );

        // Sign with new owner (user2)
        PackedUserOperation memory op2 = _createUserOp(address(user1.pub), address(multipleOwnerValidator));
        op2.callData = opCalldata2;
        bytes32 hash2 = entrypoint.getUserOpHash(op2);
        bytes memory signature2 = _ethSign(hash2, user2);
        op2.signature = signature2;

        // Execute the operation with MultipleOwnerECDSAValidator
        _executeUserOp(op2);

        // Check that the transfer worked
        assertEq(usdt.balanceOf(user2.pub), 100e18 + 1e6); // user2 had 100e18, now has 100e18 + 1e6
    }

    /// @dev 7702 delegate _owner to the scw
    function _createSimple7702Wallet(User memory _user) internal {
        vm.signAndAttachDelegation(address(walletSingleton), _user.priv);
        assertEq(address(walletSingleton), _getDelegationCode(address(_user.pub)));

        // Initialize the wallet with the owner
        ModularEtherspotWallet(payable(_user.pub)).initializeAccount(abi.encode(_user.pub, address(0), ""));

        // Fund the wallet
        vm.deal(address(_user.pub), 100 ether);
    }

    /// @notice create a user with a name and a balance of 100 ether and a balance of 100 USDT
    function _createUser(string memory _name) internal returns (User memory) {
        (address payable addr, uint256 key) = _makePayableAddrAndKey(_name);
        User memory user = User({pub: addr, priv: key});
        vm.deal({account: addr, newBalance: 100 ether});
        deal({token: address(usdt), to: addr, give: 100e18});
        return user;
    }

    /// @notice get the delegation code of the user
    function _getDelegationCode(address _user) internal view returns (address) {
        bytes memory code = _user.code;
        if(code.length == 0) {
            return address(0);
        }
        if(code.length != 23) {
            return address(1);
        }
        uint160 v;
        assembly {
            v := shr(96, mload(add(code, 0x23)))
        }
        return address(v);
    }

    function _makePayableAddrAndKey(string memory name)
        internal
        returns (address payable addr, uint256 privateKey)
    {
        privateKey = uint256(keccak256(abi.encodePacked(name)));
        addr = payable(vm.addr(privateKey));
        vm.label(addr, name);
    }

    /// @notice Create a UserOperation for testing
    function _createUserOp(address _scw, address _validator) internal view returns (PackedUserOperation memory) {
        PackedUserOperation memory op = PackedUserOperation({
            sender: _scw,
            nonce: _getNonce(_scw, _validator),
            initCode: hex"",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(2000000), uint128(2000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        return op;
    }

    /// @notice Get nonce for an account and validator
    function _getNonce(address account, address validator) internal view returns (uint256 nonce) {
        uint192 key = uint192(bytes24(bytes20(validator)));
        nonce = entrypoint.getNonce(address(account), key);
    }

    /// @notice Sign a hash with a user's private key
    function _ethSign(bytes32 hash, User memory _user) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_user.priv, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(r, s, v);
    }

    /// @notice Execute a UserOperation
    function _executeUserOp(PackedUserOperation memory _op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _op;
        entrypoint.handleOps(ops, beneficiary);
    }
}