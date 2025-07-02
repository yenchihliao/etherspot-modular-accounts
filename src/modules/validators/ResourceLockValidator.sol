// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ECDSA} from "solady/src/utils/ECDSA.sol";
import {MerkleProofLib} from "solady/src/utils/MerkleProofLib.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {PackedUserOperation} from "ERC4337/interfaces/PackedUserOperation.sol";
import "ERC7579/interfaces/IERC7579Account.sol";
import "ERC7579/libs/ModeLib.sol";
import "ERC7579/libs/ExecutionLib.sol";
import {IResourceLockValidator} from "../../interfaces/IResourceLockValidator.sol";
import {ICredibleAccountModule} from "../../interfaces/ICredibleAccountModule.sol";
import {ResourceLock, TokenData} from "../../common/Structs.sol";
import {
    MODULE_TYPE_VALIDATOR,
    SIG_VALIDATION_SUCCESS,
    SIG_VALIDATION_FAILED,
    ERC1271_MAGIC_VALUE,
    ERC1271_INVALID
} from "../../common/Constants.sol";

contract ResourceLockValidator is IResourceLockValidator {
    using ECDSA for bytes32;
    using ModeLib for ModeCode;
    using ExecutionLib for bytes;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/

    address public immutable owner;
    ICredibleAccountModule public credibleAccountModule;

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct ValidatorStorage {
        address owner;
        bool enabled;
    }

    /*//////////////////////////////////////////////////////////////
                               MAPPINGS
    //////////////////////////////////////////////////////////////*/

    mapping(address => ValidatorStorage) public validatorStorage;
    mapping(address wallet => EnumerableSet.Bytes32Set) private consumedBidHashes;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error RLV_AlreadyInstalled(address scw, address eoa);
    error RLV_NotInstalled(address scw);
    error RLV_InvalidOwner();
    error RLV_InvalidCredibleAccountModule();
    error RLV_InvalidDataLength();
    error RLV_ResourceLockHashNotInProof();
    error RLV_InvalidTarget(address target);
    error RLV_InvalidSelector(bytes4 selector);
    error RLV_NonZeroValue(uint256 value);
    error RLV_InvalidCallType();
    error RLV_InvalidBatchLength(uint256 batchLength);
    error RLV_BidHashAlreadyConsumed(bytes32 bidHash);
    error RLV_InvalidUserOpSender();

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        if (msg.sender != owner) revert RLV_InvalidOwner();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    // TODO: Test credible account module address revert
    constructor(address _owner, address _credibleAccountModule) {
        if (_owner == address(0)) {
            revert RLV_InvalidOwner();
        }
        if (_credibleAccountModule == address(0)) {
            revert RLV_InvalidCredibleAccountModule();
        }
        owner = _owner;
        credibleAccountModule = ICredibleAccountModule(_credibleAccountModule);
    }

    /*//////////////////////////////////////////////////////////////
                      PUBLIC/EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function onInstall(bytes calldata _data) external override {
        if (_data.length < 20) revert RLV_InvalidDataLength();
        address wallet = address(bytes20(_data[_data.length - 20:]));
        if (validatorStorage[msg.sender].enabled) {
            revert RLV_AlreadyInstalled(msg.sender, validatorStorage[msg.sender].owner);
        }
        validatorStorage[msg.sender].owner = wallet;
        validatorStorage[msg.sender].enabled = true;
        emit RLV_ValidatorEnabled(msg.sender, wallet);
    }

    function onUninstall(bytes calldata) external override {
        if (!_isInitialized(msg.sender)) revert RLV_NotInstalled(msg.sender);
        delete consumedBidHashes[msg.sender];
        delete validatorStorage[msg.sender];
        emit RLV_ValidatorDisabled(msg.sender);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        override
        returns (uint256)
    {
        bytes calldata signature = userOp.signature;
        address walletOwner = validatorStorage[msg.sender].owner;
        // TODO: Need to check this validation on live network via bundler
        if (msg.sender != userOp.sender) {
            revert RLV_InvalidUserOpSender();
        }
        // NOTE: check redundant code with auditor
        // Standard signature length - no proof packing
        // if (signature.length == 65) {
        //     // standard ECDSA recover
        //     if (walletOwner == ECDSA.recover(userOpHash, signature)) {
        //         return SIG_VALIDATION_SUCCESS;
        //     }
        //     bytes32 sigHash = ECDSA.toEthSignedMessageHash(userOpHash);
        //     address recoveredSigner = ECDSA.recover(sigHash, signature);
        //     if (walletOwner != recoveredSigner) return SIG_VALIDATION_FAILED;
        //     return SIG_VALIDATION_SUCCESS;
        // }
        // or if signature.length >= 65 (standard signature length + proof packing)
        ResourceLock memory rl = _getResourceLock(userOp.callData);
        // Nonce validation
        bytes memory ecdsaSignature = signature[0:65];
        bytes32 root = bytes32(signature[65:97]); // 32 bytes
        bytes32[] memory proof;
        if (signature.length > 97) {
            // Calculate how many proof elements we have
            uint256 proofCount = (signature.length - 97) / 32;
            // Create an array of the right size
            proof = new bytes32[](proofCount);
            // Extract each proof element
            for (uint256 i; i < proofCount; ++i) {
                uint256 startPos = 97 + (i * 32);
                proof[i] = bytes32(signature[startPos:startPos + 32]);
            }
        } else {
            // Empty proof
            proof = new bytes32[](0);
        }
        if (!MerkleProofLib.verify(proof, root, _buildResourceLockHash(rl))) {
            revert RLV_ResourceLockHashNotInProof();
        }
        if (consumedBidHashes[userOp.sender].contains(rl.bidHash)) {
            revert RLV_BidHashAlreadyConsumed(rl.bidHash);
        }
        // check proof is signed
        if (walletOwner == ECDSA.recover(root, ecdsaSignature)) {
            consumedBidHashes[userOp.sender].add(rl.bidHash);
            return SIG_VALIDATION_SUCCESS;
        }
        bytes32 sigRoot = ECDSA.toEthSignedMessageHash(root);
        address recoveredMSigner = ECDSA.recover(sigRoot, ecdsaSignature);
        if (walletOwner != recoveredMSigner) return SIG_VALIDATION_FAILED;
        consumedBidHashes[userOp.sender].add(rl.bidHash);
        return SIG_VALIDATION_SUCCESS;
    }

    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        address walletOwner = validatorStorage[msg.sender].owner;
        // NOTE: check redundant code with auditor
        // if (signature.length == 65) {
        //     if (walletOwner == ECDSA.recover(hash, signature)) {
        //         return ERC1271_MAGIC_VALUE;
        //     }
        //     bytes32 sigHash = ECDSA.toEthSignedMessageHash(hash);
        //     address recoveredSigner = ECDSA.recover(sigHash, signature);
        //     if (walletOwner != recoveredSigner) return ERC1271_INVALID;
        //     return ERC1271_MAGIC_VALUE;
        // }
        bytes memory ecdsaSig = signature[0:65];
        bytes32 root = bytes32(signature[65:97]);
        bytes32[] memory proof;
        if (signature.length > 97) {
            // Calculate how many proof elements we have
            uint256 proofCount = (signature.length - 97) / 32;
            // Create an array of the right size
            proof = new bytes32[](proofCount);
            // Extract each proof element
            for (uint256 i; i < proofCount; ++i) {
                uint256 startPos = 97 + (i * 32);
                proof[i] = bytes32(signature[startPos:startPos + 32]);
            }
        } else {
            // Empty proof
            proof = new bytes32[](0);
        }
        if (!MerkleProofLib.verify(proof, root, hash)) {
            revert RLV_ResourceLockHashNotInProof();
        }
        // simple ecdsa verification
        if (walletOwner == ECDSA.recover(root, ecdsaSig)) {
            return ERC1271_MAGIC_VALUE;
        }
        bytes32 sigRoot = ECDSA.toEthSignedMessageHash(root);
        address recoveredMSigner = ECDSA.recover(sigRoot, ecdsaSig);
        if (walletOwner != recoveredMSigner) return ERC1271_INVALID;
        return ERC1271_MAGIC_VALUE;
    }

    function getCredibleAccountModule() external view returns (address) {
        return address(credibleAccountModule);
    }

    function setCredibleAccountModule(address _credibleAccountModule) external onlyOwner {
        if (_credibleAccountModule == address(0)) revert RLV_InvalidCredibleAccountModule();
        credibleAccountModule = ICredibleAccountModule(_credibleAccountModule);
    }

    function isConsumedBidHash(address _wallet, bytes32 _bidHash) external view returns (bool) {
        return consumedBidHashes[_wallet].contains(_bidHash);
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    /*//////////////////////////////////////////////////////////////
                      INTERNAL/PRIVATE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _isInitialized(address _smartAccount) internal view returns (bool) {
        return validatorStorage[_smartAccount].enabled;
    }

    function _getArrayInfo(bytes calldata _data) internal pure returns (uint256 offset, uint256 length) {
        offset = uint256(bytes32(_data[292:324]));
        length = uint256(bytes32(_data[100 + offset:132 + offset]));
    }

    function _getSingleTokenData(bytes calldata _data, uint256 _basePos) internal pure returns (TokenData memory) {
        return TokenData({
            token: address(uint160(uint256(bytes32(_data[_basePos:_basePos + 32])))),
            amount: uint256(bytes32(_data[_basePos + 32:_basePos + 64]))
        });
    }

    function _getResourceLock(bytes calldata _callData) internal view returns (ResourceLock memory) {
        if (bytes4(_callData[:4]) == IERC7579Account.execute.selector) {
            (CallType calltype,,,) = ModeLib.decode(ModeCode.wrap(bytes32(_callData[4:36])));
            if (calltype == CALLTYPE_SINGLE) {
                (address target, uint256 value, bytes calldata execData) = ExecutionLib.decodeSingle(_callData[100:]);
                if (target != address(credibleAccountModule)) {
                    revert RLV_InvalidTarget(target);
                }
                if (value != 0) {
                    revert RLV_NonZeroValue(value);
                }
                if (bytes4(execData[:4]) != ICredibleAccountModule.enableSessionKey.selector) {
                    revert RLV_InvalidSelector(bytes4(execData[:4]));
                }
                (uint256 arrayOffset, uint256 arrayLength) = _getArrayInfo(execData);
                TokenData[] memory td = new TokenData[](arrayLength);
                for (uint256 i; i < arrayLength; ++i) {
                    td[i] = _getSingleTokenData(execData, 132 + arrayOffset + (i * 64));
                }
                address scw = address(uint160(uint256(bytes32(execData[132:164]))));
                return ResourceLock({
                    chainId: uint256(bytes32(execData[100:132])),
                    smartWallet: scw,
                    sessionKey: address(uint160(uint256(bytes32(execData[164:196])))),
                    validAfter: uint48(uint256(bytes32(execData[196:228]))),
                    validUntil: uint48(uint256(bytes32(execData[228:260]))),
                    bidHash: bytes32(execData[260:292]),
                    tokenData: td
                });
            } else if (calltype == CALLTYPE_BATCH) {
                // NOTE: If batch call then it will should only contain a single UserOperation
                // so hardcoded values will hold here
                Execution[] calldata batchExecs = ExecutionLib.decodeBatch(_callData[100:]);
                for (uint256 i; i < batchExecs.length; ++i) {
                    if (batchExecs.length != 1) {
                        revert RLV_InvalidBatchLength(batchExecs.length);
                    }
                    if (batchExecs[0].target != address(credibleAccountModule)) {
                        revert RLV_InvalidTarget(batchExecs[0].target);
                    }
                    if (batchExecs[0].value != 0) {
                        revert RLV_NonZeroValue(batchExecs[0].value);
                    }
                    if (bytes4(batchExecs[i].callData[:4]) == bytes4(ICredibleAccountModule.enableSessionKey.selector))
                    {
                        bytes calldata lockData = batchExecs[i].callData;
                        uint256 dataOffset = 68; // Skip function selector + 64 bytes
                        uint256 arrayStart = dataOffset + 256;
                        uint256 tokenDataLength = uint256(bytes32(lockData[arrayStart:arrayStart + 32]));
                        TokenData[] memory td = new TokenData[](tokenDataLength);
                        for (uint256 j; j < tokenDataLength; ++j) {
                            uint256 tokenEntryStart = arrayStart + 32 + (j * 64);
                            address token =
                                address(uint160(uint256(bytes32(lockData[tokenEntryStart:tokenEntryStart + 32]))));
                            uint256 amount = uint256(bytes32(lockData[tokenEntryStart + 32:tokenEntryStart + 64]));
                            td[j] = TokenData({token: token, amount: amount});
                        }
                        return ResourceLock({
                            chainId: uint256(bytes32(lockData[dataOffset + 32:dataOffset + 64])),
                            smartWallet: address(uint160(uint256(bytes32(lockData[dataOffset + 64:dataOffset + 96])))),
                            sessionKey: address(uint160(uint256(bytes32(lockData[dataOffset + 96:dataOffset + 128])))),
                            validAfter: uint48(uint256(bytes32(lockData[dataOffset + 128:dataOffset + 160]))),
                            validUntil: uint48(uint256(bytes32(lockData[dataOffset + 160:dataOffset + 192]))),
                            bidHash: bytes32(lockData[dataOffset + 192:dataOffset + 224]),
                            tokenData: td
                        });
                    }
                    revert RLV_InvalidSelector(bytes4(batchExecs[i].callData[:4]));
                }
            } else {
                revert RLV_InvalidCallType();
            }
        }
    }

    /// @notice Builds a unique hash for a resource lock
    /// @dev Combines chain ID, wallet, session key, validity period, token data, and nonce into a single hash
    /// @param _lock The ResourceLock struct containing all lock parameters
    /// @return bytes32 The unique hash representing this resource lock

    function _buildResourceLockHash(ResourceLock memory _lock) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                _lock.chainId,
                _lock.smartWallet,
                _lock.sessionKey,
                _lock.validAfter,
                _lock.validUntil,
                _lock.bidHash,
                abi.encode(_lock.tokenData)
            )
        );
    }
}
