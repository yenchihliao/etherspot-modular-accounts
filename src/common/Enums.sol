// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

// SessionKeyValidator
enum ComparisonRule {
    LESS_THAN,
    LESS_THAN_OR_EQUAL,
    EQUAL,
    GREATER_THAN_OR_EQUAL,
    GREATER_THAN,
    NOT_EQUAL
}

// HookMultiplexer
enum HookType {
    GLOBAL,
    DELEGATECALL,
    VALUE,
    SIG,
    TARGET_SIG
}
