// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IPoolManager} from "./IPoolManager.sol";

/// @title Interface for ImmutableState
interface IImmutableState {
    /// @notice The Uniswap v4 PoolManager contract
    function poolManager() external view returns (IPoolManager);
}
