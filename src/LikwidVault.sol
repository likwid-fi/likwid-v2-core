// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.28;

import {Owned} from "solmate/src/auth/Owned.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {Currency, CurrencyLibrary} from "./types/Currency.sol";
import {PoolKey} from "./types/PoolKey.sol";
import {IHooks} from "./interfaces/IHooks.sol";
import {IPoolManager} from "./interfaces/IPoolManager.sol";
import {IUnlockCallback} from "./interfaces/callback/IUnlockCallback.sol";
import {ERC6909Claims} from "./ERC6909Claims.sol";
import {NoDelegateCall} from "./NoDelegateCall.sol";
import {PoolId} from "./types/PoolId.sol";
import {BalanceDelta, toBalanceDelta, BalanceDeltaLibrary} from "./types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "./types/BeforeSwapDelta.sol";
import {Hooks} from "./libraries/Hooks.sol";
import {CurrencyGuard} from "./libraries/CurrencyGuard.sol";

/// @title Likwid vault
/// @notice Holds the property for all likwid pools
contract LikwidVault is IPoolManager, Owned, NoDelegateCall, ERC6909Claims {
    using SafeCast for *;
    using Hooks for IHooks;
    using CurrencyGuard for Currency;
    using BalanceDeltaLibrary for BalanceDelta;
    using BeforeSwapDeltaLibrary for BeforeSwapDelta;

    error NotImplemented();

    mapping(PoolId id => address) public pools;

    /// transient storage
    bool transient unlocked;
    uint256 transient nonzeroDeltaCount;
    Currency transient syncedCurrency;
    uint256 transient syncedReserves;

    /// @notice This will revert if the contract is locked
    modifier onlyWhenUnlocked() {
        if (!unlocked) revert ManagerLocked();
        _;
    }

    constructor(address initialOwner) Owned(initialOwner) {}

    /// @inheritdoc IPoolManager
    function unlock(bytes calldata data) external override returns (bytes memory result) {
        if (unlocked) revert AlreadyUnlocked();

        unlocked = true;

        // the caller does everything in this callback, including paying what they owe via calls to settle
        result = IUnlockCallback(msg.sender).unlockCallback(data);

        if (nonzeroDeltaCount != 0) revert CurrencyNotSettled();
        unlocked = false;
    }

    /// @inheritdoc IPoolManager
    function initialize(PoolKey memory key, uint160 sqrtPriceX96) external noDelegateCall returns (int24 tick) {
        if (key.currency0 >= key.currency1) {
            revert CurrenciesOutOfOrderOrEqual(Currency.unwrap(key.currency0), Currency.unwrap(key.currency1));
        }
        if (!key.hooks.isValidHookAddress()) revert Hooks.HookAddressNotValid(address(key.hooks));

        key.hooks.beforeInitialize(msg.sender, key, sqrtPriceX96);
        // likwid pools are initialized with tick = 1
        tick = 1;
        PoolId id = key.toId();
        if (pools[id] != address(0)) {
            revert PoolAlreadyInitialized(id);
        }
        pools[id] = msg.sender;
        emit Initialize(id, key.currency0, key.currency1, key.fee, key.tickSpacing, key.hooks, sqrtPriceX96, tick);
    }

    /// @inheritdoc IPoolManager
    function swap(PoolKey memory key, IPoolManager.SwapParams memory params, bytes calldata hookData)
        external
        onlyWhenUnlocked
        noDelegateCall
        returns (BalanceDelta swapDelta)
    {
        if (params.amountSpecified == 0) revert SwapAmountCannotBeZero();
        PoolId id = key.toId();
        if (pools[id] == address(0)) revert PoolNotInitialized();

        BeforeSwapDelta beforeSwapDelta;
        (, beforeSwapDelta,) = key.hooks.beforeSwap(msg.sender, key, params, hookData);

        int128 hookDeltaSpecified = beforeSwapDelta.getSpecifiedDelta();
        int128 hookDeltaUnspecified = beforeSwapDelta.getUnspecifiedDelta();

        BalanceDelta hookDelta;
        if (hookDeltaUnspecified != 0 || hookDeltaSpecified != 0) {
            hookDelta = (params.amountSpecified < 0 == params.zeroForOne)
                ? toBalanceDelta(hookDeltaSpecified, hookDeltaUnspecified)
                : toBalanceDelta(hookDeltaUnspecified, hookDeltaSpecified);

            swapDelta = swapDelta - hookDelta;
        }

        _appendPoolBalanceDelta(key, msg.sender, swapDelta);
    }

    /// @inheritdoc IPoolManager
    function modifyLiquidity(PoolKey memory, IPoolManager.ModifyLiquidityParams memory, bytes calldata)
        external
        view
        onlyWhenUnlocked
        noDelegateCall
        returns (BalanceDelta, BalanceDelta)
    {
        revert NotImplemented();
    }

    /// @inheritdoc IPoolManager
    function donate(PoolKey memory, uint256, uint256, bytes calldata)
        external
        view
        onlyWhenUnlocked
        noDelegateCall
        returns (BalanceDelta)
    {
        revert NotImplemented();
    }

    /// @inheritdoc IPoolManager
    function updateDynamicLPFee(PoolKey memory, uint24) external pure {
        revert NotImplemented();
    }

    /// @inheritdoc IPoolManager
    function sync(Currency currency) external {
        // address(0) is used for the native currency
        if (currency.isAddressZero()) {
            syncedCurrency = CurrencyLibrary.ADDRESS_ZERO;
        } else {
            uint256 balance = currency.balanceOfSelf();
            syncedCurrency = currency;
            syncedReserves = balance;
        }
    }

    /// @inheritdoc IPoolManager
    function take(Currency currency, address to, uint256 amount) external onlyWhenUnlocked {
        unchecked {
            // negation must be safe as amount is not negative
            _appendDelta(currency, msg.sender, -amount.toInt256());
            currency.transfer(to, amount);
        }
    }

    /// @inheritdoc IPoolManager
    function settle() external payable onlyWhenUnlocked returns (uint256) {
        return _settle(msg.sender);
    }

    /// @inheritdoc IPoolManager
    function settleFor(address recipient) external payable onlyWhenUnlocked returns (uint256) {
        return _settle(recipient);
    }

    /// @inheritdoc IPoolManager
    function clear(Currency currency, uint256 amount) external onlyWhenUnlocked {
        int256 current = currency.currentDelta(msg.sender);
        int256 amountDelta = amount.toInt256();
        if (amountDelta != current) revert MustClearExactPositiveDelta();
        // negation must be safe as amountDelta is positive
        unchecked {
            _appendDelta(currency, msg.sender, -(amountDelta));
        }
    }

    /// @inheritdoc IPoolManager
    function mint(address to, uint256 id, uint256 amount) external onlyWhenUnlocked {
        unchecked {
            Currency currency = CurrencyLibrary.fromId(id);
            // negation must be safe as amount is not negative
            _appendDelta(currency, msg.sender, -amount.toInt256());
            _mint(to, currency.toId(), amount);
        }
    }

    /// @inheritdoc IPoolManager
    function burn(address from, uint256 id, uint256 amount) external onlyWhenUnlocked {
        Currency currency = CurrencyLibrary.fromId(id);
        _appendDelta(currency, msg.sender, amount.toInt256());
        _burnFrom(from, currency.toId(), amount);
    }

    function _settle(address recipient) internal returns (uint256 paid) {
        Currency currency = syncedCurrency;

        if (currency.isAddressZero()) {
            paid = msg.value;
        } else {
            if (msg.value > 0) revert NonzeroNativeValue();
            uint256 reservesBefore = syncedReserves;
            uint256 reservesNow = currency.balanceOfSelf();
            paid = reservesNow - reservesBefore;
            syncedCurrency = CurrencyLibrary.ADDRESS_ZERO; // reset synced currency
        }

        _appendDelta(currency, recipient, paid.toInt256());
    }

    /// @notice Appends a balance delta in a currency for a target address
    function _appendDelta(Currency currency, address target, int256 delta) internal {
        if (delta == 0) return;

        (int256 previous, int256 current) = currency.appendDelta(target, delta.toInt128());

        if (current == 0) {
            nonzeroDeltaCount -= 1;
        } else if (previous == 0) {
            nonzeroDeltaCount += 1;
        }
    }

    /// @notice Appends the deltas of 2 currencies to a target address
    function _appendPoolBalanceDelta(PoolKey memory key, address target, BalanceDelta delta) internal {
        _appendDelta(key.currency0, target, delta.amount0());
        _appendDelta(key.currency1, target, delta.amount1());
    }
}
