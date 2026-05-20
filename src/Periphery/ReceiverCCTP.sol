// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

import { IERC20, SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { LibSwap } from "../Libraries/LibSwap.sol";
import { ILiFi } from "../Interfaces/ILiFi.sol";
import { IExecutor } from "../Interfaces/IExecutor.sol";
import { WithdrawablePeriphery } from "../Helpers/WithdrawablePeriphery.sol";
// solhint-disable-next-line no-unused-import
import { InvalidConfig, InvalidReceiver, UnAuthorized } from "../Errors/GenericErrors.sol";

/// @title IMessageTransmitterV2
/// @notice Minimal interface for Circle's CCTP v2 MessageTransmitter.receiveMessage
/// @dev See: https://github.com/circlefin/evm-cctp-contracts/blob/master/src/v2/MessageTransmitterV2.sol
interface IMessageTransmitterV2 {
    /// @notice Receive a CCTP message. Validates attestation, mints tokens, and
    ///         routes the message body to the recipient (TokenMessengerV2) via
    ///         IMessageHandlerV2.handleReceiveFinalizedMessage.
    /// @param message The raw CCTP message bytes
    /// @param attestation Concatenated 65-byte signatures
    /// @return success True if successful
    function receiveMessage(
        bytes calldata message,
        bytes calldata attestation
    ) external returns (bool success);
}

/// @title ReceiverCCTP
/// @author LI.FI (https://li.fi)
/// @notice Arbitrary execution contract for cross-chain swaps via CCTP v2.
/// @dev Uses the "relayer-calls-receiver-directly" pattern (inspired by Across Protocol's
///      SponsoredCCTPDstPeriphery) rather than the IMessageReceiver callback pattern.
///
///      Why this pattern:
///      - CCTP v2's MessageTransmitterV2 routes messages to the TokenMessengerV2 (the outer
///        message `recipient`), which then mints tokens to the `mintRecipient`. Unlike CCTP v1,
///        there is NO handleReceiveMessage callback to the mintRecipient.
///      - Having the relayer call this contract directly gives us full control over the
///        post-mint execution flow — balance verification, message parsing, and error handling.
///
///      Flow:
///      1. Source chain: PolymerCCTPFacet calls TokenMessengerV2.depositForBurnWithHook with
///         mintRecipient = this contract and hookData = abi.encode(transactionId, swapData, receiver)
///      2. Destination: Relayer calls this.receiveMessage(message, attestation)
///      3. This contract calls messageTransmitter.receiveMessage() which triggers the v2 flow:
///         MessageTransmitterV2 -> TokenMessengerV2.handleReceiveFinalizedMessage() -> mints USDC
///         to this contract
///      4. This contract parses the raw CCTP message to extract hookData (at a fixed offset in the
///         BurnMessageV2 payload, since hookData is appended via abi.encodePacked)
///      5. Hook data is decoded as (transactionId, swapData[], receiver) and swaps are executed
///         via the Executor
///
/// @custom:version 2.0.0
contract ReceiverCCTP is ILiFi, WithdrawablePeriphery {
    using SafeERC20 for IERC20;

    // ─────────────────────────────────────────────────────────────────────
    //  CCTP v2 Message Layout Constants
    // ─────────────────────────────────────────────────────────────────────
    //
    //  Outer message (MessageV2):
    //    Offset  Size  Field
    //    ──────  ────  ───────────────────────────
    //    0       4     version (uint32)
    //    4       4     sourceDomain (uint32)
    //    8       4     destinationDomain (uint32)
    //    12      32    nonce (bytes32)
    //    44      32    sender (bytes32)
    //    76      32    recipient (bytes32)  ← TokenMessengerV2 address
    //    108     32    destinationCaller (bytes32)
    //    140     4     minFinalityThreshold (uint32)
    //    144     4     finalityThresholdExecuted (uint32)
    //    148     dyn   messageBody (bytes)   ← BurnMessageV2 begins here
    //
    //  Burn message body (BurnMessageV2, within messageBody):
    //    Offset  Size  Field
    //    ──────  ────  ───────────────────────────
    //    0       4     version (uint32)
    //    4       32    burnToken (bytes32)
    //    36      32    mintRecipient (bytes32)  ← this contract
    //    68      32    amount (uint256)
    //    100     32    messageSender (bytes32)
    //    132     32    maxFee (uint256)
    //    164     32    feeExecuted (uint256)
    //    196     32    expirationBlock (uint256)
    //    228     dyn   hookData (raw bytes, NO length prefix — appended via abi.encodePacked)
    //
    //  Reference:
    //    https://github.com/circlefin/evm-cctp-contracts/blob/master/src/messages/v2/MessageV2.sol
    //    https://github.com/circlefin/evm-cctp-contracts/blob/master/src/messages/v2/BurnMessageV2.sol

    /// @dev Offset of the messageBody in the outer CCTP v2 message
    uint256 private constant MESSAGE_BODY_OFFSET = 148;

    /// @dev Offset of hookData in the BurnMessageV2 body (after all fixed fields)
    uint256 private constant HOOK_DATA_OFFSET = 228;

    // ─────────────────────────────────────────────────────────────────────
    //  Storage
    // ─────────────────────────────────────────────────────────────────────

    /// @notice The Executor contract that performs the actual swaps
    // solhint-disable-next-line immutable-vars-naming
    IExecutor public immutable executor;

    /// @notice Circle's CCTP v2 MessageTransmitter on this chain
    // solhint-disable-next-line immutable-vars-naming
    IMessageTransmitterV2 public immutable messageTransmitter;

    /// @notice The USDC token address on this chain
    // solhint-disable-next-line immutable-vars-naming
    address public immutable usdc;

    /// @notice The amount of gas to reserve for the recovery path (sending USDC directly to receiver)
    // solhint-disable-next-line immutable-vars-naming
    uint256 public immutable recoverGas;

    // ─────────────────────────────────────────────────────────────────────
    //  Constructor
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Initializes the ReceiverCCTP contract
    /// @param _owner Address that can withdraw funds from this contract
    /// @param _executor Address of the Executor contract that performs swaps
    /// @param _messageTransmitter Address of Circle's CCTP v2 MessageTransmitter on this chain
    /// @param _usdc Address of the USDC token on this chain
    /// @param _recoverGas Gas to reserve for the recovery path (sending tokens directly to receiver)
    constructor(
        address _owner,
        address _executor,
        address _messageTransmitter,
        address _usdc,
        uint256 _recoverGas
    ) WithdrawablePeriphery(_owner) {
        if (
            _executor == address(0) ||
            _messageTransmitter == address(0) ||
            _usdc == address(0)
        ) {
            revert InvalidConfig();
        }

        executor = IExecutor(_executor);
        messageTransmitter = IMessageTransmitterV2(_messageTransmitter);
        usdc = _usdc;
        recoverGas = _recoverGas;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  External — Relayer Entrypoint
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Called by any relayer with the CCTP message and attestation.
    ///         Triggers the CCTP v2 mint flow (MessageTransmitterV2 → TokenMessengerV2 →
    ///         mints USDC to this contract), then extracts hook data from the raw message
    ///         bytes and executes swaps.
    /// @dev The source chain must have called depositForBurnWithHook with:
    ///      - mintRecipient = address(this)
    ///      - destinationCaller = address(this) or bytes32(0)
    ///      - hookData = abi.encode(transactionId, swapData[], receiver)
    /// @param message The raw CCTP message bytes
    /// @param attestation The attestation (concatenated 65-byte signatures)
    function receiveMessage(
        bytes calldata message,
        bytes calldata attestation
    ) external {
        // ── Step 1: Trigger the CCTP v2 mint flow ──
        // MessageTransmitterV2 validates the attestation and message, then calls
        // IMessageHandlerV2.handleReceiveFinalizedMessage on the outer message's
        // `recipient` (the TokenMessengerV2). TokenMessengerV2 parses the BurnMessageV2
        // and mints USDC to the `mintRecipient` — this contract.
        // If destinationCaller in the message is non-zero, it must equal this contract's address
        // (since msg.sender in the MessageTransmitterV2 call is this contract).
        bool success = messageTransmitter.receiveMessage(message, attestation);
        if (!success) {
            revert("CCTP: receiveMessage failed");
        }

        // ── Step 2: Verify USDC was minted ──
        uint256 amount = IERC20(usdc).balanceOf(address(this));
        if (amount == 0) {
            revert("CCTP: zero amount minted");
        }

        // ── Step 3: Extract and decode hook data from the raw message ──
        // Hook data is appended at a fixed offset in the BurnMessageV2 payload.
        // It is stored as raw bytes (via abi.encodePacked), so no length prefix — we can
        // decode it directly.
        bytes calldata hookData = message[MESSAGE_BODY_OFFSET + HOOK_DATA_OFFSET:];

        (bytes32 transactionId, LibSwap.SwapData[] memory swapData, address receiver) = abi
            .decode(hookData, (bytes32, LibSwap.SwapData[], address));

        if (receiver == address(0)) {
            revert InvalidReceiver();
        }

        // ── Step 4: Execute swaps and complete the bridge transfer ──
        _swapAndCompleteBridgeTokens(transactionId, swapData, usdc, payable(receiver), amount);
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Events
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Emitted when the emergency receive path is taken
    /// @param transactionId The transaction ID from the hook data (zero if unparseable)
    /// @param receiver The final recipient the USDC was sent to (zero if unparseable)
    /// @param amount The amount of USDC minted and forwarded
    event ReceiverCCTPEmergencyReceive(
        bytes32 indexed transactionId,
        address indexed receiver,
        uint256 amount
    );

    // ─────────────────────────────────────────────────────────────────────
    //  External — Owner-Only Recovery
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Emergency handler for cases where the normal swap/execute flow cannot
    ///         proceed (e.g., Executor is broken, DEX is blacklisted, etc.).
    /// @dev Calls MessageTransmitterV2.receiveMessage() to mint USDC, then sends the
    ///      minted USDC directly to the intended receiver extracted from the hook data,
    ///      bypassing all swap logic. If hook data cannot be parsed, funds stay in this
    ///      contract and can be recovered via withdrawToken().
    /// @param message The raw CCTP message bytes
    /// @param attestation The attestation (concatenated 65-byte signatures)
    function emergencyReceiveMessage(
        bytes calldata message,
        bytes calldata attestation
    ) external onlyOwner {
        uint256 balanceBefore = IERC20(usdc).balanceOf(address(this));

        // Trigger the CCTP v2 mint flow. If receiveMessage fails (e.g. bad attestation,
        // already-used nonce).
        bool success = messageTransmitter.receiveMessage(message, attestation);
        if (!success) {
            revert("CCTP: receiveMessage failed");
        }

        uint256 balanceAfter = IERC20(usdc).balanceOf(address(this));
        uint256 mintedAmount = balanceAfter - balanceBefore;

        if (mintedAmount == 0) {
            return;
        }

        // Try to extract the intended receiver from the hook data.
        // Use try-catch since a malformed message could cause abi.decode to revert.
        try this.decodeHookData(message) returns (bytes32 transactionId, address receiver) {
            if (receiver != address(0) && receiver != address(this)) {
                IERC20(usdc).safeTransfer(receiver, mintedAmount);

                emit ReceiverCCTPEmergencyReceive(transactionId, receiver, mintedAmount);
                return;
            }
        } catch {
            // Malformed hook data — funds remain in this contract.
            // Owner can recover via withdrawToken().
        }

        // If we reach here, the receiver was invalid or hook data was unparseable.
        // Funds stay in this contract; owner should use withdrawToken().
        emit ReceiverCCTPEmergencyReceive(bytes32(0), address(0), mintedAmount);
    }

    /// @notice Public read-only wrapper that decodes hook data from a CCTP message.
    ///         Exists to enable safe try-catch in emergencyReceiveMessage without inline assembly.
    /// @param message The raw CCTP message bytes
    /// @return transactionId The transaction ID extracted from the hook data
    /// @return receiver The receiver address extracted from the hook data
    function decodeHookData(
        bytes calldata message
    ) external pure returns (bytes32 transactionId, address receiver) {
        bytes calldata hookData = message[MESSAGE_BODY_OFFSET + HOOK_DATA_OFFSET:];
        (transactionId, , receiver) = abi.decode(hookData, (bytes32, LibSwap.SwapData[], address));
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Private — Swap & Recovery
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Performs a swap before completing a cross-chain transaction
    /// @param _transactionId The transaction id associated with the operation
    /// @param _swapData Array of data needed for swaps
    /// @param assetId Address of the token received from the source chain (USDC)
    /// @param receiver Address that will receive tokens in the end
    /// @param amount Amount of tokens available for swapping
    /// @dev If gas is too low to execute swaps, tokens are sent directly to the receiver.
    ///      If the swap fails, the original USDC tokens are sent directly to the receiver.
    ///      Approvals are reset to 0 after the operation completes.
    function _swapAndCompleteBridgeTokens(
        bytes32 _transactionId,
        LibSwap.SwapData[] memory _swapData,
        address assetId,
        address payable receiver,
        uint256 amount
    ) private {
        uint256 cacheGasLeft = gasleft();

        // USDC is an ERC20 token, never native
        IERC20 token = IERC20(assetId);
        token.safeApprove(address(executor), 0);

        if (cacheGasLeft < recoverGas) {
            // Not enough gas left to execute calls — send USDC directly to receiver
            token.safeTransfer(receiver, amount);

            emit LiFiTransferRecovered(_transactionId, assetId, receiver, amount, block.timestamp);
            return;
        }

        // Enough gas left — attempt to execute swaps
        token.safeIncreaseAllowance(address(executor), amount);
        try
            executor.swapAndCompleteBridgeTokens{ gas: cacheGasLeft - recoverGas }(
                _transactionId,
                _swapData,
                assetId,
                receiver
            )
        {
            // Swaps succeeded — LiFiTransferCompleted is emitted by Executor
            // No additional action needed
        } catch {
            // Swap failed — send the original USDC directly to receiver
            token.safeTransfer(receiver, amount);

            emit LiFiTransferRecovered(_transactionId, assetId, receiver, amount, block.timestamp);
        }

        // Reset approval
        token.safeApprove(address(executor), 0);
    }

    /// @notice Receive native asset directly
    /// @dev Allows the contract to receive native assets (e.g., from refunds)
    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}
}
