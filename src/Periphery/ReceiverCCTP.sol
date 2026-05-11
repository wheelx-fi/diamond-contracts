// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

import { IERC20, SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { LibSwap } from "../Libraries/LibSwap.sol";
import { ILiFi } from "../Interfaces/ILiFi.sol";
import { IExecutor } from "../Interfaces/IExecutor.sol";
import { WithdrawablePeriphery } from "../Helpers/WithdrawablePeriphery.sol";
// solhint-disable-next-line no-unused-import
import { InvalidConfig, InvalidReceiver, UnAuthorized } from "../Errors/GenericErrors.sol";

/// @title IMessageReceiver
/// @notice Interface for Circle's CCTP v2 Message Receiver (IMessageReceiver)
/// @dev The mintRecipient on the destination chain must implement this interface
///      to receive hook data when using depositForBurnWithHook on the source chain.
///      See: https://github.com/circlefin/evm-cctp-contracts
interface IMessageReceiver {
    /// @notice Handles a received message from the MessageTransmitter
    /// @param messageId The unique identifier for the message
    /// @param sourceMessageSender The address that initiated the message on the source chain (as bytes)
    /// @param hookData The hook data appended to the burn message on the source chain
    /// @return magicValue The selector of handleReceiveMessage (bytes4) to acknowledge receipt
    function handleReceiveMessage(
        bytes32 messageId,
        bytes calldata sourceMessageSender,
        bytes calldata hookData
    ) external returns (bytes4);
}

/// @title ReceiverCCTP
/// @author LI.FI (https://li.fi)
/// @notice Arbitrary execution contract used for cross-chain swaps and message passing via CCTP v2
/// @dev Handles handleReceiveMessage callbacks from Circle's MessageTransmitterV2 when
///      USDC is bridged via CCTP with a composed message (hookData).
///      This contract receives the minted USDC and executes swap(s) before delivering
///      the output tokens to the final receiver.
///
///      Flow:
///      1. Source chain: PolymerCCTPFacet calls depositForBurnWithHook with mintRecipient = this contract
///         and hookData = abi.encode(transactionId, swapData, receiver)
///      2. Destination chain: MessageTransmitter mints USDC to this contract, then calls
///         handleReceiveMessage with the hook data
///      3. This contract decodes the hook data, approves USDC to Executor, executes swaps,
///         and sends the output tokens to the final receiver
///
/// @custom:version 1.0.0
contract ReceiverCCTP is ILiFi, WithdrawablePeriphery, IMessageReceiver {
    using SafeERC20 for IERC20;

    /// Storage ///

    /// @notice The Executor contract that performs the actual swaps
    // solhint-disable-next-line immutable-vars-naming
    IExecutor public immutable executor;

    /// @notice Circle's CCTP v2 MessageTransmitter address on this chain
    // solhint-disable-next-line immutable-vars-naming
    address public immutable messageTransmitter;

    /// @notice The USDC token address on this chain
    // solhint-disable-next-line immutable-vars-naming
    address public immutable usdc;

    /// @notice The amount of gas to reserve for the recovery path (sending USDC directly to receiver)
    // solhint-disable-next-line immutable-vars-naming
    uint256 public immutable recoverGas;

    /// @dev The magic value returned by handleReceiveMessage to indicate success
    ///      Equals this.handleReceiveMessage.selector
    bytes4 private constant HANDLE_RECEIVE_MESSAGE_MAGIC = 0xce253d94;

    /// Modifiers ///

    /// @notice Ensures only the authorized MessageTransmitter can call the function
    modifier onlyMessageTransmitter() {
        if (msg.sender != messageTransmitter) {
            revert UnAuthorized();
        }
        _;
    }

    /// Constructor ///

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
        messageTransmitter = _messageTransmitter;
        usdc = _usdc;
        recoverGas = _recoverGas;
    }

    /// External Methods ///

    /// @notice Handles a received CCTP v2 message with hook data from the MessageTransmitter
    /// @dev Only callable by the authorized MessageTransmitter contract.
    ///      USDC is already minted to this contract before this callback is invoked
    ///      (MessageTransmitter mints first, then calls handleReceiveMessage).
    ///
    ///      The hook data is expected to be ABI-encoded as:
    ///      (bytes32 transactionId, LibSwap.SwapData[] swapData, address receiver)
    ///
    /// @param * (unused) messageId The unique identifier for the message
    /// @param * (unused) sourceMessageSender The address that initiated the message on the source chain
    /// @param hookData The hook data containing swap execution details
    /// @return magicValue The selector of handleReceiveMessage to acknowledge receipt
    function handleReceiveMessage(
        bytes32, // messageId (not used)
        bytes calldata, // sourceMessageSender (not used)
        bytes calldata hookData
    ) external onlyMessageTransmitter returns (bytes4) {
        // Decode the hook data: (transactionId, swapData[], receiver)
        (bytes32 transactionId, LibSwap.SwapData[] memory swapData, address receiver) = abi
            .decode(hookData, (bytes32, LibSwap.SwapData[], address));

        if (receiver == address(0)) {
            revert InvalidReceiver();
        }

        // Get the amount of USDC minted to this contract by the MessageTransmitter
        uint256 amount = IERC20(usdc).balanceOf(address(this));

        if (amount == 0) {
            // No USDC was minted — nothing to swap or transfer
            return HANDLE_RECEIVE_MESSAGE_MAGIC;
        }

        // Execute swap(s) and complete the bridge transfer
        _swapAndCompleteBridgeTokens(transactionId, swapData, usdc, payable(receiver), amount);

        return HANDLE_RECEIVE_MESSAGE_MAGIC;
    }

    /// Private Methods ///

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
