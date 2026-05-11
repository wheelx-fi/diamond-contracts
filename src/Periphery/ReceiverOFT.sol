// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {LibSwap} from "../Libraries/LibSwap.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {LibAsset} from "../Libraries/LibAsset.sol";
import {OFTComposeMsgCodec} from "../Libraries/OFTComposeMsgCodec.sol";
import {ILiFi} from "../Interfaces/ILiFi.sol";
import {IOFT} from "../Interfaces/IOFT.sol";
import {IExecutor} from "../Interfaces/IExecutor.sol";
import {WithdrawablePeriphery} from "../Helpers/WithdrawablePeriphery.sol";
import {UnAuthorized} from "../Errors/GenericErrors.sol";

/// @title ILayerZeroComposer
/// @notice Interface for the LayerZero V2 composer callback
interface ILayerZeroComposer {
    /// @notice Composes a LayerZero message from an OApp.
    /// @param _from The address initiating the composition, typically the OApp where the lzReceive was called.
    /// @param _guid The unique identifier for the corresponding LayerZero src/dst tx.
    /// @param _message The composed message payload in bytes.
    /// @param _executor The address of the executor for the composed message.
    /// @param _extraData Additional arbitrary data in bytes passed by the entity who executes the lzCompose.
    function lzCompose(
        address _from,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata _extraData
    ) external payable;
}

/// @title ReceiverOFT
/// @author LI.FI (https://li.fi)
/// @notice Arbitrary execution contract used for cross-chain swaps and message passing via LayerZero OFT
/// @dev Handles lzCompose callbacks from LayerZero endpoint for OFT tokens with compose messages.
///      This contract receives the bridged tokens and executes swap(s) before delivering to the final receiver.
///      OFT tokens are self-contained — each OFT contract handles its own bridging and calls
///      the LayerZero endpoint's lzCompose to trigger this contract.
/// @custom:version 1.0.0
contract ReceiverOFT is ILiFi, WithdrawablePeriphery, ILayerZeroComposer {
    using SafeERC20 for IERC20;

    /// Storage ///
    // solhint-disable-next-line immutable-vars-naming
    IExecutor public immutable executor;
    // solhint-disable-next-line immutable-vars-naming
    address public immutable endpointV2;
    // solhint-disable-next-line immutable-vars-naming
    uint256 public immutable recoverGas;

    /// Modifiers ///
    modifier onlyEndpointV2() {
        if (msg.sender != endpointV2) {
            revert UnAuthorized();
        }
        _;
    }

    /// Constructor
    /// @param _owner The owner of this contract (can withdraw tokens)
    /// @param _executor The Executor contract that performs the actual swaps
    /// @param _endpointV2 The LayerZero V2 endpoint address
    /// @param _recoverGas The amount of gas to reserve for the recovery path (sending tokens directly)
    constructor(address _owner, address _executor, address _endpointV2, uint256 _recoverGas)
        WithdrawablePeriphery(_owner)
    {
        executor = IExecutor(_executor);
        endpointV2 = _endpointV2;
        recoverGas = _recoverGas;
    }

    /// External Methods ///

    /// @notice Completes an OFT cross-chain transaction on the receiving chain
    /// @dev This function is called by LayerZero endpoint when a composed message is sent with an OFT transfer.
    ///      The `_from` address is the OApp/OFT contract that initiated the compose via sendCompose().
    ///      The bridged token address is obtained by calling `IOFT(_from).token()`, which returns the
    ///      underlying ERC20 in all cases: standard OFT (returns itself), OFTAdapter (returns the
    ///      wrapped token), and Stargate V2 pools (returns the pool's underlying token).
    ///
    ///      Security is provided by the `onlyEndpointV2` modifier — only the LayerZero
    ///      endpoint can call this function, and it only routes legitimate sendCompose()
    ///      calls from real OApp contracts.
    ///
    ///      ⚠️ Because the endpoint's `lzCompose` is permissionless and must be
    ///      replayed with exactly the same parameters, a frontrunner could slip in
    ///      first with too little gas and force our internal `_swapAndCompleteBridgeTokens`
    ///      into its "recover only" fallback. The user would then receive raw bridged
    ///      tokens instead of the intended swap output. This is a known protocol level
    ///      limitation that cannot be 100% prevented on-chain. For simplicity and
    ///      manual recoverability, consumers should monitor `LiFiTransferRecovered`
    ///      events and retry if necessary.
    ///
    /// @param _from The OApp/OFT contract that initiated the compose
    /// @param _message The composed message payload in bytes. Contains the swap execution data.
    function lzCompose(
        address _from,
        bytes32, // _guid (not used)
        bytes calldata _message,
        address, // _executor (not used)
        bytes calldata // _extraData (not used)
    )
        external
        payable
        onlyEndpointV2
    {
        // sanity check: _from must be a contract (EOAs cannot be OApps)
        if (!LibAsset.isContract(_from)) revert UnAuthorized();

        // get the underlying token address via the OFT token() interface.
        // This is consistent across all OFT variants:
        //   - Standard OFT:      returns address(this)  (= _from)
        //   - OFTAdapter:        returns the wrapped ERC20 address
        //   - Stargate V2 Pool:  returns the pool's token address
        address bridgedAssetId = IOFT(_from).token();

        // decode payload
        (bytes32 transactionId, LibSwap.SwapData[] memory swapData, address receiver) =
            abi.decode(OFTComposeMsgCodec.composeMsg(_message), (bytes32, LibSwap.SwapData[], address));

        // execute swap(s)
        _swapAndCompleteBridgeTokens(
            transactionId, swapData, bridgedAssetId, payable(receiver), OFTComposeMsgCodec.amountLD(_message)
        );
    }

    /// Private Methods ///

    /// @notice Performs a swap before completing a cross-chain transaction
    /// @param _transactionId the transaction id associated with the operation
    /// @param _swapData array of data needed for swaps
    /// @param assetId address of the token received from the source chain
    /// @param receiver address that will receive tokens in the end
    /// @param amount amount of token
    function _swapAndCompleteBridgeTokens(
        bytes32 _transactionId,
        LibSwap.SwapData[] memory _swapData,
        address assetId,
        address payable receiver,
        uint256 amount
    ) private {
        uint256 cacheGasLeft = gasleft();

        if (LibAsset.isNativeAsset(assetId)) {
            // case 1: native asset
            if (cacheGasLeft < recoverGas) {
                // case 1a: not enough gas left to execute calls
                SafeTransferLib.safeTransferETH(receiver, amount);

                emit LiFiTransferRecovered(_transactionId, assetId, receiver, amount, block.timestamp);
                return;
            }

            // case 1b: enough gas left to execute calls
            // solhint-disable no-empty-blocks
            try executor.swapAndCompleteBridgeTokens{value: amount, gas: cacheGasLeft - recoverGas}(
                _transactionId, _swapData, assetId, receiver
            ) {}
            catch {
                SafeTransferLib.safeTransferETH(receiver, amount);

                emit LiFiTransferRecovered(_transactionId, assetId, receiver, amount, block.timestamp);
            }
        } else {
            // case 2: ERC20 asset
            IERC20 token = IERC20(assetId);
            token.safeApprove(address(executor), 0);

            if (cacheGasLeft < recoverGas) {
                // case 2a: not enough gas left to execute calls
                token.safeTransfer(receiver, amount);

                emit LiFiTransferRecovered(_transactionId, assetId, receiver, amount, block.timestamp);
                return;
            }

            // case 2b: enough gas left to execute calls
            token.safeIncreaseAllowance(address(executor), amount);
            try executor.swapAndCompleteBridgeTokens{gas: cacheGasLeft - recoverGas}(
                _transactionId, _swapData, assetId, receiver
            ) {}
            catch {
                token.safeTransfer(receiver, amount);
                emit LiFiTransferRecovered(_transactionId, assetId, receiver, amount, block.timestamp);
            }

            token.safeApprove(address(executor), 0);
        }
    }

    /// @notice Receive native asset directly.
    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}
}
