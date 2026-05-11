// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

import {ILiFi} from "../Interfaces/ILiFi.sol";
import {IOFT} from "../Interfaces/IOFT.sol";
import {LibAsset} from "../Libraries/LibAsset.sol";
import {ReentrancyGuard} from "../Helpers/ReentrancyGuard.sol";
import {InformationMismatch} from "../Errors/GenericErrors.sol";
import {SwapperV2, LibSwap} from "../Helpers/SwapperV2.sol";
import {Validatable} from "../Helpers/Validatable.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {ERC20} from "solady/tokens/ERC20.sol";

/// @title OFTFacet
/// @author LI.FI (https://li.fi)
/// @notice Provides functionality for bridging through LayerZero OFT tokens
/// @dev OFT (Omnichain Fungible Token) is a LayerZero V2 standard that allows
///      tokens to be transferred cross-chain. Each OFT token contract handles
///      its own bridging logic directly, unlike Stargate which uses separate
///      pool contracts managed by a TokenMessaging registry.
/// @custom:version 1.0.0
contract OFTFacet is ILiFi, ReentrancyGuard, SwapperV2, Validatable {
    using SafeTransferLib for address;

    /// STORAGE ///

    /// @param oftToken The OFT contract address to call send() on.
    ///                 For standard OFT this is the token address itself.
    ///                 For OFTAdapter this is the adapter contract (distinct from the underlying token).
    /// @param sendParams Various parameters that describe what needs to be bridged, how to bridge it
    ///                    and what to do with it on dst
    /// @param fee Information about the (native) LayerZero fee that needs to be sent with the tx
    /// @param refundAddress the address that is used for potential refunds
    struct OFTData {
        address oftToken;
        IOFT.SendParam sendParams;
        IOFT.MessagingFee fee;
        address payable refundAddress;
    }

    /// ERRORS ///
    error InvalidOFTToken();

    /// EXTERNAL METHODS ///

    /// @notice Bridges tokens via LayerZero OFT
    /// @param _bridgeData Data used purely for tracking and analytics
    /// @param _oftData Data specific to OFT bridging
    function startBridgeTokensViaOFT(ILiFi.BridgeData calldata _bridgeData, OFTData calldata _oftData)
        external
        payable
        nonReentrant
        refundExcessNative(payable(msg.sender))
        doesNotContainSourceSwaps(_bridgeData)
        validateBridgeData(_bridgeData)
    {
        LibAsset.depositAsset(_bridgeData.sendingAssetId, _bridgeData.minAmount);
        _startBridge(_bridgeData, _oftData);
    }

    /// @notice Performs a swap before bridging via LayerZero OFT
    /// @param _bridgeData Data used purely for tracking and analytics
    /// @param _swapData An array of swap related data for performing swaps before bridging
    /// @param _oftData Data specific to OFT bridging
    function swapAndStartBridgeTokensViaOFT(
        ILiFi.BridgeData memory _bridgeData,
        LibSwap.SwapData[] calldata _swapData,
        OFTData calldata _oftData
    )
        external
        payable
        nonReentrant
        refundExcessNative(payable(msg.sender))
        containsSourceSwaps(_bridgeData)
        validateBridgeData(_bridgeData)
    {
        _bridgeData.minAmount = _depositAndSwap(
            _bridgeData.transactionId, _bridgeData.minAmount, _swapData, payable(msg.sender), _oftData.fee.nativeFee
        );

        _startBridge(_bridgeData, _oftData);
    }

    /// PRIVATE METHODS ///

    /// @notice Contains the business logic for the bridging via OFT
    /// @param _bridgeData Data used purely for tracking and analytics
    /// @param _oftData Data specific to OFT bridging
    function _startBridge(ILiFi.BridgeData memory _bridgeData, OFTData memory _oftData) private {
        // validate destination call flag
        if (
            (_oftData.sendParams.composeMsg.length > 0 != _bridgeData.hasDestinationCall)
                || (_bridgeData.hasDestinationCall && _oftData.sendParams.oftCmd.length != 0)
        ) revert InformationMismatch();

        // ensure that receiver addresses match in case of no destination call
        if (
            !_bridgeData.hasDestinationCall
                && (_bridgeData.receiver != address(uint160(uint256(_oftData.sendParams.to))))
        ) revert InformationMismatch();

        address oftToken = _oftData.oftToken;
        address token = _bridgeData.sendingAssetId;

        // validate that the OFT contract's token() matches the bridged asset
        if (IOFT(oftToken).token() != token) revert InvalidOFTToken();

        // approve the OFT contract to spend the deposited token
        // For standard OFT (oftToken == token) no approval is needed — the OFT
        // burns from msg.sender directly rather than pulling via transferFrom.
        // For OFTAdapter (oftToken != token), the adapter pulls the underlying
        // token via transferFrom, so approval is required.
        if (oftToken != token) {
            uint256 currentAllowance = ERC20(token).allowance(address(this), oftToken);
            if (currentAllowance < _bridgeData.minAmount) {
                if (currentAllowance != 0) {
                    token.safeApprove(oftToken, 0);
                }
                token.safeApprove(oftToken, type(uint256).max);
            }
        }

        uint256 msgValue = _oftData.fee.nativeFee;

        // update amount in sendParams
        _oftData.sendParams.amountLD = _bridgeData.minAmount;

        // execute call to OFT token contract
        // solhint-disable-next-line check-send-result
        IOFT(oftToken).send{value: msgValue}(_oftData.sendParams, _oftData.fee, _oftData.refundAddress);

        emit LiFiTransferStarted(_bridgeData);
    }
}
