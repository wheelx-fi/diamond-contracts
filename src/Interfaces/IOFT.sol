// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

/// @title IOFT
/// @author LI.FI (https://li.fi)
/// @notice Interface for LayerZero OFT (Omnichain Fungible Token) standard
/// @dev Based on LayerZero V2 OFT standard
///      Reference: https://github.com/LayerZero-Labs/LayerZero-v2
/// @custom:version 1.0.0
interface IOFT {
    /// @notice Struct representing token parameters for the OFT send() operation.
    struct SendParam {
        uint32 dstEid; // Destination endpoint ID.
        bytes32 to; // Recipient address.
        uint256 amountLD; // Amount to send in local decimals.
        uint256 minAmountLD; // Minimum amount to send in local decimals.
        bytes extraOptions; // Additional options supplied by the caller to be used in the LayerZero message.
        bytes composeMsg; // The composed message for the send() operation.
        bytes oftCmd; // The OFT command to be executed, unused in default OFT implementations.
    }

    /// @notice Struct representing OFT limit information.
    struct OFTLimit {
        uint256 minAmountLD;
        uint256 maxAmountLD;
    }

    /// @notice Struct representing OFT receipt information.
    struct OFTReceipt {
        uint256 amountSentLD;
        uint256 amountReceivedLD;
    }

    /// @notice Struct representing OFT fee details.
    struct OFTFeeDetail {
        int256 feeAmountLD;
        string description;
    }

    /// @notice Struct representing LayerZero messaging fee.
    struct MessagingFee {
        uint256 nativeFee;
        uint256 lzTokenFee;
    }

    /// @notice Struct representing LayerZero messaging receipt.
    struct MessagingReceipt {
        bytes32 guid;
        uint64 nonce;
        MessagingFee fee;
    }

    /// @notice Sends tokens cross-chain via LayerZero OFT protocol.
    /// @param _sendParam The parameters for the send operation.
    /// @param _fee The calculated LayerZero messaging fee.
    /// @param _refundAddress The address to refund excess native fee to.
    /// @return msgReceipt The LayerZero messaging receipt.
    /// @return oftReceipt The OFT receipt (amounts sent/received).
    function send(SendParam calldata _sendParam, MessagingFee calldata _fee, address _refundAddress)
        external
        payable
        returns (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt);

    /// @notice Provides a quote for the send() operation.
    /// @param _sendParam The parameters for the send() operation.
    /// @param _payInLzToken Flag indicating whether the caller is paying in the LZ token.
    /// @return fee The calculated LayerZero messaging fee.
    function quoteSend(SendParam calldata _sendParam, bool _payInLzToken)
        external
        view
        returns (MessagingFee memory fee);

    /// @notice Provides a quote for OFT-related operations.
    /// @param _sendParam The parameters for the send operation.
    /// @return limit The OFT limit information.
    /// @return oftFeeDetails The details of OFT fees.
    /// @return receipt The OFT receipt information.
    function quoteOFT(SendParam calldata _sendParam)
        external
        view
        returns (OFTLimit memory limit, OFTFeeDetail[] memory oftFeeDetails, OFTReceipt memory receipt);

    /// @notice Returns the underlying ERC20 token address.
    ///         For standard OFT this returns itself; for OFTAdapter it
    ///         returns the wrapped ERC20.
    /// @return The address of the underlying token.
    function token() external view returns (address);
}
