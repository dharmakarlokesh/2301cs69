// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title  Three-party escrow (buyer, seller, arbiter) with pull payments
/// @author CS
/// @notice See docs/specification.md for the state machine this contract implements.
contract Escrow is ReentrancyGuard, EIP712 {
    // ------------------------------------------------------------------ types
    enum State {
        Created,
        Funded,
        Released,
        Disputed,
        ResolvedToBuyer,
        ResolvedToSeller,
        Cancelled
    }

    // ------------------------------------------------------------------ errors
    error ZeroAddress();
    error RoleOverlap();
    error ZeroPrice();
    error Unauthorized(address caller);
    error InvalidState(State current);
    error WrongAmount(uint256 sent, uint256 expected);
    error AlreadyApproved(address party);
    error NothingToWithdraw();
    error SignatureExpired(uint256 deadline);
    error InvalidSignature();

    // ------------------------------------------------------------------ events
    event StateChanged(State indexed from, State indexed to);
    event Funded(address indexed buyer, uint256 amount);
    event CancelApproved(address indexed party);
    event Cancelled();
    event Released(address indexed by, address indexed seller, uint256 amount);
    event Disputed(address indexed by);
    event Resolved(address indexed arbiter, address indexed payee, uint256 amount, bool toBuyer);
    event Withdrawn(address indexed payee, uint256 amount);

    // ------------------------------------------------------------------ storage
    bytes32 public constant RELEASE_TYPEHASH =
        keccak256("Release(address escrow,uint256 nonce,uint256 deadline)");

    address public immutable buyer;
    address public immutable seller;
    address public immutable arbiter;
    uint256 public immutable price;

    State public state;
    uint256 public escrowed; // funds held for the deal
    uint256 public totalCredits; // funds owed to payees (sum of credit[])
    uint256 public releaseNonce; // EIP-712 replay protection
    bool public buyerApprovedCancel;
    bool public sellerApprovedCancel;
    mapping(address => uint256) public credit;

    // ------------------------------------------------------------------ modifiers
    modifier inState(State expected) {
        _checkState(expected);
        _;
    }

    modifier only(address who) {
        _checkCaller(who);
        _;
    }

    function _checkState(State expected) private view {
        if (state != expected) revert InvalidState(state);
    }

    function _checkCaller(address who) private view {
        if (msg.sender != who) revert Unauthorized(msg.sender);
    }

    // ------------------------------------------------------------------ constructor
    constructor(address buyer_, address seller_, address arbiter_, uint256 price_) EIP712("ToyEscrow", "1") {
        if (buyer_ == address(0) || seller_ == address(0) || arbiter_ == address(0)) revert ZeroAddress();
        if (buyer_ == seller_ || arbiter_ == buyer_ || arbiter_ == seller_) revert RoleOverlap();
        if (price_ == 0) revert ZeroPrice();
        buyer = buyer_;
        seller = seller_;
        arbiter = arbiter_;
        price = price_;
        // state defaults to Created
    }

    // ------------------------------------------------------------------ Created
    /// @notice Buyer deposits exactly `price`. Can only happen once (state check).
    function fund() external payable only(buyer) inState(State.Created) {
        if (msg.value != price) revert WrongAmount(msg.value, price);
        escrowed = msg.value;
        _transition(State.Funded);
        emit Funded(msg.sender, msg.value);
    }

    /// @notice Mutual cancellation before funding: both buyer and seller must approve.
    function approveCancel() external inState(State.Created) {
        if (msg.sender == buyer) {
            if (buyerApprovedCancel) revert AlreadyApproved(msg.sender);
            buyerApprovedCancel = true;
        } else if (msg.sender == seller) {
            if (sellerApprovedCancel) revert AlreadyApproved(msg.sender);
            sellerApprovedCancel = true;
        } else {
            revert Unauthorized(msg.sender);
        }
        emit CancelApproved(msg.sender);
        if (buyerApprovedCancel && sellerApprovedCancel) {
            _transition(State.Cancelled);
            emit Cancelled();
        }
    }

    // ------------------------------------------------------------------ Funded
    /// @notice Buyer is satisfied: the seller is credited with the escrowed amount.
    function release() external only(buyer) inState(State.Funded) {
        _release(msg.sender);
    }

    /// @notice Gas-sponsored release: anyone may submit the buyer's EIP-712 signature.
    function releaseWithSig(uint256 deadline, uint8 v, bytes32 r, bytes32 s) external inState(State.Funded) {
        if (block.timestamp > deadline) revert SignatureExpired(deadline);
        bytes32 digest = releaseDigest(releaseNonce, deadline);
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, v, r, s);
        if (err != ECDSA.RecoverError.NoError || signer != buyer) revert InvalidSignature();
        unchecked {
            ++releaseNonce;
        }
        _release(msg.sender);
    }

    /// @notice Buyer or seller escalates to the arbiter.
    function dispute() external inState(State.Funded) {
        if (msg.sender != buyer && msg.sender != seller) revert Unauthorized(msg.sender);
        _transition(State.Disputed);
        emit Disputed(msg.sender);
    }

    // ------------------------------------------------------------------ Disputed
    function resolveToBuyer() external only(arbiter) inState(State.Disputed) {
        _resolve(buyer, State.ResolvedToBuyer, true);
    }

    function resolveToSeller() external only(arbiter) inState(State.Disputed) {
        _resolve(seller, State.ResolvedToSeller, false);
    }

    // ------------------------------------------------------------------ pull payment
    /// @notice Collect any credited funds. Checks-effects-interactions + reentrancy guard.
    function withdraw() external nonReentrant {
        uint256 amount = credit[msg.sender]; // check
        if (amount == 0) revert NothingToWithdraw();
        credit[msg.sender] = 0; // effects
        totalCredits -= amount;
        emit Withdrawn(msg.sender, amount);
        Address.sendValue(payable(msg.sender), amount); // interaction (reverts on failure)
    }

    // ------------------------------------------------------------------ views
    function releaseDigest(uint256 nonce, uint256 deadline) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(RELEASE_TYPEHASH, address(this), nonce, deadline)));
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Liabilities recorded by the contract; equals address(this).balance unless
    ///         someone force-sent ETH (selfdestruct), in which case balance is larger.
    function liabilities() external view returns (uint256) {
        return escrowed + totalCredits;
    }

    function isTerminal() public view returns (bool) {
        return state == State.Released || state == State.ResolvedToBuyer || state == State.ResolvedToSeller
            || state == State.Cancelled;
    }

    // ------------------------------------------------------------------ internal
    function _release(address by) private {
        uint256 amount = escrowed;
        escrowed = 0;
        credit[seller] += amount;
        totalCredits += amount;
        _transition(State.Released);
        emit Released(by, seller, amount);
    }

    function _resolve(address payee, State to, bool toBuyer) private {
        uint256 amount = escrowed;
        escrowed = 0;
        credit[payee] += amount;
        totalCredits += amount;
        _transition(to);
        emit Resolved(msg.sender, payee, amount, toBuyer);
    }

    function _transition(State to) private {
        emit StateChanged(state, to);
        state = to;
    }

    // No receive()/fallback(): plain ETH transfers revert, so funds only enter via fund().
}
