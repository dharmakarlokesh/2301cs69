// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Escrow} from "../src/Escrow.sol";

/// Seller contract that tries to re-enter withdraw() when it receives ETH.
contract ReentrantSeller {
    Escrow public escrow;
    uint256 public reentryAttempts;
    bool public reentrySucceeded;

    function setEscrow(Escrow e) external {
        escrow = e;
    }

    function collect() external {
        escrow.withdraw();
    }

    receive() external payable {
        reentryAttempts++;
        try escrow.withdraw() {
            reentrySucceeded = true;
        } catch {}
    }
}

/// Seller contract that refuses ETH.
contract RejectingSeller {
    function collect(Escrow e) external {
        e.withdraw();
    }

    receive() external payable {
        revert("no thanks");
    }
}

contract EscrowTest is Test {
    Escrow internal e;
    address internal buyer;
    uint256 internal buyerPk;
    address internal seller = makeAddr("seller");
    address internal arbiter = makeAddr("arbiter");
    address internal stranger = makeAddr("stranger");
    uint256 internal constant PRICE = 1 ether;

    event StateChanged(Escrow.State indexed from, Escrow.State indexed to);
    event Funded(address indexed buyer, uint256 amount);
    event CancelApproved(address indexed party);
    event Cancelled();
    event Released(address indexed by, address indexed seller, uint256 amount);
    event Disputed(address indexed by);
    event Resolved(address indexed arbiter, address indexed payee, uint256 amount, bool toBuyer);
    event Withdrawn(address indexed payee, uint256 amount);

    function setUp() public {
        (buyer, buyerPk) = makeAddrAndKey("buyer");
        e = new Escrow(buyer, seller, arbiter, PRICE);
        vm.deal(buyer, 100 ether);
        vm.deal(stranger, 100 ether);
        vm.deal(seller, 100 ether);
        vm.deal(arbiter, 100 ether);
    }

    // ------------------------------------------------------------------ helpers
    function _accountingHolds(Escrow x) internal view {
        assertEq(address(x).balance, x.escrowed() + x.totalCredits(), "balance != liabilities");
        assertEq(x.liabilities(), address(x).balance);
        uint256 sum = x.credit(x.buyer()) + x.credit(x.seller()) + x.credit(x.arbiter());
        assertEq(sum, x.totalCredits(), "credits do not sum");
    }

    function _fund() internal {
        vm.prank(buyer);
        e.fund{value: PRICE}();
    }

    function _toState(Escrow.State s) internal {
        if (s == Escrow.State.Created) return;
        if (s == Escrow.State.Cancelled) {
            vm.prank(buyer);
            e.approveCancel();
            vm.prank(seller);
            e.approveCancel();
            return;
        }
        _fund();
        if (s == Escrow.State.Funded) return;
        if (s == Escrow.State.Released) {
            vm.prank(buyer);
            e.release();
            return;
        }
        vm.prank(seller);
        e.dispute();
        if (s == Escrow.State.Disputed) return;
        vm.prank(arbiter);
        if (s == Escrow.State.ResolvedToBuyer) e.resolveToBuyer();
        else e.resolveToSeller();
    }

    function _sign(uint256 pk, Escrow x, uint256 nonce, uint256 deadline)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(pk, x.releaseDigest(nonce, deadline));
    }

    // ------------------------------------------------------------------ constructor
    function test_constructor_setsRolesAndState() public view {
        assertEq(e.buyer(), buyer);
        assertEq(e.seller(), seller);
        assertEq(e.arbiter(), arbiter);
        assertEq(e.price(), PRICE);
        assertEq(uint256(e.state()), uint256(Escrow.State.Created));
        _accountingHolds(e);
    }

    function test_constructor_rejectsZeroAddresses() public {
        vm.expectRevert(Escrow.ZeroAddress.selector);
        new Escrow(address(0), seller, arbiter, 1);
        vm.expectRevert(Escrow.ZeroAddress.selector);
        new Escrow(buyer, address(0), arbiter, 1);
        vm.expectRevert(Escrow.ZeroAddress.selector);
        new Escrow(buyer, seller, address(0), 1);
    }

    function test_constructor_rejectsRoleOverlap() public {
        vm.expectRevert(Escrow.RoleOverlap.selector);
        new Escrow(buyer, buyer, arbiter, 1);
        vm.expectRevert(Escrow.RoleOverlap.selector);
        new Escrow(buyer, seller, buyer, 1);
        vm.expectRevert(Escrow.RoleOverlap.selector);
        new Escrow(buyer, seller, seller, 1);
    }

    function test_constructor_rejectsZeroPrice() public {
        vm.expectRevert(Escrow.ZeroPrice.selector);
        new Escrow(buyer, seller, arbiter, 0);
    }

    // ------------------------------------------------------------------ Created -> Funded
    function test_fund() public {
        vm.expectEmit(true, true, false, false, address(e));
        emit StateChanged(Escrow.State.Created, Escrow.State.Funded);
        vm.expectEmit(true, false, false, true, address(e));
        emit Funded(buyer, PRICE);
        _fund();
        assertEq(uint256(e.state()), uint256(Escrow.State.Funded));
        assertEq(e.escrowed(), PRICE);
        assertEq(address(e).balance, PRICE);
        _accountingHolds(e);
    }

    function test_fund_rejectsWrongAmount() public {
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(Escrow.WrongAmount.selector, PRICE - 1, PRICE));
        e.fund{value: PRICE - 1}();
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(Escrow.WrongAmount.selector, PRICE + 1, PRICE));
        e.fund{value: PRICE + 1}();
    }

    function test_fund_rejectsNonBuyer() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, stranger));
        e.fund{value: PRICE}();
    }

    function test_fund_rejectsRepeatedFunding() public {
        _fund();
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(Escrow.InvalidState.selector, Escrow.State.Funded));
        e.fund{value: PRICE}();
        assertEq(address(e).balance, PRICE);
    }

    // ------------------------------------------------------------------ Created -> Cancelled
    function test_cancel_requiresBothParties() public {
        vm.expectEmit(true, false, false, false, address(e));
        emit CancelApproved(seller);
        vm.prank(seller);
        e.approveCancel();
        assertEq(uint256(e.state()), uint256(Escrow.State.Created), "one approval is not enough");
        vm.expectEmit(true, false, false, false, address(e));
        emit CancelApproved(buyer);
        vm.expectEmit(true, true, false, false, address(e));
        emit StateChanged(Escrow.State.Created, Escrow.State.Cancelled);
        vm.expectEmit(false, false, false, false, address(e));
        emit Cancelled();
        vm.prank(buyer);
        e.approveCancel();
        assertEq(uint256(e.state()), uint256(Escrow.State.Cancelled));
        // nothing can be funded afterwards
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(Escrow.InvalidState.selector, Escrow.State.Cancelled));
        e.fund{value: PRICE}();
    }

    function test_cancel_rejectsDoubleApprovalAndOutsiders() public {
        vm.prank(buyer);
        e.approveCancel();
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(Escrow.AlreadyApproved.selector, buyer));
        e.approveCancel();
        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, arbiter));
        e.approveCancel();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, stranger));
        e.approveCancel();
    }

    function test_cancel_notAfterFunding() public {
        _fund();
        vm.prank(seller);
        vm.expectRevert(abi.encodeWithSelector(Escrow.InvalidState.selector, Escrow.State.Funded));
        e.approveCancel();
    }

    // ------------------------------------------------------------------ Funded -> Released
    function test_release_creditsSellerAndPullPayment() public {
        _fund();
        vm.expectEmit(true, true, false, false, address(e));
        emit StateChanged(Escrow.State.Funded, Escrow.State.Released);
        vm.expectEmit(true, true, false, true, address(e));
        emit Released(buyer, seller, PRICE);
        vm.prank(buyer);
        e.release();
        assertEq(e.credit(seller), PRICE);
        assertEq(e.escrowed(), 0);
        assertEq(address(e).balance, PRICE, "no push payment happened");
        _accountingHolds(e);

        uint256 before = seller.balance;
        vm.expectEmit(true, false, false, true, address(e));
        emit Withdrawn(seller, PRICE);
        vm.prank(seller);
        e.withdraw();
        assertEq(seller.balance, before + PRICE);
        assertEq(address(e).balance, 0);
        _accountingHolds(e);
    }

    function test_release_onlyBuyer() public {
        _fund();
        address[3] memory others = [seller, arbiter, stranger];
        for (uint256 i; i < 3; i++) {
            vm.prank(others[i]);
            vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, others[i]));
            e.release();
        }
    }

    // ------------------------------------------------------------------ Funded -> Disputed -> Resolved
    function test_dispute_byBuyerOrSeller() public {
        _fund();
        vm.expectEmit(true, false, false, false, address(e));
        emit Disputed(buyer);
        vm.prank(buyer);
        e.dispute();
        assertEq(uint256(e.state()), uint256(Escrow.State.Disputed));

        Escrow e2 = new Escrow(buyer, seller, arbiter, PRICE);
        vm.prank(buyer);
        e2.fund{value: PRICE}();
        vm.prank(seller);
        e2.dispute();
        assertEq(uint256(e2.state()), uint256(Escrow.State.Disputed));
    }

    function test_dispute_rejectsArbiterAndStranger() public {
        _fund();
        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, arbiter));
        e.dispute();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, stranger));
        e.dispute();
    }

    function test_resolveToBuyer() public {
        _toState(Escrow.State.Disputed);
        vm.expectEmit(true, true, false, true, address(e));
        emit Resolved(arbiter, buyer, PRICE, true);
        vm.prank(arbiter);
        e.resolveToBuyer();
        assertEq(uint256(e.state()), uint256(Escrow.State.ResolvedToBuyer));
        assertEq(e.credit(buyer), PRICE);
        assertEq(e.credit(seller), 0);
        uint256 before = buyer.balance;
        vm.prank(buyer);
        e.withdraw();
        assertEq(buyer.balance, before + PRICE);
        _accountingHolds(e);
    }

    function test_resolveToSeller() public {
        _toState(Escrow.State.Disputed);
        vm.expectEmit(true, true, false, true, address(e));
        emit Resolved(arbiter, seller, PRICE, false);
        vm.prank(arbiter);
        e.resolveToSeller();
        assertEq(uint256(e.state()), uint256(Escrow.State.ResolvedToSeller));
        assertEq(e.credit(seller), PRICE);
        vm.prank(seller);
        e.withdraw();
        assertEq(address(e).balance, 0);
        _accountingHolds(e);
    }

    function test_resolve_onlyArbiter() public {
        _toState(Escrow.State.Disputed);
        address[3] memory others = [buyer, seller, stranger];
        for (uint256 i; i < 3; i++) {
            vm.startPrank(others[i]);
            vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, others[i]));
            e.resolveToBuyer();
            vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, others[i]));
            e.resolveToSeller();
            vm.stopPrank();
        }
    }

    // ------------------------------------------------------------------ exhaustive transition matrix
    /// For every state, every action and every caller: the call succeeds iff the spec allows it,
    /// and a rejected call changes neither the state nor any balance.
    function test_transitionMatrix_everyRejectedTransition() public {
        address[4] memory callers = [buyer, seller, arbiter, stranger];
        uint256 checked;
        for (uint8 s = 0; s <= uint8(Escrow.State.Cancelled); s++) {
            for (uint8 a = 0; a < 6; a++) {
                for (uint256 c = 0; c < 4; c++) {
                    uint256 snap = vm.snapshotState();
                    e = new Escrow(buyer, seller, arbiter, PRICE);
                    _toState(Escrow.State(s));
                    Escrow.State before = e.state();
                    uint256 bal = address(e).balance;
                    bool allowed = _allowed(Escrow.State(s), a, callers[c]);
                    vm.prank(callers[c]);
                    (bool ok,) = address(e).call{value: a == 0 ? PRICE : 0}(_calldata(a));
                    assertEq(ok, allowed, string.concat("state ", vm.toString(s), " action ", vm.toString(a),
                        " caller ", vm.toString(c)));
                    if (!ok) {
                        assertEq(uint256(e.state()), uint256(before), "rejected call changed state");
                        assertEq(address(e).balance, bal, "rejected call moved funds");
                    }
                    _accountingHolds(e);
                    checked++;
                    vm.revertToState(snap);
                }
            }
        }
        assertEq(checked, 7 * 6 * 4);
    }

    function _calldata(uint8 a) internal pure returns (bytes memory) {
        if (a == 0) return abi.encodeCall(Escrow.fund, ());
        if (a == 1) return abi.encodeCall(Escrow.approveCancel, ());
        if (a == 2) return abi.encodeCall(Escrow.release, ());
        if (a == 3) return abi.encodeCall(Escrow.dispute, ());
        if (a == 4) return abi.encodeCall(Escrow.resolveToBuyer, ());
        return abi.encodeCall(Escrow.resolveToSeller, ());
    }

    function _allowed(Escrow.State s, uint8 a, address who) internal view returns (bool) {
        if (s == Escrow.State.Created) {
            if (a == 0) return who == buyer;
            if (a == 1) return who == buyer || who == seller;
            return false;
        }
        if (s == Escrow.State.Funded) {
            if (a == 2) return who == buyer;
            if (a == 3) return who == buyer || who == seller;
            return false;
        }
        if (s == Escrow.State.Disputed) return (a == 4 || a == 5) && who == arbiter;
        return false; // terminal states: nothing
    }

    // ------------------------------------------------------------------ terminal states cannot pay twice
    function test_terminal_cannotPayTwice() public {
        _toState(Escrow.State.Released);
        vm.prank(seller);
        e.withdraw();
        vm.prank(seller);
        vm.expectRevert(Escrow.NothingToWithdraw.selector);
        e.withdraw();
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(Escrow.InvalidState.selector, Escrow.State.Released));
        e.release();
        vm.prank(seller);
        vm.expectRevert(abi.encodeWithSelector(Escrow.InvalidState.selector, Escrow.State.Released));
        e.dispute();
        assertEq(address(e).balance, 0);
    }

    function test_withdraw_nothingForStrangerOrArbiter() public {
        _toState(Escrow.State.ResolvedToSeller);
        vm.prank(stranger);
        vm.expectRevert(Escrow.NothingToWithdraw.selector);
        e.withdraw();
        vm.prank(arbiter);
        vm.expectRevert(Escrow.NothingToWithdraw.selector);
        e.withdraw();
        vm.prank(buyer);
        vm.expectRevert(Escrow.NothingToWithdraw.selector);
        e.withdraw();
    }

    // ------------------------------------------------------------------ reentrancy / hostile receivers
    function test_reentrancy_cannotDrain() public {
        ReentrantSeller evil = new ReentrantSeller();
        Escrow x = new Escrow(buyer, address(evil), arbiter, PRICE);
        evil.setEscrow(x);
        vm.prank(buyer);
        x.fund{value: PRICE}();
        vm.prank(buyer);
        x.release();
        evil.collect();
        assertEq(address(evil).balance, PRICE, "paid exactly once");
        assertEq(evil.reentryAttempts(), 1);
        assertFalse(evil.reentrySucceeded(), "re-entrant withdraw must fail");
        assertEq(address(x).balance, 0);
        _accountingHolds(x);
    }

    function test_rejectingPayee_onlyBlocksItself() public {
        RejectingSeller bad = new RejectingSeller();
        Escrow x = new Escrow(buyer, address(bad), arbiter, PRICE);
        vm.prank(buyer);
        x.fund{value: PRICE}();
        vm.prank(buyer);
        x.release();
        vm.expectRevert(bytes("no thanks")); // payee's own revert reason is bubbled up
        bad.collect(x);
        assertEq(x.credit(address(bad)), PRICE, "credit kept after failed send");
        _accountingHolds(x);
    }

    function test_plainEtherTransferRejected() public {
        vm.prank(stranger);
        (bool ok,) = address(e).call{value: 1 ether}("");
        assertFalse(ok);
        assertEq(address(e).balance, 0);
    }

    function test_forcedEther_doesNotBreakAccounting() public {
        _fund();
        vm.deal(address(e), address(e).balance + 5 ether); // simulates selfdestruct force-send
        assertGe(address(e).balance, e.liabilities());
        vm.prank(buyer);
        e.release();
        vm.prank(seller);
        e.withdraw();
        assertEq(e.liabilities(), 0);
    }

    // ------------------------------------------------------------------ EIP-712 gas-sponsored release
    function test_releaseWithSig_byRelayer() public {
        _fund();
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _sign(buyerPk, e, 0, deadline);
        vm.expectEmit(true, true, false, true, address(e));
        emit Released(stranger, seller, PRICE);
        vm.prank(stranger); // relayer pays the gas
        e.releaseWithSig(deadline, v, r, s);
        assertEq(uint256(e.state()), uint256(Escrow.State.Released));
        assertEq(e.credit(seller), PRICE);
        assertEq(e.releaseNonce(), 1);
        // replay of the same signature fails
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Escrow.InvalidState.selector, Escrow.State.Released));
        e.releaseWithSig(deadline, v, r, s);
    }

    function test_releaseWithSig_rejectsExpiredWrongSignerOtherContract() public {
        _fund();
        uint256 deadline = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(buyerPk, e, 0, deadline);
        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(Escrow.SignatureExpired.selector, deadline));
        e.releaseWithSig(deadline, v, r, s);
        vm.warp(deadline); // exactly at the deadline is still valid ( > not >= )

        (, uint256 sellerPk) = makeAddrAndKey("seller-key");
        (v, r, s) = _sign(sellerPk, e, 0, deadline);
        vm.expectRevert(Escrow.InvalidSignature.selector);
        e.releaseWithSig(deadline, v, r, s);

        Escrow other = new Escrow(buyer, seller, arbiter, PRICE);
        (v, r, s) = _sign(buyerPk, other, 0, deadline); // signed for a different contract
        vm.expectRevert(Escrow.InvalidSignature.selector);
        e.releaseWithSig(deadline, v, r, s);

        (v, r, s) = _sign(buyerPk, e, 1, deadline); // wrong nonce
        vm.expectRevert(Escrow.InvalidSignature.selector);
        e.releaseWithSig(deadline, v, r, s);

        (v, r, s) = _sign(buyerPk, e, 0, deadline); // malleable high-s twin is rejected
        bytes32 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        vm.expectRevert(Escrow.InvalidSignature.selector);
        e.releaseWithSig(deadline, v == 27 ? 28 : 27, r, bytes32(uint256(n) - uint256(s)));

        e.releaseWithSig(deadline, v, r, s); // the genuine one still works
        assertEq(uint256(e.state()), uint256(Escrow.State.Released));
    }

    function test_domainSeparator_bindsChainAndContract() public {
        bytes32 expected = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("ToyEscrow"), keccak256("1"), block.chainid, address(e)));
        assertEq(e.domainSeparator(), expected);
        Escrow other = new Escrow(buyer, seller, arbiter, PRICE);
        assertTrue(other.domainSeparator() != e.domainSeparator());
    }

    function test_releaseWithSig_notInDispute() public {
        _toState(Escrow.State.Disputed);
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _sign(buyerPk, e, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(Escrow.InvalidState.selector, Escrow.State.Disputed));
        e.releaseWithSig(deadline, v, r, s);
    }

    // ------------------------------------------------------------------ fuzz tests
    function testFuzz_depositAmounts(uint256 price, uint256 sent) public {
        price = bound(price, 1, 1e30);
        Escrow x = new Escrow(buyer, seller, arbiter, price);
        vm.deal(buyer, sent > price ? sent : price);
        vm.prank(buyer);
        if (sent != price) {
            vm.expectRevert(abi.encodeWithSelector(Escrow.WrongAmount.selector, sent, price));
            x.fund{value: sent}();
            assertEq(uint256(x.state()), uint256(Escrow.State.Created));
        } else {
            x.fund{value: sent}();
            assertEq(x.escrowed(), price);
        }
        _accountingHolds(x);
    }

    function testFuzz_callerRoles(address caller) public {
        vm.assume(caller != buyer && caller != seller && caller != arbiter);
        vm.deal(caller, 10 ether);
        vm.startPrank(caller);
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, caller));
        e.fund{value: PRICE}();
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, caller));
        e.approveCancel();
        vm.stopPrank();
        _fund();
        vm.startPrank(caller);
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, caller));
        e.release();
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, caller));
        e.dispute();
        vm.stopPrank();
        vm.prank(buyer);
        e.dispute();
        vm.startPrank(caller);
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, caller));
        e.resolveToBuyer();
        vm.expectRevert(abi.encodeWithSelector(Escrow.Unauthorized.selector, caller));
        e.resolveToSeller();
        vm.expectRevert(Escrow.NothingToWithdraw.selector);
        e.withdraw();
        vm.stopPrank();
        assertEq(address(e).balance, PRICE);
        _accountingHolds(e);
    }

    function testFuzz_rolesAtConstruction(address b, address s, address a) public {
        bool bad = b == address(0) || s == address(0) || a == address(0) || b == s || a == b || a == s;
        if (bad) vm.expectRevert();
        new Escrow(b, s, a, 1);
    }

    function testFuzz_everyPathPaysExactlyOnce(uint256 price, uint8 path) public {
        price = bound(price, 1, 1e24);
        path = uint8(bound(path, 0, 2));
        Escrow x = new Escrow(buyer, seller, arbiter, price);
        vm.deal(buyer, price);
        vm.prank(buyer);
        x.fund{value: price}();
        address payee;
        if (path == 0) {
            vm.prank(buyer);
            x.release();
            payee = seller;
        } else {
            vm.prank(path == 1 ? buyer : seller);
            x.dispute();
            vm.prank(arbiter);
            if (path == 1) x.resolveToBuyer();
            else x.resolveToSeller();
            payee = path == 1 ? buyer : seller;
        }
        _accountingHolds(x);
        uint256 before = payee.balance;
        vm.prank(payee);
        x.withdraw();
        assertEq(payee.balance - before, price);
        vm.prank(payee);
        vm.expectRevert(Escrow.NothingToWithdraw.selector);
        x.withdraw();
        assertTrue(x.isTerminal());
        assertEq(address(x).balance, 0);
    }
}
