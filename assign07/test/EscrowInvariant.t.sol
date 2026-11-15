// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Escrow} from "../src/Escrow.sol";

/// Drives the escrow with random actions from random roles.
contract Handler is Test {
    Escrow public e;
    address[4] public actors;
    uint256 public paidOut;
    uint256 public deposited;
    mapping(uint8 => uint256) public visits;

    function _visit() internal {
        visits[uint8(e.state())]++;
    }

    constructor(Escrow e_, address buyer, address seller, address arbiter, address stranger) {
        e = e_;
        actors = [buyer, seller, arbiter, stranger];
        for (uint256 i; i < 4; i++) vm.deal(actors[i], 1000 ether);
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % 4];
    }

    function fund(uint256 who, uint256 amount) external {
        // mostly the correct price (so the state machine is explored), sometimes a wrong amount
        amount = amount % 4 == 0 ? bound(amount, 0, 3 ether) : e.price();
        vm.prank(who % 2 == 0 ? actors[0] : _actor(who / 2)); // buyer half of the time
        try e.fund{value: amount}() {
            deposited += amount;
        } catch {}
        _visit();
    }

    function approveCancel(uint256 who) external {
        if (who % 8 != 0) return; // rare, otherwise most runs end in Cancelled immediately
        vm.prank(_actor(who / 8));
        try e.approveCancel() {} catch {}
    }

    function release(uint256 who) external {
        vm.prank(_actor(who));
        try e.release() {} catch {}
        _visit();
    }

    function dispute(uint256 who) external {
        vm.prank(_actor(who));
        try e.dispute() {} catch {}
        _visit();
    }

    function resolve(uint256 who, bool toBuyer) external {
        vm.prank(_actor(who));
        if (toBuyer) {
            try e.resolveToBuyer() {} catch {}
        } else {
            try e.resolveToSeller() {} catch {}
        }
        _visit();
    }

    function withdraw(uint256 who) external {
        address a = _actor(who);
        uint256 before = a.balance;
        vm.prank(a);
        try e.withdraw() {
            paidOut += a.balance - before;
        } catch {}
    }
}

contract EscrowInvariantTest is StdInvariant, Test {
    Escrow internal e;
    Handler internal h;
    address internal buyer = makeAddr("buyer");
    address internal seller = makeAddr("seller");
    address internal arbiter = makeAddr("arbiter");

    function setUp() public {
        e = new Escrow(buyer, seller, arbiter, 2 ether);
        h = new Handler(e, buyer, seller, arbiter, makeAddr("stranger"));
        targetContract(address(h));
    }

    /// The contract's balance and recorded liabilities agree after every action.
    function invariant_balanceEqualsLiabilities() public view {
        assertEq(address(e).balance, e.escrowed() + e.totalCredits());
    }

    /// Credits are owed only to parties, and sum to totalCredits.
    function invariant_creditsSum() public view {
        assertEq(e.credit(buyer) + e.credit(seller) + e.credit(arbiter), e.totalCredits());
        assertEq(e.credit(arbiter), 0, "arbiter is never a payee");
    }

    /// Money is conserved: never pays out more than was deposited (no double pay).
    function invariant_noDoublePay() public view {
        assertEq(h.deposited(), h.paidOut() + address(e).balance);
        assertLe(h.deposited(), e.price());
    }

    /// Terminal states hold nothing in escrow.
    function invariant_terminalHoldsNoEscrow() public view {
        if (e.isTerminal()) assertEq(e.escrowed(), 0);
    }

    /// Prints how often each state was reached, to show the fuzzer explores the whole machine.
    function afterInvariant() external view {
        for (uint8 s = 0; s <= uint8(Escrow.State.Cancelled); s++) {
            console.log("state", s, "visits", h.visits(s));
        }
    }
}
