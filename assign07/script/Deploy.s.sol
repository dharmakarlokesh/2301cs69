// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Escrow} from "../src/Escrow.sol";

/// Deploys two escrows on a local Anvil node and drives them through both payout paths.
/// Keys default to Anvil's well-known TEST accounts (never use them on a real network).
contract DeployAndInteract is Script {
    uint256 constant PRICE = 1 ether;

    function run() external {
        uint256 deployerPk = vm.envOr("DEPLOYER_PK", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
        uint256 buyerPk = vm.envOr("BUYER_PK", uint256(0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d));
        uint256 sellerPk = vm.envOr("SELLER_PK", uint256(0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a));
        uint256 arbiterPk = vm.envOr("ARBITER_PK", uint256(0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6));
        address buyer = vm.addr(buyerPk);
        address seller = vm.addr(sellerPk);
        address arbiter = vm.addr(arbiterPk);

        // ---- deal 1: happy path  Created -> Funded -> Released, seller withdraws
        vm.broadcast(deployerPk);
        Escrow happy = new Escrow(buyer, seller, arbiter, PRICE);
        vm.broadcast(buyerPk);
        happy.fund{value: PRICE}();
        vm.broadcast(buyerPk);
        happy.release();
        vm.broadcast(sellerPk);
        happy.withdraw();

        // ---- deal 2: dispute path  Created -> Funded -> Disputed -> ResolvedToBuyer, buyer withdraws
        vm.broadcast(deployerPk);
        Escrow disputed = new Escrow(buyer, seller, arbiter, PRICE);
        vm.broadcast(buyerPk);
        disputed.fund{value: PRICE}();
        vm.broadcast(sellerPk);
        disputed.dispute();
        vm.broadcast(arbiterPk);
        disputed.resolveToBuyer();
        vm.broadcast(buyerPk);
        disputed.withdraw();

        console.log("HAPPY_ESCROW", address(happy));
        console.log("DISPUTE_ESCROW", address(disputed));
        require(happy.state() == Escrow.State.Released, "happy path state");
        require(disputed.state() == Escrow.State.ResolvedToBuyer, "dispute path state");
        require(address(happy).balance == 0 && address(disputed).balance == 0, "funds left behind");
    }
}
