// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {CoinbaseSmartWalletFactory} from "../lib/smart-wallet/src/CoinbaseSmartWalletFactory.sol";
import {CoinbaseSmartWallet} from "../lib/smart-wallet/src/CoinbaseSmartWallet.sol";
import {ERC1271InputGenerator} from "../lib/smart-wallet/src/utils/ERC1271InputGenerator.sol";
import {WebAuthn} from "../lib/webauthn-sol/src/WebAuthn.sol";
import {FCL_ecdsa} from "../lib/FreshCryptoLib/solidity/src/FCL_ecdsa.sol";
import {FCL_Elliptic_ZZ} from "../lib/FreshCryptoLib/solidity/src/FCL_elliptic.sol";
import "../lib/webauthn-sol/test/Utils.sol";

contract ForkTest is Test {
    uint256 baseSepoliaFork;
    CoinbaseSmartWalletFactory factory = CoinbaseSmartWalletFactory(0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a);

    function setUp() public {
        baseSepoliaFork = vm.createFork("https://sepolia.base.org");
        vm.selectFork(baseSepoliaFork);
        vm.rollFork(11692348);
    }

    function test_getAddress() public {
        bytes[] memory encodedOwners = new bytes[](1);
        encodedOwners[0] =
            hex"e510df1864033a2d1b63887b89c8512c52c0558d2b7f75b3108833429b824f296414e0ee79a4d15f1604d8f8bd3accff38e57cbb106c6b1bf11dfc02793b453e";
        CoinbaseSmartWallet predeploy = CoinbaseSmartWallet(payable(factory.getAddress(encodedOwners, 0)));
        require(address(predeploy) == 0xD87B536AbCD7e1374deC8dDA04E00184D16071F7, "incorrect predeploy");
        CoinbaseSmartWallet deploy = factory.createAccount(encodedOwners, 0);
        require(address(deploy) == address(predeploy), "error with deploy");

        bytes32 digest = hex"0455a08063080cd71b109eee7d5ad0ccb9b2938e39bf58c61b07548dcea0611c";
        bytes32 expectedReplaySafeHash = hex"44f4a27beeaabf338e0ba37a2d5c73016d72f3f3462e592ee213960c410f2fb3";

        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            predeploy,
            digest,
            address(factory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", encodedOwners, 0)
        );
        bytes32 genReplaySafeHash = bytes32(address(generator).code);
        bytes32 acctReplaySafeHash = deploy.replaySafeHash(digest);

        require(genReplaySafeHash == expectedReplaySafeHash, "incorrect replay hash calc");
        require(acctReplaySafeHash == expectedReplaySafeHash, "incorrect replay hash calc");

        bytes memory ownerAtIndex = deploy.ownerAtIndex(0);
        require(keccak256(ownerAtIndex) == keccak256(encodedOwners[0]), "incorrect owners");
        (uint256 x, uint256 y) = abi.decode(ownerAtIndex, (uint256, uint256));
        bytes memory reEncodeOwner = abi.encode(x, y);
        require(keccak256(reEncodeOwner) == keccak256(ownerAtIndex), "doesnt work");

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000",
            clientDataJSON: '{"type":"webauthn.get","challenge":"RPSie-6qvzOOC6N6LVxzAW1y8_NGLlku4hOWDEEPL7M","origin":"http://localhost:8081"}',
            challengeIndex: 23,
            typeIndex: 1,
            r: 87070780048049564128261020234231055847291972353486035926385077028770276517563,
            s: 33108861173107666143707192040629126170716015320338451680773098959699683514241
        });

        bool isValid = WebAuthn.verify(abi.encode(genReplaySafeHash), false, auth, x, y);

        require(isValid == true, "invalid webauthn");

        // nexst step is to call `isValidSignature` on the deployed account
        deploy.isValidSignature(digest, signature);
    }
}
