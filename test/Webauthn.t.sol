// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Counter} from "../src/Counter.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

contract WebAuthnTest is Test {

    uint256[2] pubKey = [
        3305928622425856744352843582162251482220859276426393803749818581027740414165,
        72769490441581222652029243776681931147458015896971649613894794235112580521314
    ];
    uint256 r = 12643522219387179356909003300968974447268897629027673757099845396776034286995;
    uint256 s = 50975385794640995967722680236368715834413946075113511164504246349777408356743;    







    function test_webauthn_coinbase_static() public {
        string memory clientDataJSON =
            '{"type":"webauthn.get","challenge":"KcJTk1RRndUBFFyH24ZKrbpzzazeBC6GDrNQWnBO1Y4","origin":"http://localhost:8081"}';
        bytes memory challenge = hex"29c2539354519dd501145c87db864aadba73cdacde042e860eb3505a704ed58e";

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631900000000",
            clientDataJSON: clientDataJSON,
            challengeIndex: 23,
            typeIndex: 1,
            r: r,
            s: s
        });        
        assertTrue(WebAuthn.verify(challenge, false, auth, pubKey[0], pubKey[1]));        
    }
}
