// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BridgeBaseTest.t.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "../contracts/interfaces/ISuiBridge.sol";
import "./mocks/MockSuiBridgeV2.sol";

contract SuiBridgeTest is BridgeBaseTest, ISuiBridge {
    // This function is called before each unit test
    function setUp() public {
        setUpBridgeTest();
    }

    function testSuiBridgeInitialization() public {
        assertEq(address(bridge.committee()), address(committee));
        assertEq(address(bridge.vault()), address(vault));
        assertEq(address(bridge.wETH()), wETH);
    }

    function testTransferBridgedTokensWithSignaturesTokenDailyLimitExceeded() public {
        uint8 senderAddressLength = 32;
        bytes memory senderAddress = abi.encode(0);
        uint8 targetChain = chainID;
        uint8 recipientAddressLength = 20;
        address recipientAddress = bridgerA;
        uint8 tokenID = BridgeMessage.ETH;
        uint64 amount = 100000000000000;
        bytes memory payload = abi.encodePacked(
            senderAddressLength,
            senderAddress,
            targetChain,
            recipientAddressLength,
            recipientAddress,
            tokenID,
            amount
        );

        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: 0,
            payload: payload
        });

        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        vm.expectRevert(bytes("SuiBridge: Amount exceeds bridge limit"));
        bridge.transferBridgedTokensWithSignatures(signatures, message);
    }

    function testTransferBridgedTokensWithSignaturesInvalidTargetChain() public {
        uint8 senderAddressLength = 32;
        bytes memory senderAddress = abi.encode(0);
        uint8 targetChain = 0;
        uint8 recipientAddressLength = 20;
        address recipientAddress = bridgerA;
        uint8 tokenID = BridgeMessage.ETH;
        uint64 amount = 10000;
        bytes memory payload = abi.encodePacked(
            senderAddressLength,
            senderAddress,
            targetChain,
            recipientAddressLength,
            recipientAddress,
            tokenID,
            amount
        );

        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: 1,
            payload: payload
        });

        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        vm.expectRevert(bytes("SuiBridge: Target chain not supported"));
        bridge.transferBridgedTokensWithSignatures(signatures, message);
    }

    function testTransferBridgedTokensWithSignaturesInsufficientStakeAmount() public {
        // Create transfer message
        BridgeMessage.TokenTransferPayload memory payload = BridgeMessage.TokenTransferPayload({
            senderAddressLength: 0,
            senderAddress: abi.encode(0),
            targetChain: 1,
            recipientAddressLength: 0,
            recipientAddress: bridgerA,
            tokenID: BridgeMessage.ETH,
            // This is Sui amount (eth decimal 8)
            amount: 100_000_000
        });
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: abi.encode(payload)
        });
        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        vm.expectRevert(bytes("BridgeCommittee: Insufficient stake amount"));
        bridge.transferBridgedTokensWithSignatures(signatures, message);
    }

    function testTransferBridgedTokensWithSignaturesMessageDoesNotMatchType() public {
        // Create transfer message
        BridgeMessage.TokenTransferPayload memory payload = BridgeMessage.TokenTransferPayload({
            senderAddressLength: 0,
            senderAddress: abi.encode(0),
            targetChain: 1,
            recipientAddressLength: 0,
            recipientAddress: bridgerA,
            tokenID: BridgeMessage.ETH,
            // This is Sui amount (eth decimal 8)
            amount: 100_000_000
        });
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.EMERGENCY_OP,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: abi.encode(payload)
        });
        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        vm.expectRevert(bytes("MessageVerifier: message does not match type"));
        bridge.transferBridgedTokensWithSignatures(signatures, message);
    }

    function testTransferWETHWithValidSignatures() public {
        // Fill vault with WETH
        changePrank(deployer);
        IWETH9(wETH).deposit{value: 10 ether}();
        // IWETH9(wETH).withdraw(1 ether);
        IERC20(wETH).transfer(address(vault), 10 ether);
        // Create transfer payload
        uint8 senderAddressLength = 32;
        bytes memory senderAddress = abi.encode(0);
        uint8 targetChain = chainID;
        uint8 recipientAddressLength = 20;
        address recipientAddress = bridgerA;
        uint8 tokenID = BridgeMessage.ETH;
        uint64 amount = 100000000; // 1 ether in sui decimals
        bytes memory payload = abi.encodePacked(
            senderAddressLength,
            senderAddress,
            targetChain,
            recipientAddressLength,
            recipientAddress,
            tokenID,
            amount
        );

        // Create transfer message
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: 0,
            payload: payload
        });

        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);

        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);

        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        uint256 aBalance = bridgerA.balance;
        bridge.transferBridgedTokensWithSignatures(signatures, message);
        assertEq(bridgerA.balance, aBalance + 1 ether);

        vm.expectRevert(bytes("SuiBridge: Message already processed"));
        bridge.transferBridgedTokensWithSignatures(signatures, message);
    }

    function testTransferUSDCWithValidSignatures() public {
        // Fill vault with USDC
        changePrank(USDCWhale);
        IERC20(USDC).transfer(address(vault), 100_000_000);
        changePrank(deployer);

        // Create transfer payload
        uint8 senderAddressLength = 32;
        bytes memory senderAddress = abi.encode(0);
        uint8 targetChain = chainID;
        uint8 recipientAddressLength = 20;
        address recipientAddress = bridgerA;
        uint8 tokenID = BridgeMessage.USDC;
        uint64 amount = 1_000_000;
        bytes memory payload = abi.encodePacked(
            senderAddressLength,
            senderAddress,
            targetChain,
            recipientAddressLength,
            recipientAddress,
            tokenID,
            amount
        );

        // Create transfer message
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: 0,
            payload: payload
        });

        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);

        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        assert(IERC20(USDC).balanceOf(bridgerA) == 0);
        bridge.transferBridgedTokensWithSignatures(signatures, message);
        assert(IERC20(USDC).balanceOf(bridgerA) == 1_000_000);
    }

    function testExecuteEmergencyOpWithSignaturesInvalidOpCode() public {
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: hex"02"
        });
        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        vm.expectRevert(bytes("BridgeMessage: Invalid op code"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);
    }

    function testExecuteEmergencyOpWithSignaturesInvalidNonce() public {
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.EMERGENCY_OP,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: bytes(hex"00")
        });
        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        vm.expectRevert(bytes("MessageVerifier: Invalid nonce"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);
    }

    function testExecuteEmergencyOpWithSignaturesMessageDoesNotMatchType() public {
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.TOKEN_TRANSFER,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: abi.encode(0)
        });
        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        vm.expectRevert(bytes("MessageVerifier: message does not match type"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);
    }

    function testExecuteEmergencyOpWithSignaturesInvalidSignatures() public {
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: bytes(hex"01")
        });
        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        vm.expectRevert(bytes("BridgeCommittee: Insufficient stake amount"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);
    }

    function testFreezeBridgeEmergencyOp() public {
        // Create emergency op message
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: bytes(hex"00")
        });

        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);

        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        assertFalse(bridge.paused());
        bridge.executeEmergencyOpWithSignatures(signatures, message);
        assertTrue(bridge.paused());
    }

    function testUnfreezeBridgeEmergencyOp() public {
        testFreezeBridgeEmergencyOp();
        // Create emergency op message
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.EMERGENCY_OP,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: bytes(hex"01")
        });

        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);

        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        bridge.executeEmergencyOpWithSignatures(signatures, message);
        assertFalse(bridge.paused());
    }

    function testBridgeERC20UnsupportedToken() public {
        vm.expectRevert(bytes("SuiBridge: Unsupported token"));
        bridge.bridgeERC20(255, 1 ether, abi.encode("suiAddress"), 0);
    }

    function testBridgeERC20InsufficientAllowance() public {
        vm.expectRevert(bytes("SuiBridge: Insufficient allowance"));
        bridge.bridgeERC20(BridgeMessage.ETH, type(uint256).max, abi.encode("suiAddress"), 0);
    }

    function testBridgeWETH() public {
        changePrank(deployer);
        IWETH9(wETH).deposit{value: 10 ether}();
        IERC20(wETH).approve(address(bridge), 10 ether);
        assertEq(IERC20(wETH).balanceOf(address(vault)), 0);
        uint256 balance = IERC20(wETH).balanceOf(deployer);

        // assert emitted event
        vm.expectEmit(true, true, true, false);
        emit TokensDeposited(
            chainID,
            0, // nonce
            0, // destination chain id
            BridgeMessage.ETH,
            1_00_000_000, // 1 ether
            deployer,
            abi.encode("suiAddress")
        );

        bridge.bridgeERC20(BridgeMessage.ETH, 1 ether, abi.encode("suiAddress"), 0);
        assertEq(IERC20(wETH).balanceOf(address(vault)), 1 ether);
        assertEq(IERC20(wETH).balanceOf(deployer), balance - 1 ether);
        assertEq(bridge.nonces(BridgeMessage.TOKEN_TRANSFER), 1);

        // Now test rounding. For ETH, the last 10 digits are rounded
        vm.expectEmit(true, true, true, false);
        emit TokensDeposited(
            chainID,
            1, // nonce
            0, // destination chain id
            BridgeMessage.ETH,
            2.00000001 ether,
            deployer,
            abi.encode("suiAddress")
        );
        // 2_000_000_011_000_000_888 is rounded to 2.00000001 eth
        bridge.bridgeERC20(
            BridgeMessage.ETH, 2_000_000_011_000_000_888, abi.encode("suiAddress"), 0
        );
        assertEq(IERC20(wETH).balanceOf(address(vault)), 3_000_000_011_000_000_888);
        assertEq(IERC20(wETH).balanceOf(deployer), balance - 3_000_000_011_000_000_888);
        assertEq(bridge.nonces(BridgeMessage.TOKEN_TRANSFER), 2);
    }

    function testBridgeUSDC() public {
        // TODO test and make sure adjusted amount in event is correct
    }

    function testBridgeUSDT() public {
        // TODO test and make sure adjusted amount in event is correct
    }

    function testBridgeBTC() public {
        // TODO test and make sure adjusted amount in event is correct
    }

    function testBridgeEth() public {
        changePrank(deployer);
        assertEq(IERC20(wETH).balanceOf(address(vault)), 0);
        uint256 balance = deployer.balance;

        // assert emitted event
        vm.expectEmit(true, true, true, false);
        emit ISuiBridge.TokensDeposited(
            chainID,
            0, // nonce
            0, // destination chain id
            BridgeMessage.ETH,
            1_000_000_00, // 1 ether
            deployer,
            abi.encode("suiAddress")
        );

        bridge.bridgeETH{value: 1 ether}(abi.encode("suiAddress"), 0);
        assertEq(IERC20(wETH).balanceOf(address(vault)), 1 ether);
        assertEq(deployer.balance, balance - 1 ether);
        assertEq(bridge.nonces(BridgeMessage.TOKEN_TRANSFER), 1);
    }

    // TESTS FOR GAS MEASUREMENT

    // function testTransferBridgedTokensWith7Signatures() public {
    //     // define committee with 50 members
    //     address[] memory _committee = new address[](56);
    //     uint256[] memory pks = new uint256[](56);
    //     uint16[] memory _stake = new uint16[](56);
    //     for (uint256 i = 0; i < 56; i++) {
    //         string memory name = string(abi.encodePacked("committeeMember", i));
    //         (address member, uint256 pk) = makeAddrAndKey(name);
    //         _committee[i] = member;
    //         pks[i] = pk;
    //         // 1 member with 2500 stake
    //         if (i == 55) {
    //             _stake[i] = 2500;
    //             // 50 members with 100 stake (total: 5000)
    //         } else if (i < 50) {
    //             _stake[i] = 100;
    //             // 5 members with 500 stake (total: 2500)
    //         } else {
    //             _stake[i] = 500;
    //         }
    //     }
    //     committee = new BridgeCommittee();
    //     committee.initialize(address(config), _committee, _stake, minStakeRequired);
    //     uint256[] memory tokenPrices = new uint256[](4);
    //     tokenPrices[0] = 10000; // SUI PRICE
    //     tokenPrices[1] = 10000; // BTC PRICE
    //     tokenPrices[2] = 10000; // ETH PRICE
    //     tokenPrices[3] = 10000; // USDC PRICE
    //     uint64[] memory totalLimits = new uint64[](1);
    //     totalLimits[0] = 1000000;
    //     skip(2 days);
    //     SuiBridge _bridge = new SuiBridge();
    //     _bridge.initialize(address(committee), address(vault), address(limiter), wETH);
    //     changePrank(address(bridge));
    //     limiter.transferOwnership(address(_bridge));
    //     vault.transferOwnership(address(_bridge));
    //     bridge = _bridge;

    //     // Fill vault with WETH
    //     changePrank(deployer);
    //     IWETH9(wETH).deposit{value: 10 ether}();
    //     IERC20(wETH).transfer(address(vault), 10 ether);

    //     // transfer bridged tokens with 7 signatures
    //     // Create transfer payload
    //     uint8 senderAddressLength = 32;
    //     bytes memory senderAddress = abi.encode(0);
    //     uint8 targetChain = chainID;
    //     uint8 recipientAddressLength = 20;
    //     address recipientAddress = bridgerA;
    //     uint8 tokenID = BridgeMessage.ETH;
    //     uint64 amount = 100000000; // 1 ether in sui decimals
    //     bytes memory payload = abi.encodePacked(
    //         senderAddressLength,
    //         senderAddress,
    //         targetChain,
    //         recipientAddressLength,
    //         recipientAddress,
    //         tokenID,
    //         amount
    //     );

    //     // Create transfer message
    //     BridgeMessage.Message memory message = BridgeMessage.Message({
    //         messageType: BridgeMessage.TOKEN_TRANSFER,
    //         version: 1,
    //         nonce: 1,
    //         chainID: 0,
    //         payload: payload
    //     });

    //     bytes memory encodedMessage = BridgeMessage.encodeMessage(message);

    //     bytes32 messageHash = keccak256(encodedMessage);

    //     bytes[] memory signatures = new bytes[](7);

    //     uint8 index;
    //     for (uint256 i = 50; i < 55; i++) {
    //         signatures[index++] = getSignature(messageHash, pks[i]);
    //     }
    //     signatures[5] = getSignature(messageHash, pks[55]);
    //     signatures[6] = getSignature(messageHash, pks[0]);

    //     bridge.transferBridgedTokensWithSignatures(signatures, message);
    // }

    // function testTransferBridgedTokensWith26Signatures() public {
    //     // define committee with 50 members
    //     address[] memory _committee = new address[](56);
    //     uint256[] memory pks = new uint256[](56);
    //     uint16[] memory _stake = new uint16[](56);
    //     for (uint256 i = 0; i < 56; i++) {
    //         string memory name = string(abi.encodePacked("committeeMember", i));
    //         (address member, uint256 pk) = makeAddrAndKey(name);
    //         _committee[i] = member;
    //         pks[i] = pk;
    //         // 1 member with 2500 stake
    //         if (i == 55) {
    //             _stake[i] = 2500;
    //             // 50 members with 100 stake (total: 5000)
    //         } else if (i < 50) {
    //             _stake[i] = 100;
    //             // 5 members with 500 stake (total: 2500)
    //         } else {
    //             _stake[i] = 500;
    //         }
    //     }
    //     committee = new BridgeCommittee();
    //     committee.initialize(address(config), _committee, _stake, minStakeRequired);
    //     uint256[] memory tokenPrices = new uint256[](4);
    //     tokenPrices[0] = 10000; // SUI PRICE
    //     tokenPrices[1] = 10000; // BTC PRICE
    //     tokenPrices[2] = 10000; // ETH PRICE
    //     tokenPrices[3] = 10000; // USDC PRICE
    //     uint64[] memory totalLimits = new uint64[](1);
    //     totalLimits[0] = 1000000;
    //     skip(2 days);
    //     SuiBridge _bridge = new SuiBridge();
    //     _bridge.initialize(address(committee), address(vault), address(limiter), wETH);
    //     changePrank(address(bridge));
    //     limiter.transferOwnership(address(_bridge));
    //     vault.transferOwnership(address(_bridge));
    //     bridge = _bridge;

    //     // Fill vault with WETH
    //     changePrank(deployer);
    //     IWETH9(wETH).deposit{value: 10 ether}();
    //     IERC20(wETH).transfer(address(vault), 10 ether);

    //     // transfer bridged tokens with 26 signatures

    //     // Create transfer payload
    //     uint8 senderAddressLength = 32;
    //     bytes memory senderAddress = abi.encode(0);
    //     uint8 targetChain = chainID;
    //     uint8 recipientAddressLength = 20;
    //     address recipientAddress = bridgerA;
    //     uint8 tokenID = BridgeMessage.ETH;
    //     uint64 amount = 100000000; // 1 ether in sui decimals
    //     bytes memory payload = abi.encodePacked(
    //         senderAddressLength,
    //         senderAddress,
    //         targetChain,
    //         recipientAddressLength,
    //         recipientAddress,
    //         tokenID,
    //         amount
    //     );

    //     // Create transfer message
    //     BridgeMessage.Message memory message = BridgeMessage.Message({
    //         messageType: BridgeMessage.TOKEN_TRANSFER,
    //         version: 1,
    //         nonce: 2,
    //         chainID: 0,
    //         payload: payload
    //     });

    //     bytes memory encodedMessage = BridgeMessage.encodeMessage(message);

    //     bytes32 messageHash = keccak256(encodedMessage);

    //     bytes[] memory signatures = new bytes[](25);

    //     uint256 index = 0;
    //     // add 5 committee members with 100 stake
    //     for (uint256 i = 50; i < 55; i++) {
    //         signatures[index++] = getSignature(messageHash, pks[i]);
    //     }
    //     // add last committee member with 2500 stake
    //     signatures[5] = getSignature(messageHash, pks[55]);

    //     // add 20 committee members with 100 stake
    //     for (uint256 i = 0; i < 20; i++) {
    //         signatures[index++] = getSignature(messageHash, pks[i]);
    //     }

    //     bridge.transferBridgedTokensWithSignatures(signatures, message);
    // }

    // function testTransferBridgedTokensWith56Signatures() public {
    //     // define committee with 50 members
    //     address[] memory _committee = new address[](56);
    //     uint256[] memory pks = new uint256[](56);
    //     uint16[] memory _stake = new uint16[](56);
    //     for (uint256 i = 0; i < 56; i++) {
    //         string memory name = string(abi.encodePacked("committeeMember", i));
    //         (address member, uint256 pk) = makeAddrAndKey(name);
    //         _committee[i] = member;
    //         pks[i] = pk;
    //         // 1 member with 2500 stake
    //         if (i == 55) {
    //             _stake[i] = 2500;
    //             // 50 members with 100 stake (total: 5000)
    //         } else if (i < 50) {
    //             _stake[i] = 100;
    //             // 5 members with 500 stake (total: 2500)
    //         } else {
    //             _stake[i] = 500;
    //         }
    //     }
    //     committee = new BridgeCommittee();
    //     committee.initialize(address(config), _committee, _stake, minStakeRequired);
    //     uint256[] memory tokenPrices = new uint256[](4);
    //     tokenPrices[0] = 10000; // SUI PRICE
    //     tokenPrices[1] = 10000; // BTC PRICE
    //     tokenPrices[2] = 10000; // ETH PRICE
    //     tokenPrices[3] = 10000; // USDC PRICE
    //     uint64[] memory totalLimits = new uint64[](1);
    //     totalLimits[0] = 1000000;
    //     skip(2 days);
    //     SuiBridge _bridge = new SuiBridge();
    //     _bridge.initialize(address(committee), address(vault), address(limiter), wETH);
    //     changePrank(address(bridge));
    //     limiter.transferOwnership(address(_bridge));
    //     vault.transferOwnership(address(_bridge));
    //     bridge = _bridge;

    //     // Fill vault with WETH
    //     changePrank(deployer);
    //     IWETH9(wETH).deposit{value: 10 ether}();
    //     IERC20(wETH).transfer(address(vault), 10 ether);

    //     // transfer bridged tokens with 56 signatures

    //     // Create transfer payload
    //     uint8 senderAddressLength = 32;
    //     bytes memory senderAddress = abi.encode(0);
    //     uint8 targetChain = chainID;
    //     uint8 recipientAddressLength = 20;
    //     address recipientAddress = bridgerA;
    //     uint8 tokenID = BridgeMessage.ETH;
    //     uint64 amount = 100000000; // 1 ether in sui decimals
    //     bytes memory payload = abi.encodePacked(
    //         senderAddressLength,
    //         senderAddress,
    //         targetChain,
    //         recipientAddressLength,
    //         recipientAddress,
    //         tokenID,
    //         amount
    //     );

    //     // Create transfer message
    //     BridgeMessage.Message memory message = BridgeMessage.Message({
    //         messageType: BridgeMessage.TOKEN_TRANSFER,
    //         version: 1,
    //         nonce: 3,
    //         chainID: 0,
    //         payload: payload
    //     });

    //     bytes memory encodedMessage = BridgeMessage.encodeMessage(message);

    //     bytes32 messageHash = keccak256(encodedMessage);

    //     bytes[] memory signatures = new bytes[](56);

    //     // get all signatures
    //     for (uint256 i = 0; i < 56; i++) {
    //         signatures[i] = getSignature(messageHash, pks[i]);
    //     }

    //     bridge.transferBridgedTokensWithSignatures(signatures, message);
    // }

    // An e2e token transfer regression test covering message ser/de and signature verification
    function testTransferSuiToEthRegressionTest() public {
        address[] memory _committee = new address[](4);
        uint16[] memory _stake = new uint16[](4);
        _committee[0] = 0x68B43fD906C0B8F024a18C56e06744F7c6157c65;
        _committee[1] = 0xaCAEf39832CB995c4E049437A3E2eC6a7bad1Ab5;
        _committee[2] = 0x8061f127910e8eF56F16a2C411220BaD25D61444;
        _committee[3] = 0x508F3F1ff45F4ca3D8e86CDCC91445F00aCC59fC;
        _stake[0] = 2500;
        _stake[1] = 2500;
        _stake[2] = 2500;
        _stake[3] = 2500;
        committee = new BridgeCommittee();

        // deploy bridge config with 11 chainID
        address[] memory _supportedTokens = new address[](4);
        _supportedTokens[0] = wBTC;
        _supportedTokens[1] = wETH;
        _supportedTokens[2] = USDC;
        _supportedTokens[3] = USDT;
        uint8 supportedChainID = 1;
        uint8[] memory _supportedDestinationChains = new uint8[](1);
        _supportedDestinationChains[0] = 1;
        BridgeConfig _config = new BridgeConfig(11, _supportedTokens, _supportedDestinationChains);

        committee.initialize(address(_config), _committee, _stake, minStakeRequired);
        vault = new BridgeVault(wETH);
        uint256[] memory tokenPrices = new uint256[](4);
        tokenPrices[0] = 10000; // SUI PRICE
        tokenPrices[1] = 10000; // BTC PRICE
        tokenPrices[2] = 10000; // ETH PRICE
        tokenPrices[3] = 10000; // USDC PRICE
        uint64[] memory totalLimits = new uint64[](1);
        totalLimits[0] = 1000000;

        skip(2 days);
        limiter = new BridgeLimiter();
        limiter.initialize(
            address(committee), tokenPrices, _supportedDestinationChains, totalLimits
        );
        bridge = new SuiBridge();
        bridge.initialize(address(committee), address(vault), address(limiter), wETH);
        vault.transferOwnership(address(bridge));
        limiter.transferOwnership(address(bridge));

        // Fill vault with WETH
        changePrank(deployer);
        IWETH9(wETH).deposit{value: 10 ether}();
        IERC20(wETH).transfer(address(vault), 10 ether);
        address recipientAddress = 0xb18f79Fe671db47393315fFDB377Da4Ea1B7AF96;

        bytes memory payload =
            hex"2080ab1ee086210a3a37355300ca24672e81062fcdb5ced6618dab203f6a3b291c0b14b18f79fe671db47393315ffdb377da4ea1b7af960200000000000186a0";
        // Create transfer message
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: supportedChainID,
            payload: payload
        });
        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes memory expectedEncodedMessage =
            hex"5355495f4252494447455f4d45535341474500010000000000000001012080ab1ee086210a3a37355300ca24672e81062fcdb5ced6618dab203f6a3b291c0b14b18f79fe671db47393315ffdb377da4ea1b7af960200000000000186a0";

        assertEq(encodedMessage, expectedEncodedMessage);

        bytes[] memory signatures = new bytes[](2);

        signatures[0] =
            hex"e1cf11b380855ff1d4a451ebc2fd68477cf701b7d4ec88da3082709fe95201a5061b4b60cf13815a80ba9dfead23e220506aa74c4a863ba045d95715b4cc6b6e00";
        signatures[1] =
            hex"8ba9ec92c2d5a44ecc123182f689b901a93921fd35f581354fea20b25a0ded6d055b96a64bdda77dd5a62b93d29abe93640aa3c1a136348093cd7a2418c6bfa301";

        uint256 aBalance = recipientAddress.balance;
        committee.verifySignatures(signatures, message);

        bridge.transferBridgedTokensWithSignatures(signatures, message);
        assertEq(recipientAddress.balance, aBalance + 0.001 ether);
    }

    // An e2e emergency op regression test covering message ser/de
    function testEmergencyOpRegressionTest() public {
        address[] memory _committee = new address[](4);
        uint16[] memory _stake = new uint16[](4);
        _committee[0] = 0x68B43fD906C0B8F024a18C56e06744F7c6157c65;
        _committee[1] = 0xaCAEf39832CB995c4E049437A3E2eC6a7bad1Ab5;
        _committee[2] = 0x8061f127910e8eF56F16a2C411220BaD25D61444;
        _committee[3] = 0x508F3F1ff45F4ca3D8e86CDCC91445F00aCC59fC;
        _stake[0] = 2500;
        _stake[1] = 2500;
        _stake[2] = 2500;
        _stake[3] = 2500;
        uint8 _chainID = 3;
        uint8[] memory _supportedDestinationChains = new uint8[](1);
        _supportedDestinationChains[0] = 0;
        address[] memory _supportedTokens = new address[](4);
        _supportedTokens[0] = wBTC;
        _supportedTokens[1] = wETH;
        _supportedTokens[2] = USDC;
        _supportedTokens[3] = USDT;
        config = new BridgeConfig(_chainID, _supportedTokens, _supportedDestinationChains);
        committee = new BridgeCommittee();
        committee.initialize(address(config), _committee, _stake, minStakeRequired);
        vault = new BridgeVault(wETH);
        uint256[] memory tokenPrices = new uint256[](4);
        tokenPrices[0] = 10000; // SUI PRICE
        tokenPrices[1] = 10000; // BTC PRICE
        tokenPrices[2] = 10000; // ETH PRICE
        tokenPrices[3] = 10000; // USDC PRICE
        uint64[] memory totalLimits = new uint64[](1);
        totalLimits[0] = 1000000;
        skip(2 days);
        limiter = new BridgeLimiter();
        limiter.initialize(
            address(committee), tokenPrices, _supportedDestinationChains, totalLimits
        );
        bridge = new SuiBridge();
        bridge.initialize(address(committee), address(vault), address(limiter), wETH);

        bytes memory payload = hex"00";
        // Create emergency op message
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.EMERGENCY_OP,
            version: 1,
            nonce: 55,
            chainID: _chainID,
            payload: payload
        });
        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes memory expectedEncodedMessage =
            hex"5355495f4252494447455f4d455353414745020100000000000000370300";

        assertEq(encodedMessage, expectedEncodedMessage);
    }

    // An e2e emergency op regression test covering message ser/de and signature verification
    function testEmergencyOpRegressionTestWithSigVerification() public {
        address[] memory _committee = new address[](4);
        uint16[] memory _stake = new uint16[](4);
        uint8 chainID = 11;
        _committee[0] = 0x68B43fD906C0B8F024a18C56e06744F7c6157c65;
        _committee[1] = 0xaCAEf39832CB995c4E049437A3E2eC6a7bad1Ab5;
        _committee[2] = 0x8061f127910e8eF56F16a2C411220BaD25D61444;
        _committee[3] = 0x508F3F1ff45F4ca3D8e86CDCC91445F00aCC59fC;
        _stake[0] = 2500;
        _stake[1] = 2500;
        _stake[2] = 2500;
        _stake[3] = 2500;
        config = new BridgeConfig(chainID, supportedTokens, supportedChains);
        committee = new BridgeCommittee();
        committee.initialize(address(config), _committee, _stake, minStakeRequired);
        vault = new BridgeVault(wETH);

        uint64[] memory totalLimits = new uint64[](1);
        totalLimits[0] = 1000000;

        skip(2 days);
        limiter = new BridgeLimiter();
        limiter.initialize(
            address(committee), tokenPrices, supportedChains, totalLimits
        );
        bridge = new SuiBridge();
        bridge.initialize(address(committee), address(vault), address(limiter), wETH);

        assertFalse(bridge.paused());

        // pause
        bytes memory payload = hex"00";
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });
        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes memory expectedEncodedMessage =
            hex"5355495f4252494447455f4d455353414745020100000000000000000b00";

        assertEq(encodedMessage, expectedEncodedMessage);

        bytes[] memory signatures = new bytes[](1);

        signatures[0] =
            hex"859db4dff22e43821b9b451e88bc7489aec3381d3e4fb5d8cbf025a84d34964a2bd556e0a86e13cb5b2d0fa52f08d02e4b62b9e6d9e07d8f8451d4c19430806d01";

        bridge.executeEmergencyOpWithSignatures(signatures, message);
        assertTrue(bridge.paused());

        // unpause
        payload = hex"01";
        message = BridgeMessage.Message({
            messageType: BridgeMessage.EMERGENCY_OP,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: payload
        });
        encodedMessage = BridgeMessage.encodeMessage(message);
        expectedEncodedMessage =
            hex"5355495f4252494447455f4d455353414745020100000000000000010b01";

        assertEq(encodedMessage, expectedEncodedMessage);

        bytes[] memory signatures2 = new bytes[](3);

        signatures2[0] =
            hex"de5ca964c5aa1aa323cc480cd6de46eae980a1670a5fe8e12e31f724d0bcec6516e54b516737bb6ed6ccad775370c14d46f2e10100e9d16851d2050bf2349c6401";
        signatures2[1] =
            hex"fe8006e2013eaa7b8af0e5ac9f2890c2b2bd375d343684b2604ac6acd4142ccf5c9ec1914bce53a005232ef880bf0f597eed319d41d80e92d035c8314e1198ff00";
        signatures2[2] =
            hex"f5749ac37e11f22da0622082c9e63a91dc7b5c59cfdaa86438d9f6a53bbacf6b763126f1a20a826d7dff73252cf2fd68da67b9caec4d3c24a07fbd566a7a6bec00";

        bridge.executeEmergencyOpWithSignatures(signatures2, message);
        assertFalse(bridge.paused());

        // reusing the sig from nonce 0 will revert
        payload = hex"00";
        message = BridgeMessage.Message({
            messageType: BridgeMessage.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });

        signatures = new bytes[](1);

        signatures[0] =
            hex"859db4dff22e43821b9b451e88bc7489aec3381d3e4fb5d8cbf025a84d34964a2bd556e0a86e13cb5b2d0fa52f08d02e4b62b9e6d9e07d8f8451d4c19430806d01";

        vm.expectRevert(bytes("MessageVerifier: Invalid nonce"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);

        assertFalse(bridge.paused());
    }

    // An e2e upgrade regression test covering message ser/de and signature verification
    function testUpgradeRegressionTest() public {
        address[] memory _committee = new address[](4);
        uint16[] memory _stake = new uint16[](4);
        _committee[0] = 0x68B43fD906C0B8F024a18C56e06744F7c6157c65;
        _committee[1] = 0xaCAEf39832CB995c4E049437A3E2eC6a7bad1Ab5;
        _committee[2] = 0x8061f127910e8eF56F16a2C411220BaD25D61444;
        _committee[3] = 0x508F3F1ff45F4ca3D8e86CDCC91445F00aCC59fC;
        _stake[0] = 2500;
        _stake[1] = 2500;
        _stake[2] = 2500;
        _stake[3] = 2500;
        committee = new BridgeCommittee();

        uint8 _chainID = 12;
        uint8[] memory _supportedDestinationChains = new uint8[](1);
        _supportedDestinationChains[0] = 0;
        address[] memory _supportedTokens = new address[](4);
        _supportedTokens[0] = wBTC;
        _supportedTokens[1] = wETH;
        _supportedTokens[2] = USDC;
        _supportedTokens[3] = USDT;
        config = new BridgeConfig(_chainID, _supportedTokens, _supportedDestinationChains);

        committee.initialize(address(config), _committee, _stake, minStakeRequired);
        vault = new BridgeVault(wETH);
        uint256[] memory tokenPrices = new uint256[](4);
        tokenPrices[0] = 10000; // SUI PRICE
        tokenPrices[1] = 10000; // BTC PRICE
        tokenPrices[2] = 10000; // ETH PRICE
        tokenPrices[3] = 10000; // USDC PRICE
        skip(2 days);
        uint64[] memory totalLimits = new uint64[](1);
        totalLimits[0] = 1000000;
        limiter = new BridgeLimiter();
        limiter.initialize(
            address(committee), tokenPrices, _supportedDestinationChains, totalLimits
        );
        bridge = new SuiBridge();
        bridge.initialize(address(committee), address(vault), address(limiter), wETH);
        vault.transferOwnership(address(bridge));
        limiter.transferOwnership(address(bridge));

        // Fill vault with WETH
        changePrank(deployer);
        IWETH9(wETH).deposit{value: 10 ether}();
        IERC20(wETH).transfer(address(vault), 10 ether);

        bytes memory payload =
            hex"00000000000000000000000006060606060606060606060606060606060606060000000000000000000000000909090909090909090909090909090909090909000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000045cd8a76b00000000000000000000000000000000000000000000000000000000";
        // Create transfer message
        BridgeMessage.Message memory message = BridgeMessage.Message({
            messageType: BridgeMessage.UPGRADE,
            version: 1,
            nonce: 123,
            chainID: _chainID,
            payload: payload
        });
        bytes memory encodedMessage = BridgeMessage.encodeMessage(message);
        bytes memory expectedEncodedMessage =
            hex"5355495f4252494447455f4d4553534147450501000000000000007b0c00000000000000000000000006060606060606060606060606060606060606060000000000000000000000000909090909090909090909090909090909090909000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000045cd8a76b00000000000000000000000000000000000000000000000000000000";

        assertEq(encodedMessage, expectedEncodedMessage);

        (address proxy, address newImp, bytes memory _calldata) =
            BridgeMessage.decodeUpgradePayload(payload);

        assertEq(proxy, address(0x0606060606060606060606060606060606060606));
        assertEq(newImp, address(0x0909090909090909090909090909090909090909));
        assertEq(_calldata, hex"5cd8a76b");
    }
}
