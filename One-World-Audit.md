# My Audit of the -One-World project whose source code is: https://github.com/Cyfrin/2024-11-one-world  
# Project - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)

- ## Medium Risk Findings
    - ### [M-01. Function MembershipERC1155::mint is susceptible to reentrance manipulation when it calls onERC1155Received()](#M-01)
- ## Low Risk Findings
    - ### [L-01. Function MembershipERC1155::initialize() is missing onlyInitializing modifier thus limiting future inheritance.](#L-01)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: One World

### Dates: Nov 6th, 2024 - Nov 13th, 2024

[See more contest details here](https://codehawks.cyfrin.io/c/2024-11-one-world)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 0
- Medium: 1
- Low: 1



    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Function MembershipERC1155::mint is susceptible to reentrance manipulation when it calls onERC1155Received()            



## Summary

The mint function inherits and uses `ERC1155Upgradeable::_mint()` which has a protection against zero address calls, however, it requires that if the caller is  a smart contract, it must implement {IERC1155Receiver-onERC1155Received}.  In that external call and inside the `onERC1155Received()`,  reentrance attack can be introduced. Below are mint() code as well as ERC1155Upgradeable::\_mint()

## Vulnerability Details

reentrance attack can be used when mint() calls to verify that "to" address is smart contract and inside the `onERC1155Received()`. This happened in the documented attack against "HypeBears NFT contract".

<https://blocksecteam.medium.com/when-safemint-becomes-unsafe-lessons-from-the-hypebears-security-incident-2965209bda2a>

Can also be problem of future exploitation of same external call(`onERC1155Received()`).

Note: The access control on the mint() can't help against this since, this is mint() legitimately calling external contract to verify address as stated above.

```Solidity
/// @notice Mint a new token
    /// @param to The address to mint tokens to
    /// @param tokenId The token ID to mint
    /// @param amount The amount of tokens to mint
    function mint(address to, uint256 tokenId, uint256 amount) external override onlyRole(OWP_FACTORY_ROLE) {
        totalSupply += amount * 2 ** (6 - tokenId); // Update total supply with weight
        _mint(to, tokenId, amount, "");
    }


https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/token/ERC1155/ERC1155Upgradeable.sol	

/**
     * @dev Creates a `value` amount of tokens of type `id`, and assigns them to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function _mint(address to, uint256 id, uint256 value, bytes memory data) internal {
        if (to == address(0)) {
            revert ERC1155InvalidReceiver(address(0));
        }
        (uint256[] memory ids, uint256[] memory values) = _asSingletonArrays(id, value);
        _updateWithAcceptanceCheck(address(0), to, ids, values, data);
    }

	

```

## Impact

Manipulation of mint logic and future issues that can be introduced by reentrance attack() as the case linked above.
For example an attacker can setup his/her  onERC1155Received() function and include logic to manipulate / call back the contract as below.

```Solidity
 function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
    ox233fddi799dfdfdfdf.0x6444455(raw data); //address.mintAddress(raw data)
        return this.onERC1155Received.selector;
    }
```

## Tools Used

Manual review

## Recommendations

Add reentrance guard modifier on mint or add additional if condition. 

Inherit from ReentrancyGuard, then use nonReentrant modifier on mint() function.


# Low Risk Findings

## <a id='L-01'></a>L-01. Function MembershipERC1155::initialize() is missing onlyInitializing modifier thus limiting future inheritance.            



## Summary

Function `MembershipERC1155::initialize`() uses the *initializer* modifier which can only be called once, even when using inheritance ( as per OZ docs -see below link). This limits contracts that want extend/inherit from it inlcuding future upgrades by owner or others. Its recommended that parent contracts should use the onlyInitializing modifier.

From the OZ docs: per OZ docs: <https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable>

> Another difference between a `constructor` and a regular function is that Solidity takes care of automatically invoking the constructors of all ancestors of a contract. When writing an initializer, you need to take special care to manually call the initializers of all parent contracts. Note that the `initializer` modifier can only be called once even when using inheritance, so parent contracts should use the `onlyInitializing` modifier:

If the contract *MembershipERC1155* was meant to be not extendible, then it should have used **abstract** keyword/modifier as such.

## Vulnerability Details

Snippets below show the function \[`MembershipERC1155::initialize()` ] which is missing the *onlyInitializing* modifier.

```Solidity
function initialize(
        string memory name_,
        string memory symbol_,
        string memory uri_,
        address creator_,
        address currency_
    ) external initializer {
        _name = name_;
        _symbol = symbol_;
        creator = creator_;
        currency = currency_;
        _setURI(uri_);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DAO_CREATOR, creator_);
        _grantRole(OWP_FACTORY_ROLE, msg.sender);
    }
```

## Impact

This limits future inheritance  inlcuding future upgrades by owner or others. If there is ever a need to  extend/inherit this contract for any reason, then those inheriting can't make use of OpenZeppelin Upgrades and initializer or \_disableInitializers()  capabilities  (docs link in summary).  Also, If the contract *MembershipERC1155* was meant to be not inheritable, then it should have used \*\*abstract keyword/modifier \*\*as such.

## Tools Used

Manual review.

## Recommendations

Add the correct modifier. Snippets below show the function \[`MembershipERC1155::initialize`() ] with the correct *onlyInitializing* modifier.

```Solidity
function initialize(
        string memory name_,
        string memory symbol_,
        string memory uri_,
        address creator_,
        address currency_
    ) external  onlyInitializing {
        _name = name_;
        _symbol = symbol_;
        creator = creator_;
        currency = currency_;
        _setURI(uri_);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DAO_CREATOR, creator_);
        _grantRole(OWP_FACTORY_ROLE, msg.sender);
    }
```



