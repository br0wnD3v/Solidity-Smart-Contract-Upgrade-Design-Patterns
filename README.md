# Solidity Smart Contract Upgrade Design Patterns

---

# Proxy Pattern Family

## Transparent Proxy Pattern

Uses an admin address to determine if a call should go to the proxy itself or be delegated
Implemented widely in OpenZeppelin's TransparentUpgradeableProxy
Prevents function selector clashes through admin address checks

### Custom Implementation

```solidity
contract Logic {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}

// Proxy contract
contract TransparentProxy {
    address public admin;
    address public implementation;
    mapping(bytes4 => bool) public adminFunctions;

    constructor(address _implementation) {
        admin = msg.sender;
        implementation = _implementation;
        // Admin functions selectors
        adminFunctions[bytes4(keccak256("upgradeTo(address)"))] = true;
    }

    function upgradeTo(address _newImplementation) public {
        require(msg.sender == admin, "Only admin");
        implementation = _newImplementation;
    }

    fallback() external payable {
        // If admin is calling a non-admin function, delegate to implementation
        // If non-admin is calling, always delegate to implementation
        if (msg.sender == admin && adminFunctions[msg.sig]) {
            (bool success, ) = address(this).call(msg.data);
            require(success, "Admin function failed");
        } else {
            // Delegate call to implementation
            (bool success, bytes memory data) = implementation.delegatecall(msg.data);
            require(success, "Delegatecall failed");

            assembly {
                return(add(data, 32), mload(data))
            }
        }
    }
}
```

### OpenZeppelin Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

// Implementation contract
contract LogicV1 {
    uint256 public value;

    // Note: no constructor - use initializer instead
    function initialize() public {
        value = 42;
    }

    function setValue(uint256 _value) public {
        value = _value;
    }
}

// Deployment script (not part of contracts)
/*
1. Deploy LogicV1
2. Deploy ProxyAdmin
3. Deploy TransparentUpgradeableProxy with parameters:
   - implementation: address of LogicV1
   - admin: address of ProxyAdmin
   - data: abi.encodeWithSignature("initialize()")
*/
```

## UUPS (Universal Upgradeable Proxy Standard)

Moves upgrade logic to the implementation contract
Reduces proxy deployment gas costs
Implementation must include self-destruct or upgrade logic
Standardized in EIP-1822

### Custom Implementation

```solidity
contract UUPSImplementation {
    address public implementation;
    address public owner;
    uint256 public value;

    // Storage slot used by ERC-1967
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function initialize() public {
        require(owner == address(0), "Already initialized");
        owner = msg.sender;
    }

    function setValue(uint256 _value) public {
        value = _value;
    }

    function _getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
    }

    function _setImplementation(address newImplementation) internal {
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
    }

    function upgradeTo(address newImplementation) public onlyOwner {
        _setImplementation(newImplementation);
    }
}

// Proxy contract (minimal)
contract UUPSProxy {
    // Storage slot used by ERC-1967
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address _implementation, bytes memory _data) {
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = _implementation;
        (bool success, ) = _implementation.delegatecall(_data);
        require(success, "Initialization failed");
    }

    fallback() external payable {
        address implementation = StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// Helper library for storage slots
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly {
            r.slot := slot
        }
    }
}
```

### OpenZeppelin Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

// Implementation contract
contract UUPSLogicV1 is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public value;

    function initialize() public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        value = 42;
    }

    function setValue(uint256 _value) public {
        value = _value;
    }

    // Required override for UUPS
    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// The proxy is ERC1967Proxy from OpenZeppelin
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Deployment script (not part of contracts)
/*
1. Deploy UUPSLogicV1
2. Deploy ERC1967Proxy with parameters:
   - implementation: address of UUPSLogicV1
   - data: abi.encodeWithSignature("initialize()")
*/
```

## Beacon Proxy Pattern

Uses a central Beacon contract that stores the current implementation address
Multiple proxies can point to a single Beacon
Allows upgrading many contracts at once by changing one address
Useful for deploying many instances of the same contract

### Custom Implementation

```solidity
// Beacon contract
contract UpgradeableBeacon {
    address public owner;
    address public implementation;

    constructor(address _implementation) {
        owner = msg.sender;
        implementation = _implementation;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function upgradeTo(address newImplementation) public onlyOwner {
        implementation = newImplementation;
    }
}

// Beacon Proxy
contract BeaconProxy {
    address public beacon;

    constructor(address _beacon, bytes memory _data) {
        beacon = _beacon;

        // Initialize if data provided
        if(_data.length > 0) {
            address impl = UpgradeableBeacon(beacon).implementation();
            (bool success, ) = impl.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    fallback() external payable {
        address impl = UpgradeableBeacon(beacon).implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// Implementation contract
contract BeaconImplementation {
    uint256 public value;

    function initialize() public {
        value = 42;
    }

    function setValue(uint256 _value) public {
        value = _value;
    }
}
```

### OpenZeppelin Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

// Implementation contract
contract BeaconImplementationOZ is Initializable {
    uint256 public value;

    function initialize() public initializer {
        value = 42;
    }

    function setValue(uint256 _value) public {
        value = _value;
    }
}

// Deployment script (not part of contracts)
/*
1. Deploy BeaconImplementationOZ
2. Deploy UpgradeableBeacon with BeaconImplementationOZ address
3. Deploy multiple BeaconProxy instances with:
   - beacon: address of UpgradeableBeacon
   - data: abi.encodeWithSignature("initialize()")
*/
```

## Diamond Pattern (EIP-2535)

Allows multiple implementation contracts (facets)
Supports partial upgrades of specific functionalities
Uses a diamond cut function for adding, replacing, or removing facets
Solves the 24KB contract size limitation
Provides fine-grained access control over functions

### Custom Implementation

```solidity
// Diamond contract
contract Diamond {
    // Diamond storage position
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.storage");

    struct FacetAddressAndPosition {
        address facetAddress;
        uint16 functionSelectorPosition;
    }

    struct DiamondStorage {
        mapping(bytes4 => FacetAddressAndPosition) facetAddressAndPosition;
        bytes4[] functionSelectors;
        address owner;
    }

    event DiamondCut(address facet, bytes4[] selectors, uint8 action);

    // Actions for diamond cut
    uint8 constant ADD = 0;
    uint8 constant REPLACE = 1;
    uint8 constant REMOVE = 2;

    // Return DiamondStorage
    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    constructor() {
        DiamondStorage storage ds = diamondStorage();
        ds.owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == diamondStorage().owner, "Not owner");
        _;
    }

    // Add/replace/remove facet function selectors
    function diamondCut(
        address _facet,
        bytes4[] memory _selectors,
        uint8 _action
    ) public onlyOwner {
        DiamondStorage storage ds = diamondStorage();

        if(_action == ADD) {
            require(_facet != address(0), "Facet is zero address");
            for(uint i = 0; i < _selectors.length; i++) {
                bytes4 selector = _selectors[i];
                ds.facetAddressAndPosition[selector] = FacetAddressAndPosition(
                    _facet,
                    uint16(ds.functionSelectors.length)
                );
                ds.functionSelectors.push(selector);
            }
        } else if(_action == REPLACE) {
            require(_facet != address(0), "Facet is zero address");
            for(uint i = 0; i < _selectors.length; i++) {
                bytes4 selector = _selectors[i];
                ds.facetAddressAndPosition[selector].facetAddress = _facet;
            }
        } else if(_action == REMOVE) {
            for(uint i = 0; i < _selectors.length; i++) {
                bytes4 selector = _selectors[i];
                uint16 selectorPosition = ds.facetAddressAndPosition[selector].functionSelectorPosition;

                // Replace selector with last one and delete last one
                if(selectorPosition != ds.functionSelectors.length - 1) {
                    bytes4 lastSelector = ds.functionSelectors[ds.functionSelectors.length - 1];
                    ds.functionSelectors[selectorPosition] = lastSelector;
                    ds.facetAddressAndPosition[lastSelector].functionSelectorPosition = selectorPosition;
                }

                // Delete last selector
                ds.functionSelectors.pop();
                delete ds.facetAddressAndPosition[selector];
            }
        }

        emit DiamondCut(_facet, _selectors, _action);
    }

    // Fallback function handles all function calls
    fallback() external payable {
        DiamondStorage storage ds = diamondStorage();
        address facet = ds.facetAddressAndPosition[msg.sig].facetAddress;
        require(facet != address(0), "Function does not exist");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// Facet contracts
contract FacetA {
    // Storage layout must be compatible with Diamond
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.storage");

    struct DiamondStorage {
        mapping(bytes4 => address) functionToFacet;
        bytes4[] functionSelectors;
        address owner;
        // Facet-specific storage
        uint256 valueA;
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    function setValueA(uint256 _value) external {
        diamondStorage().valueA = _value;
    }

    function getValueA() external view returns (uint256) {
        return diamondStorage().valueA;
    }
}

contract FacetB {
    // Storage layout must be compatible with Diamond
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.storage");

    struct DiamondStorage {
        mapping(bytes4 => address) functionToFacet;
        bytes4[] functionSelectors;
        address owner;
        uint256 valueA; // maintain layout compatibility
        // Facet-specific storage
        string valueB;
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    function setValueB(string calldata _value) external {
        diamondStorage().valueB = _value;
    }

    function getValueB() external view returns (string memory) {
        return diamondStorage().valueB;
    }
}
```

### OpenZeppelin + Diamond-Standard Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IDiamondCut } from "@solidstate/contracts/proxy/diamond/IDiamondCut.sol";
import { SolidStateDiamond } from "@solidstate/contracts/proxy/diamond/SolidStateDiamond.sol";
import { OwnableInternal } from "@solidstate/contracts/access/ownable/OwnableInternal.sol";

// Diamond contract
contract DiamondOZ is SolidStateDiamond {
    constructor(IDiamondCut.FacetCut[] memory cuts) SolidStateDiamond(cuts) {
        // Set contract owner
        _setOwner(msg.sender);
    }
}

// Facet contract A
import { DiamondWritable } from "@solidstate/contracts/proxy/diamond/writable/DiamondWritable.sol";
import { DiamondWritableInternal } from "@solidstate/contracts/proxy/diamond/writable/DiamondWritableInternal.sol";

contract FacetAOZ is DiamondWritableInternal {
    // Storage layout using ERC-2535 pattern with namespaced storage
    bytes32 constant FACET_A_STORAGE_POSITION = keccak256("facetA.storage");

    struct FacetAStorage {
        uint256 valueA;
    }

    function facetAStorage() internal pure returns (FacetAStorage storage fs) {
        bytes32 position = FACET_A_STORAGE_POSITION;
        assembly {
            fs.slot := position
        }
    }

    function setValueA(uint256 _value) external {
        facetAStorage().valueA = _value;
    }

    function getValueA() external view returns (uint256) {
        return facetAStorage().valueA;
    }
}

// Facet contract B
contract FacetBOZ {
    // Storage layout using ERC-2535 pattern with namespaced storage
    bytes32 constant FACET_B_STORAGE_POSITION = keccak256("facetB.storage");

    struct FacetBStorage {
        string valueB;
    }

    function facetBStorage() internal pure returns (FacetBStorage storage fs) {
        bytes32 position = FACET_B_STORAGE_POSITION;
        assembly {
            fs.slot := position
        }
    }

    function setValueB(string calldata _value) external {
        facetBStorage().valueB = _value;
    }

    function getValueB() external view returns (string memory) {
        return facetBStorage().valueB;
    }
}

// Deployment script (not part of contracts)
/*
1. Deploy facets FacetAOZ and FacetBOZ
2. Create facet cuts array with function selectors for each facet
3. Deploy DiamondOZ with the facet cuts
*/
```

## Minimal Proxy (EIP-1167/Clones)

Extremely gas-efficient proxy deployment
Creates lightweight proxy clones that delegate to a single implementation
Not typically used for upgrades but for deploying many instances cheaply
Can be combined with Beacon pattern for upgradeable clones

### Custom Implementation

```solidity
// Implementation contract
contract MinimalImplementation {
    uint256 public value;
    address public owner;

    function initialize() public {
        require(owner == address(0), "Already initialized");
        owner = msg.sender;
        value = 42;
    }

    function setValue(uint256 _value) public {
        require(msg.sender == owner, "Only owner");
        value = _value;
    }
}

// Factory for creating minimal proxies
contract MinimalProxyFactory {
    // The bytecode for a minimal proxy (EIP-1167)
    bytes private constant MINIMAL_PROXY_BYTECODE = hex"3d602d80600a3d3981f3363d3d373d3d3d363d73";
    bytes private constant MINIMAL_PROXY_BYTECODE_SUFFIX = hex"5af43d82803e903d91602b57fd5bf3";

    function deploy(address implementation, bytes calldata initData) public returns (address proxy) {
        // Create the proxy creation bytecode: bytecode + implementation address + suffix
        bytes memory bytecode = abi.encodePacked(
            MINIMAL_PROXY_BYTECODE,
            implementation,
            MINIMAL_PROXY_BYTECODE_SUFFIX
        );

        // Deploy the proxy
        assembly {
            proxy := create(0, add(bytecode, 0x20), mload(bytecode))
        }

        // Initialize if needed
        if (initData.length > 0) {
            (bool success, ) = proxy.call(initData);
            require(success, "Initialization failed");
        }
    }
}
```

### OpenZeppelin Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

// Implementation contract
contract MinimalImplementationOZ is Initializable, OwnableUpgradeable {
    uint256 public value;

    function initialize() public initializer {
        __Ownable_init();
        value = 42;
    }

    function setValue(uint256 _value) public onlyOwner {
        value = _value;
    }
}

// Factory for creating minimal proxies
contract MinimalProxyFactoryOZ {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    function deploy() public returns (address proxy) {
        // Deploy a clone
        proxy = Clones.clone(implementation);

        // Initialize the proxy
        MinimalImplementationOZ(proxy).initialize();
    }

    // Deploy deterministic clone with CREATE2
    function deployDeterministic(bytes32 salt) public returns (address proxy) {
        proxy = Clones.cloneDeterministic(implementation, salt);
        MinimalImplementationOZ(proxy).initialize();
    }

    // Predict address for deterministic deployment
    function predictDeterministicAddress(bytes32 salt) public view returns (address) {
        return Clones.predictDeterministicAddress(implementation, salt, address(this));
    }
}
```

## Initializable Proxy

Uses initializer functions instead of constructors
Prevents multiple initializations through modifier checks
Common base for most proxy patterns

### Custom Implementation

```solidity
// Base initializable contract
contract Initializable {
    bool private initialized;

    modifier initializer() {
        require(!initialized, "Already initialized");
        _;
        initialized = true;
    }
}

// Implementation contract
contract InitializableContract is Initializable {
    uint256 public value;
    address public owner;

    function initialize(uint256 _value) public initializer {
        value = _value;
        owner = msg.sender;
    }

    function setValue(uint256 _value) public {
        require(msg.sender == owner, "Only owner");
        value = _value;
    }
}

// Proxy using initializable implementation
contract InitializableProxy {
    address public implementation;

    constructor(address _implementation, bytes memory _data) {
        implementation = _implementation;

        // Initialize if data provided
        if(_data.length > 0) {
            (bool success, ) = implementation.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    fallback() external payable {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), sload(0), 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
```

### OpenZeppelin Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

// Implementation contract
contract InitializableContractOZ is Initializable, OwnableUpgradeable {
    uint256 public value;

    function initialize(uint256 _value) public initializer {
        __Ownable_init();
        value = _value;
    }

    function setValue(uint256 _value) public onlyOwner {
        value = _value;
    }
}

// Deployment script (not part of contracts)
/*
1. Deploy InitializableContractOZ
2. Deploy ProxyAdmin
3. Deploy TransparentUpgradeableProxy with:
   - implementation: address of InitializableContractOZ
   - admin: address of ProxyAdmin
   - data: abi.encodeWithSignature("initialize(uint256)", 42)
*/
```

# Storage Patterns

---

## Eternal Storage Pattern

Separates storage into type-specific mappings
Implementation contracts access storage through getters/setters
Allows changing implementations without complex storage migrations
Offers stronger storage isolation

### Custom Implementation

```solidity
// Eternal storage contract
contract EternalStorage {
    address public owner;
    address public latestVersion;

    // Storage mappings by type
    mapping(bytes32 => uint256) private uintStorage;
    mapping(bytes32 => string) private stringStorage;
    mapping(bytes32 => address) private addressStorage;
    mapping(bytes32 => bytes) private bytesStorage;
    mapping(bytes32 => bool) private boolStorage;
    mapping(bytes32 => int256) private intStorage;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyLatestVersion() {
        require(msg.sender == latestVersion, "Only latest version");
        _;
    }

    // Set latest version contract that can use this storage
    function setLatestVersion(address _version) public onlyOwner {
        latestVersion = _version;
    }

    // Getters and setters for each type
    function getUint(bytes32 key) external view returns (uint256) {
        return uintStorage[key];
    }

    function setUint(bytes32 key, uint256 value) external onlyLatestVersion {
        uintStorage[key] = value;
    }

    function getString(bytes32 key) external view returns (string memory) {
        return stringStorage[key];
    }

    function setString(bytes32 key, string calldata value) external onlyLatestVersion {
        stringStorage[key] = value;
    }

    function getAddress(bytes32 key) external view returns (address) {
        return addressStorage[key];
    }

    function setAddress(bytes32 key, address value) external onlyLatestVersion {
        addressStorage[key] = value;
    }

    function getBool(bytes32 key) external view returns (bool) {
        return boolStorage[key];
    }

    function setBool(bytes32 key, bool value) external onlyLatestVersion {
        boolStorage[key] = value;
    }
}

// Logic contract using eternal storage
contract LogicV1 {
    EternalStorage public eternalStorage;

    // Storage keys
    bytes32 constant VALUE_KEY = keccak256("value");
    bytes32 constant OWNER_KEY = keccak256("owner");

    constructor(address _eternalStorage) {
        eternalStorage = EternalStorage(_eternalStorage);
    }

    modifier onlyOwner() {
        require(eternalStorage.getAddress(OWNER_KEY) == msg.sender, "Only owner");
        _;
    }

    function initialize() public {
        // Check if already initialized
        require(eternalStorage.getAddress(OWNER_KEY) == address(0), "Already initialized");
        eternalStorage.setAddress(OWNER_KEY, msg.sender);
        eternalStorage.setUint(VALUE_KEY, 42);
    }

    function setValue(uint256 _value) public onlyOwner {
        eternalStorage.setUint(VALUE_KEY, _value);
    }

    function getValue() public view returns (uint256) {
        return eternalStorage.getUint(VALUE_KEY);
    }
}

// Updated logic contract
contract LogicV2 {
    EternalStorage public eternalStorage;

    // Storage keys (same as V1 for compatibility)
    bytes32 constant VALUE_KEY = keccak256("value");
    bytes32 constant OWNER_KEY = keccak256("owner");
    // New storage keys
    bytes32 constant NAME_KEY = keccak256("name");

    constructor(address _eternalStorage) {
        eternalStorage = EternalStorage(_eternalStorage);
    }

    modifier onlyOwner() {
        require(eternalStorage.getAddress(OWNER_KEY) == msg.sender, "Only owner");
        _;
    }

    function setValue(uint256 _value) public onlyOwner {
        eternalStorage.setUint(VALUE_KEY, _value);
    }

    function getValue() public view returns (uint256) {
        return eternalStorage.getUint(VALUE_KEY);
    }

    // New functionality
    function setName(string calldata _name) public onlyOwner {
        eternalStorage.setString(NAME_KEY, _name);
    }

    function getName() public view returns (string memory) {
        return eternalStorage.getString(NAME_KEY);
    }
}
```

### OpenZeppelin-inspired Implementation (No direct OZ equivalent)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

// Eternal storage contract
contract EternalStorageOZ is Ownable {
    address public latestVersion;

    // Storage mappings by type
    mapping(bytes32 => uint256) private uintStorage;
    mapping(bytes32 => string) private stringStorage;
    mapping(bytes32 => address) private addressStorage;
    mapping(bytes32 => bytes) private bytesStorage;
    mapping(bytes32 => bool) private boolStorage;
    mapping(bytes32 => int256) private intStorage;

    event VersionChanged(address indexed previousVersion, address indexed newVersion);

    modifier onlyLatestVersion() {
        require(msg.sender == latestVersion, "Only latest version");
        _;
    }

    // Set latest version contract that can use this storage
    function setLatestVersion(address _version) public onlyOwner {
        emit VersionChanged(latestVersion, _version);
        latestVersion = _version;
    }

    // Getters and setters (only showing a few for brevity)
    function getUint(bytes32 key) external view returns (uint256) {
        return uintStorage[key];
    }

    function setUint(bytes32 key, uint256 value) external onlyLatestVersion {
        uintStorage[key] = value;
    }

    function getString(bytes32 key) external view returns (string memory) {
        return stringStorage[key];
    }

    function setString(bytes32 key, string calldata value) external onlyLatestVersion {
        stringStorage[key] = value;
    }

    // Additional getters/setters would follow same pattern
}

// Logic contract interface
interface ILogic {
    function initialize() external;
    function setValue(uint256 _value) external;
    function getValue() external view returns (uint256);
}

// Logic contract V1
contract LogicV1OZ is ILogic {
    EternalStorageOZ public eternalStorage;

    // Storage keys
    bytes32 constant VALUE_KEY = keccak256("value");
    bytes32 constant OWNER_KEY = keccak256("owner");

    constructor(address _eternalStorage) {
        eternalStorage = EternalStorageOZ(_eternalStorage);
    }

    modifier onlyOwner() {
        require(eternalStorage.getAddress(OWNER_KEY) == msg.sender, "Only owner");
        _;
    }

  function initialize() public override {
        // Check if already initialized
        require(eternalStorage.getAddress(OWNER_KEY) == address(0), "Already initialized");
        eternalStorage.setAddress(OWNER_KEY, msg.sender);
        eternalStorage.setUint(VALUE_KEY, 42);
    }

    function setValue(uint256 _value) public override onlyOwner {
        eternalStorage.setUint(VALUE_KEY, _value);
    }

    function getValue() public view override returns (uint256) {
        return eternalStorage.getUint(VALUE_KEY);
    }
}

// Logic contract V2
contract LogicV2OZ is ILogic {
    EternalStorageOZ public eternalStorage;

    // Storage keys (same as V1 for compatibility)
    bytes32 constant VALUE_KEY = keccak256("value");
    bytes32 constant OWNER_KEY = keccak256("owner");
    // New storage key
    bytes32 constant NAME_KEY = keccak256("name");

    constructor(address _eternalStorage) {
        eternalStorage = EternalStorageOZ(_eternalStorage);
    }

    modifier onlyOwner() {
        require(eternalStorage.getAddress(OWNER_KEY) == msg.sender, "Only owner");
        _;
    }

    // Keep V1 compatibility
    function initialize() public override {
        revert("Already initialized");
    }

    function setValue(uint256 _value) public override onlyOwner {
        eternalStorage.setUint(VALUE_KEY, _value * 2); // New logic (doubles the value)
    }

    function getValue() public view override returns (uint256) {
        return eternalStorage.getUint(VALUE_KEY);
    }

    // New functionality
    function setName(string calldata _name) public onlyOwner {
        eternalStorage.setString(NAME_KEY, _name);
    }

    function getName() public view returns (string memory) {
        return eternalStorage.getString(NAME_KEY);
    }
}
```

## Unstructured Storage Pattern

Uses specific storage slots for proxy-specific variables
Prevents storage collisions between proxy and implementation
Often used within other proxy patterns for storing implementation addresses

### Custom Implementation

```solidity
// Implementation contract
contract UnstructuredStorageImpl {
    // Storage location for implementation address
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    uint256 public value;

    function initialize() public {
        value = 42;
    }

    function setValue(uint256 _value) public {
        value = _value;
    }

    // Helper to get implementation slot
    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    // Helper to set implementation slot
    function _setImplementation(address impl) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, impl)
        }
    }
}

// Proxy using unstructured storage
contract UnstructuredStorageProxy {
    // Storage location for implementation address
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    // Storage location for admin address
    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    constructor(address _implementation, address _admin) {
        _setImplementation(_implementation);
        _setAdmin(_admin);
    }

    modifier onlyAdmin() {
        require(msg.sender == _getAdmin(), "Not admin");
        _;
    }

    // Helper to get implementation slot
    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    // Helper to set implementation slot
    function _setImplementation(address impl) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, impl)
        }
    }

    // Helper to get admin slot
    function _getAdmin() internal view returns (address admin) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            admin := sload(slot)
        }
    }

    // Helper to set admin slot
    function _setAdmin(address admin) internal {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, admin)
        }
    }

    // Admin function to upgrade implementation
    function upgradeTo(address _implementation) external onlyAdmin {
        _setImplementation(_implementation);
    }

    // Forward all calls to implementation
    fallback() external payable {
        address impl = _getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
```

### OpenZeppelin Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Upgrade.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

// Implementation contract
contract UnstructuredStorageImplOZ is Initializable, OwnableUpgradeable {
    uint256 public value;

    function initialize() public initializer {
        __Ownable_init();
        value = 42;
    }

    function setValue(uint256 _value) public onlyOwner {
        value = _value;
    }
}

// Upgradeable proxy with admin functions
contract UpgradeableProxyOZ is ERC1967Proxy, ERC1967Upgrade {
    constructor(address _logic, bytes memory _data)
        ERC1967Proxy(_logic, _data)
    {
        _changeAdmin(msg.sender);
    }

    modifier onlyAdmin() {
        require(msg.sender == _getAdmin(), "Not admin");
        _;
    }

    function upgradeTo(address newImplementation) external onlyAdmin {
        _upgradeToAndCall(newImplementation, bytes(""), false);
    }

    function upgradeToAndCall(address newImplementation, bytes memory data) external payable onlyAdmin {
        _upgradeToAndCall(newImplementation, data, true);
    }

    function changeAdmin(address newAdmin) external onlyAdmin {
        _changeAdmin(newAdmin);
    }

    function getAdmin() external view returns (address) {
        return _getAdmin();
    }

    function getImplementation() external view returns (address) {
        return _getImplementation();
    }
}
```

## Data Separation Pattern

Logic and storage in completely separate contracts
Logic contract calls methods on storage contract
Provides clear separation of concerns

### Custom Implementation

```solidity
// Storage contract
contract StorageContract {
    address public owner;
    address public logicContract;

    // Data
    uint256 public value;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyLogic() {
        require(msg.sender == logicContract, "Only logic contract");
        _;
    }

    function setLogicContract(address _logic) public onlyOwner {
        logicContract = _logic;
    }

    // Functions only callable by logic contract
    function setValue(uint256 _value) public onlyLogic {
        value = _value;
    }

    function setBalance(address _user, uint256 _balance) public onlyLogic {
        balances[_user] = _balance;
    }
}

// Logic contract V1
contract LogicContractV1 {
    StorageContract public storageContract;

    constructor(address _storageContract) {
        storageContract = StorageContract(_storageContract);
    }

    function setValue(uint256 _value) public {
        storageContract.setValue(_value);
    }

    function deposit() public payable {
        address user = msg.sender;
        uint256 currentBalance = storageContract.balances(user);
        storageContract.setBalance(user, currentBalance + msg.value);
    }
}

// Logic contract V2 with new functionality
contract LogicContractV2 {
    StorageContract public storageContract;

    constructor(address _storageContract) {
        storageContract = StorageContract(_storageContract);
    }

    function setValue(uint256 _value) public {
        // New validation
        require(_value > 0, "Value must be positive");
        storageContract.setValue(_value);
    }

    function deposit() public payable {
        address user = msg.sender;
        uint256 currentBalance = storageContract.balances(user);
        storageContract.setBalance(user, currentBalance + msg.value);
    }

    // New functionality
    function withdraw(uint256 amount) public {
        address user = msg.sender;
        uint256 currentBalance = storageContract.balances(user);
        require(currentBalance >= amount, "Insufficient balance");
        storageContract.setBalance(user, currentBalance - amount);
        payable(user).transfer(amount);
    }
}
```

### OpenZeppelin-inspired Implementation (No direct OZ equivalent)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// Storage contract
contract StorageContractOZ is Ownable {
    address public logicContract;

    // Data
    uint256 public value;
    mapping(address => uint256) public balances;

    event LogicContractChanged(address indexed previousLogic, address indexed newLogic);

    modifier onlyLogic() {
        require(msg.sender == logicContract, "Only logic contract");
        _;
    }

    function setLogicContract(address _logic) public onlyOwner {
        emit LogicContractChanged(logicContract, _logic);
        logicContract = _logic;
    }

    // Functions only callable by logic contract
    function setValue(uint256 _value) public onlyLogic {
        value = _value;
    }

    function setBalance(address _user, uint256 _balance) public onlyLogic {
        balances[_user] = _balance;
    }
}

// Logic interface
interface ILogicContract {
    function setValue(uint256 _value) external;
    function deposit() external payable;
}

// Logic contract V1
contract LogicContractV1OZ is ILogicContract, Ownable {
    StorageContractOZ public storageContract;

    constructor(address _storageContract) {
        storageContract = StorageContractOZ(_storageContract);
    }

    function setValue(uint256 _value) public override onlyOwner {
        storageContract.setValue(_value);
    }

    function deposit() public payable override {
        address user = msg.sender;
        uint256 currentBalance = storageContract.balances(user);
        storageContract.setBalance(user, currentBalance + msg.value);
    }
}

// Logic contract V2 with new functionality
contract LogicContractV2OZ is ILogicContract, Ownable, ReentrancyGuard {
    StorageContractOZ public storageContract;

    constructor(address _storageContract) {
        storageContract = StorageContractOZ(_storageContract);
    }

    function setValue(uint256 _value) public override onlyOwner {
        // New validation
        require(_value > 0, "Value must be positive");
        storageContract.setValue(_value);
    }

    function deposit() public payable override {
        address user = msg.sender;
        uint256 currentBalance = storageContract.balances(user);
        storageContract.setBalance(user, currentBalance + msg.value);
    }

    // New functionality
    function withdraw(uint256 amount) public nonReentrant {
        address user = msg.sender;
        uint256 currentBalance = storageContract.balances(user);
        require(currentBalance >= amount, "Insufficient balance");
        storageContract.setBalance(user, currentBalance - amount);
        payable(user).transfer(amount);
    }
}
```

# Additional Upgrade Mechanisms

---

## Registry Pattern

Central registry tracks latest contract versions
Users query registry before interacting with system
Doesn't update existing state but redirects to new instances

## Custom Implementation

```solidity
// Registry contract
contract ContractRegistry {
    address public owner;
    mapping(bytes32 => address) public contractAddresses;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function setContractAddress(bytes32 _name, address _address) public onlyOwner {
        contractAddresses[_name] = _address;
    }

    function getContractAddress(bytes32 _name) public view returns (address) {
        return contractAddresses[_name];
    }
}

// Contract that uses registry
contract ContractUser {
    ContractRegistry public registry;
    bytes32 public constant TOKEN_CONTRACT = keccak256("TOKEN");
    bytes32 public constant VAULT_CONTRACT = keccak256("VAULT");

    constructor(address _registry) {
        registry = ContractRegistry(_registry);
    }

    function useTokenContract() public view returns (address) {
        address tokenContract = registry.getContractAddress(TOKEN_CONTRACT);
        require(tokenContract != address(0), "Token contract not set");
        return tokenContract;
    }

    function useVaultContract() public view returns (address) {
        address vaultContract = registry.getContractAddress(VAULT_CONTRACT);
        require(vaultContract != address(0), "Vault contract not set");
        return vaultContract;
    }
}
```

### OpenZeppelin-inspired Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

// Registry contract
contract ContractRegistryOZ is Ownable {
    mapping(bytes32 => address) private contractAddresses;

    event ContractAddressChanged(bytes32 indexed name, address indexed newAddress);

    function setContractAddress(bytes32 _name, address _address) public onlyOwner {
        contractAddresses[_name] = _address;
        emit ContractAddressChanged(_name, _address);
    }

    function getContractAddress(bytes32 _name) public view returns (address) {
        return contractAddresses[_name];
    }
}

// Contract that uses registry
contract ContractUserOZ {
    ContractRegistryOZ public registry;
    bytes32 public constant TOKEN_CONTRACT = keccak256("TOKEN");
    bytes32 public constant VAULT_CONTRACT = keccak256("VAULT");

    constructor(address _registry) {
        registry = ContractRegistryOZ(_registry);
    }

    function useTokenContract() public view returns (address) {
        address tokenContract = registry.getContractAddress(TOKEN_CONTRACT);
        require(tokenContract != address(0), "Token contract not set");
        return tokenContract;
    }

    function useVaultContract() public view returns (address) {
        address vaultContract = registry.getContractAddress(VAULT_CONTRACT);
        require(vaultContract != address(0), "Vault contract not set");
        return vaultContract;
    }
}
```

## Satellite Pattern

Core contract delegates specific functions to satellite contracts
Satellites can be replaced individually
Core contract remains stable while functionality can evolve

### Custom Implementation

```solidity
// Core contract
contract CoreContract {
    address public owner;
    mapping(bytes4 => address) public satellites;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function setSatellite(bytes4 _selector, address _satellite) public onlyOwner {
        satellites[_selector] = _satellite;
    }

    fallback() external payable {
        address satellite = satellites[msg.sig];
        require(satellite != address(0), "Satellite not found");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), satellite, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// Satellite contracts
contract SatelliteA {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }
}

contract SatelliteB {
    string public name;

    function setName(string calldata _name) public {
        name = _name;
    }

    function getName() public view returns (string memory) {
        return name;
    }
}
```

### OpenZeppelin-inspired Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

// Core contract
contract CoreContractOZ is Ownable {
    mapping(bytes4 => address) private satellites;

    event SatelliteChanged(bytes4 indexed selector, address indexed satellite);

    function setSatellite(bytes4 _selector, address _satellite) public onlyOwner {
        satellites[_selector] = _satellite;
        emit SatelliteChanged(_selector, _satellite);
    }

    fallback() external payable {
        address satellite = satellites[msg.sig];
        require(satellite != address(0), "Satellite not found");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), satellite, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// Satellite contracts
contract SatelliteAOZ {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }
}

contract SatelliteBOZ {
    string public name;

    function setName(string calldata _name) public {
        name = _name;
    }

    function getName() public view returns (string memory) {
        return name;
    }
}
```

## State Migration Pattern

Explicitly moves state from old to new contract
Requires cooperation from users to migrate
Often combined with Registry pattern

### Custom Implementation

```solidity
// Interface for shared functionality
interface IContract {
    function getValue() external view returns (uint256);
    function transferOwnership(address newOwner) external;
}

// V1 contract
contract ContractV1 is IContract {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function setValue(uint256 _value) public onlyOwner {
        value = _value;
    }

    function getValue() public view override returns (uint256) {
        return value;
    }

    function transferOwnership(address newOwner) public override onlyOwner {
        owner = newOwner;
    }
}

// V2 contract with migration support
contract ContractV2 is IContract {
    address public owner;
    uint256 public value;
    string public name; // New state variable

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function setValue(uint256 _value) public onlyOwner {
        value = _value;
    }

    function getValue() public view override returns (uint256) {
        return value;
    }

    function setName(string calldata _name) public onlyOwner {
        name = _name;
    }

    function transferOwnership(address newOwner) public override onlyOwner {
        owner = newOwner;
    }

    // Migration function
    function migrateFrom(address _oldContract) public onlyOwner {
        IContract oldContract = IContract(_oldContract);
        value = oldContract.getValue();
        // No need to migrate name as it's new

        // Take ownership of old contract and disable it
        oldContract.transferOwnership(address(this));
    }
}
```

### OpenZeppelin Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

// V1 contract
contract ContractV1OZ is Ownable {
    uint256 public value;

    function setValue(uint256 _value) public onlyOwner {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }
}

// V2 contract with migration support
contract ContractV2OZ is Ownable {
    uint256 public value;
    string public name; // New state variable
    bool public migrated;

    event MigrationCompleted(address indexed oldContract);

    function setValue(uint256 _value) public onlyOwner {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }

    function setName(string calldata _name) public onlyOwner {
        name = _name;
    }

    // Migration function
    function migrateFrom(address _oldContract) public onlyOwner {
        require(!migrated, "Already migrated");

        ContractV1OZ oldContract = ContractV1OZ(_oldContract);
        value = oldContract.getValue();
        // No need to migrate name as it's new

        // Take ownership of old contract to disable it
        oldContract.transferOwnership(address(this));

        migrated = true;
        emit MigrationCompleted(_oldContract);
    }
}
```

## Metamorphic Contracts

Uses CREATE2 with a deterministic address
Self-destructs and redeploys to same address with new code
Controversial due to potential security implications

### Custom Implementation

```solidity
// Factory for metamorphic contracts
contract MetamorphicFactory {
    event ContractCreated(address addr, uint256 salt);
    event ContractDestroyed(address addr);

    // Deploy contract with CREATE2
    function deploy(bytes memory bytecode, uint256 salt) public returns (address addr) {
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(extcodesize(addr)) { revert(0, 0) }
        }
        emit ContractCreated(addr, salt);
    }

    // Helper to compute the address before deployment
    function computeAddress(bytes memory bytecode, uint256 salt) public view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(bytecode)
        )))));
    }
}

// Self-destructible contract
contract MetamorphicContract {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function setValue(uint256 _value) public {
        value = _value;
    }

    function destroy() public onlyOwner {
        selfdestruct(payable(owner));
    }
}

// New version contract
contract MetamorphicContractV2 {
    address public owner;
    uint256 public value;
    string public name; // New variable

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function setValue(uint256 _value) public {
        value = _value;
    }

    function setName(string calldata _name) public {
        name = _name;
    }

    function destroy() public onlyOwner {
        selfdestruct(payable(owner));
    }
}
```

### OpenZeppelin Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

// Factory for metamorphic contracts
contract MetamorphicFactoryOZ {
    event ContractCreated(address addr, bytes32 salt);
    event ContractDestroyed(address addr);

    // Deploy contract with CREATE2
    function deploy(bytes memory bytecode, bytes32 salt) public returns (address addr) {
        addr = Create2.deploy(0, salt, bytecode);
        emit ContractCreated(addr, salt);
    }

    // Helper to compute the address before deployment
    function computeAddress(bytes memory bytecode, bytes32 salt) public view returns (address) {
        return Create2.computeAddress(salt, keccak256(abi.encodePacked(
            type(MetamorphicContractOZ).creationCode,
            abi.encode(bytecode)
        )));
    }
}

// Self-destructible contract
contract MetamorphicContractOZ is Ownable {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function destroy() public onlyOwner {
        selfdestruct(payable(owner()));
    }
}

// New version contract
contract MetamorphicContractV2OZ is Ownable {
    uint256 public value;
    string public name; // New variable

    function setValue(uint256 _value) public {
        value = _value;
    }

    function setName(string calldata _name) public {
        name = _name;
    }

    function destroy() public onlyOwner {
        selfdestruct(payable(owner()));
    }
}
```

## Proxy Factory Pattern

Factory deploys new proxies pointing to implementations
Often combined with other proxy patterns
Useful for managing multiple proxy instances

### Custom Implementation
```solidity
// Implementation contract
contract FactoryImplementation {
    uint256 public value;
    address public owner;
    
    function initialize(address _owner) public {
        require(owner == address(0), "Already initialized");
        owner = _owner;
        value = 42;
    }
    
    function setValue(uint256 _value) public {
        require(msg.sender == owner, "Only owner");
        value = _value;
    }
}

// Proxy contract
contract FactoryProxy {
    address public implementation;
    
    constructor(address _implementation, bytes memory _data) {
        implementation = _implementation;
        
        // Initialize the proxy
        if(_data.length > 0) {
            (bool success, ) = implementation.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }
    
    fallback() external payable {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), sload(0), 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
    
    receive() external payable {}
}

// Factory to create proxies
contract ProxyFactory {
    address public implementation;
    address public owner;
    
    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    function setImplementation(address _implementation) public onlyOwner {
        implementation = _implementation;
    }
    
    function createProxy(address _owner) public returns (address) {
        bytes memory initData = abi.encodeWithSignature("initialize(address)", _owner);
        FactoryProxy proxy = new FactoryProxy(implementation, initData);
        return address(proxy);
    }
}
```
### OpenZeppelin Implementation
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

// Implementation contract
contract FactoryImplementationOZ is Initializable, OwnableUpgradeable {
    uint256 public value;
    
    function initialize() public initializer {
        __Ownable_init();
        value = 42;
    }
    
    function setValue(uint256 _value) public onlyOwner {
        value = _value;
    }
}

// Factory to create proxies
contract ProxyFactoryOZ is Ownable {
    address public implementation;
    mapping(address => address) public userToProxy;
    
    event ProxyCreated(address indexed user, address indexed proxy);
    
    constructor(address _implementation) {
        implementation = _implementation;
    }
    
    function setImplementation(address _implementation) public onlyOwner {
        implementation = _implementation;
    }
    
    function createProxy() public returns (address proxy) {
        // Create a clone
        proxy = Clones.clone(implementation);
        
        // Initialize the proxy
        FactoryImplementationOZ(proxy).initialize();
        
        // Transfer ownership to the caller
        FactoryImplementationOZ(proxy).transferOwnership(msg.sender);
        
        // Store the mapping
        userToProxy[msg.sender] = proxy;
        
        emit ProxyCreated(msg.sender, proxy);
    }
    
    // Create deterministic proxy
    function createDeterministicProxy(bytes32 salt) public returns (address proxy) {
        proxy = Clones.cloneDeterministic(implementation, keccak256(abi.encodePacked(msg.sender, salt)));
        
        // Initialize the proxy
        FactoryImplementationOZ(proxy).initialize();
        
        // Transfer ownership to the caller
        FactoryImplementationOZ(proxy).transferOwnership(msg.sender);
        
        // Store the mapping
        userToProxy[msg.sender] = proxy;
        
        emit ProxyCreated(msg.sender, proxy);
    }
    
    // Predict the address for a deterministic proxy
    function predictDeterministicAddress(bytes32 salt) public view returns (address) {
        return Clones.predictDeterministicAddress(
            implementation,
            keccak256(abi.encodePacked(msg.sender, salt)),
            address(this)
        );
    }
}
```
