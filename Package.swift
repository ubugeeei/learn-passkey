// swift-tools-version: 6.1

import PackageDescription

let package = Package(
  name: "LearnPasskey",
  platforms: [
    .macOS(.v15),
    .iOS(.v17),
  ],
  products: [
    .library(name: "PasskeyCore", targets: ["PasskeyCore"]),
    .library(name: "PasskeyClient", targets: ["PasskeyClient"]),
    .library(name: "PasskeyServer", targets: ["PasskeyServer"]),
    .library(name: "PasskeyHTTP", targets: ["PasskeyHTTP"]),
    .library(name: "PasskeyPersistence", targets: ["PasskeyPersistence"]),
    .executable(name: "PasskeyServerCLI", targets: ["PasskeyServerCLI"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.15.1"),
    .package(url: "https://github.com/apple/swift-nio.git", exact: "2.101.2"),
    .package(url: "https://github.com/swiftlang/swift-testing.git", exact: "6.2.4"),
  ],
  targets: [
    .systemLibrary(
      name: "CSQLite",
      pkgConfig: "sqlite3",
      providers: [
        .apt(["libsqlite3-dev"]),
        .brew(["sqlite3"]),
      ]
    ),
    .target(name: "PasskeyCore"),
    .target(
      name: "PasskeyClient",
      dependencies: ["PasskeyCore"]
    ),
    .target(
      name: "PasskeyServer",
      dependencies: [
        "PasskeyCore",
        .product(name: "Crypto", package: "swift-crypto"),
      ]
    ),
    .target(
      name: "PasskeyHTTP",
      dependencies: [
        "PasskeyCore",
        "PasskeyServer",
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOHTTP1", package: "swift-nio"),
        .product(name: "NIOPosix", package: "swift-nio"),
      ]
    ),
    .target(
      name: "PasskeyPersistence",
      dependencies: [
        "CSQLite",
        "PasskeyCore",
        "PasskeyServer",
      ]
    ),
    .executableTarget(
      name: "PasskeyServerCLI",
      dependencies: [
        "PasskeyHTTP",
        "PasskeyPersistence",
        "PasskeyServer",
      ]
    ),
    .testTarget(
      name: "PasskeyCoreTests",
      dependencies: [
        "PasskeyCore",
        .product(name: "Testing", package: "swift-testing"),
      ]
    ),
    .testTarget(
      name: "PasskeyServerTests",
      dependencies: [
        "PasskeyCore",
        "PasskeyServer",
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "Testing", package: "swift-testing"),
      ]
    ),
    .testTarget(
      name: "PasskeyHTTPTests",
      dependencies: [
        "PasskeyCore",
        "PasskeyHTTP",
        "PasskeyServer",
        .product(name: "Testing", package: "swift-testing"),
      ]
    ),
    .testTarget(
      name: "PasskeyClientTests",
      dependencies: [
        "PasskeyClient",
        "PasskeyCore",
        .product(name: "Testing", package: "swift-testing"),
      ]
    ),
    .testTarget(
      name: "PasskeyPersistenceTests",
      dependencies: [
        "PasskeyCore",
        "PasskeyPersistence",
        "PasskeyServer",
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "Testing", package: "swift-testing"),
      ]
    ),
  ]
)
