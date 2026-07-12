import Foundation

/// Sendable transport-neutral request data copied out of a NIO channel.
public struct HTTPRequestData: Sendable {
  /// Uppercase HTTP method used for route selection.
  public let method: String
  /// URL path without a query string.
  public let path: String
  /// Lowercased header names copied from the network request.
  public let headers: [String: String]
  /// Fully buffered request body after the transport size limit is applied.
  public let body: Data
  /// Correlation identifier returned to the caller and used in server logs.
  public let requestID: String

  /// Creates the transport-neutral value consumed by `PasskeyAPI`.
  public init(
    method: String,
    path: String,
    headers: [String: String],
    body: Data,
    requestID: String
  ) {
    self.method = method
    self.path = path
    self.headers = headers
    self.body = body
    self.requestID = requestID
  }
}

/// Transport-neutral response data written back by the NIO adapter.
public struct HTTPResponseData: Sendable {
  /// Numeric HTTP status code.
  public let status: Int
  /// Response headers written by the network adapter.
  public let headers: [String: String]
  /// Encoded response body; empty for status codes such as 204.
  public let body: Data

  /// Creates a transport-neutral response with optional headers and body.
  public init(status: Int, headers: [String: String] = [:], body: Data = Data()) {
    self.status = status
    self.headers = headers
    self.body = body
  }
}

struct APIErrorResponse: Codable, Sendable {
  let code: String
  let message: String
  let requestID: String
}
