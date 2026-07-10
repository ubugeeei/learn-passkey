import Foundation

public struct HTTPRequestData: Sendable {
  public let method: String
  public let path: String
  public let headers: [String: String]
  public let body: Data
  public let requestID: String

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

public struct HTTPResponseData: Sendable {
  public let status: Int
  public let headers: [String: String]
  public let body: Data

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
