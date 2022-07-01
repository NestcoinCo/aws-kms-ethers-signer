export interface SignatureResponse {
  /**
   * Full RPC compatible signature, usually 65 bytes in length
   * @type {string}
   * @memberof SignatureResponse
   */
  sig: string;
  /**
   * s component of signature
   * @type {string}
   * @memberof SignatureResponse
   */
  s: string;
  /**
   * r component of signature
   * @type {string}
   * @memberof SignatureResponse
   */
  r: string;
  /**
   * v component of signature
   * @type {string}
   * @memberof SignatureResponse
   */
  v: string;
}
