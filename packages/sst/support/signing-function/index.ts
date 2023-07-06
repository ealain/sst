import {
  CloudFrontHeaders,
  CloudFrontRequest,
  CloudFrontRequestHandler,
} from "aws-lambda";
import { SignatureV4 } from "@aws-sdk/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";
import { request } from "express";
import {
  cfHeadersToHeaderBag,
  getRegionFromLambdaUrl,
  getSigV4,
  headerBagToCfHeaders,
  isLambdaUrlRequest,
  queryStringToQuery,
} from "./helpers";

export const handler: CloudFrontRequestHandler = async (event) => {
  const request = event.Records[0].cf.request;
  const domainName = request.origin?.custom?.domainName;

  if (!domainName || !isLambdaUrlRequest(domainName)) return request;

  const region = getRegionFromLambdaUrl(domainName);
  const sigv4 = getSigV4(region);

  // TODO: 'x-forwarded-host' is already set, consider removing this
  // TODO: A piori, keep 'host'
  // fix host header and pass along the original host header
  const originalHost = request.headers.host[0].value;
  request.headers["x-forwarded-host"] = [
    { key: "x-forwarded-host", value: originalHost },
  ];
  request.headers.host = [{ key: "host", value: domainName }];

  const headerBag = cfHeadersToHeaderBag(request.headers);
  // don't sign x-forwarded-for b/c it changes from hop to hop
  delete headerBag["x-forwarded-for"];

  const requestToSign = {
    method: request.method,
    headers: headerBag,
    hostname: headerBag.host,
    path: request.uri,
    query: queryStringToQuery(request.querystring),
    protocol: "https",
  };

  if (!request.body?.data) {
    const signed = await sigv4.sign({
      ...requestToSign,
      body: undefined,
    });
    request.headers = headerBagToCfHeaders(signed.headers);

    return request;
  }

  const signed = await sigv4.sign({
    ...requestToSign,
    body: Buffer.from(request.body.data, "base64").toString(),
  });
  request.headers = headerBagToCfHeaders(signed.headers);

  return request;
};
