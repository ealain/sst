import { CloudFrontHeaders, CloudFrontRequest, CloudFrontRequestHandler } from "aws-lambda";
import { SignatureV4 } from "@aws-sdk/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";
import { request } from "express";

export const handler: CloudFrontRequestHandler = async (event) => {
  const req = event.Records[0].cf.request;
  console.log('signing', req)

  if (!isLambdaUrlRequest(req)) return req;

  const region = getRegionFromLambdaUrl(req.origin?.custom?.domainName || '');
  const sigv4 = getSigV4(region);
  console.log('sig', sigv4)

  const originDomainName = req.origin?.custom?.domainName;
  if (!originDomainName) throw new Error('Origin domain is missing');

  // fix host header and pass along the original host header
  const originalHost = req.headers.host[0].value;
  req.headers['x-forwarded-host'] = [{ key: 'x-forwarded-host', value: originalHost }];
  req.headers.host = [{ key: 'host', value: originDomainName }];

  const headerBag = cfHeadersToHeaderBag(req.headers);
  // don't sign x-forwarded-for b/c it changes from hop to hop
  delete headerBag['x-forwarded-for'];
  let body: string | undefined;
  if (req.body?.data) {
    body = Buffer.from(req.body.data, 'base64').toString();
  }
  const query = queryStringToQuery(req.querystring);
  const signed = await sigv4.sign({
    method: req.method,
    headers: headerBag,
    hostname: headerBag.host,
    path: req.uri,
    body,
    query,
    protocol: 'https',
  });
  console.log('method', req.method)
  console.log('method e', request.method)
  req.headers = headerBagToCfHeaders(signed.headers);
  console.log('headers', req.headers);
  console.log('req', JSON.stringify(req));

  return req;
};

const isLambdaUrlRequest = (request: CloudFrontRequest) => {
  return /[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws/.test(request.origin?.custom?.domainName || '');
}

const getSigV4 = (region: string) => {
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  const sessionToken = process.env.AWS_SESSION_TOKEN;
  if (!region) throw new Error('AWS_REGION missing');
  if (!accessKeyId) throw new Error('AWS_ACCESS_KEY_ID missing');
  if (!secretAccessKey) throw new Error('AWS_SECRET_ACCESS_KEY missing');
  if (!sessionToken) throw new Error('AWS_SESSION_TOKEN missing');
  console.log('ak', accessKeyId)
  console.log('sk', secretAccessKey)
  console.log('sk', secretAccessKey.replace(/\//g, '\\/'))
  console.log('st', sessionToken)
  return new SignatureV4({
    service: 'lambda',
    region,
    credentials: {
      accessKeyId,
      secretAccessKey,
      sessionToken,
    },
    sha256: Sha256,
    applyChecksum: false,
  });
}


type HeaderBag = Record<string, string>;
/**
 * Converts CloudFront headers (can have array of header values) to simple
 * header bag (object) required by `sigv4.sign`
 */
const cfHeadersToHeaderBag = (cfHeaders: CloudFrontHeaders): HeaderBag => {
  let headerBag: HeaderBag = {};
  for (const [header, values] of Object.entries(cfHeaders)) {
    headerBag[header] = values[0].value;
  }
  return headerBag;
}

/**
 * Converts simple header bag (object) to CloudFront headers
 */
const headerBagToCfHeaders = (headerBag: HeaderBag): CloudFrontHeaders => {
  const cfHeaders: CloudFrontHeaders = {};
  for (const [header, value] of Object.entries(headerBag)) {
    cfHeaders[header] = [{ key: header, value }];
  }
  return cfHeaders;
}

/**
 * Converts `CloudFrontRequest`'s querystring into `HttpRequest`'s query
 */
const queryStringToQuery = (querystring: string): Record<string, string> => {
  const query: Record<string, string> = {};
  const kvPairs = querystring.split('&').filter(Boolean);
  for (const kvPair of kvPairs) {
    const [key, value] = kvPair.split('=');
    if (key && value) query[key] = value;
  }
  return query;
}

const getRegionFromLambdaUrl = (url: string): string => {
  const region = url.split('.').at(2);
  if (!region) throw new Error("Region couldn't be extracted from Lambda Function URL");
  return region;
}
