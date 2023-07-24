import { QueryParameterBag } from "@aws-sdk/types";

/**
 * This function does not encodeURIComponent the values,
 * because the result is meant to be used in a JS object.
 */
export const queryParameterBagToQueryString = (
  query: QueryParameterBag
): string => {
  const keys: Array<string> = [];
  const serialized: Record<string, string> = {};

  for (const key of Object.keys(query)) {
    keys.push(key);
    const value = query[key];

    if (value === null) {
      serialized[key] = `${key}=`;
      continue;
    }

    if (Array.isArray(value)) {
      serialized[key] = value.map((v) => `${key}=${v}`).join('&');
      continue;
    }

    serialized[key] = `${key}=${value as string}`;
  }

  return keys
    .map((key) => serialized[key])
    .join("&");
};
