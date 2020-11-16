import {Request} from "express";
import { parse } from "url";

function parseAuthHeader(value: string) {
  if (typeof value !== 'string') return null;
  const matches = value.match(/(\S+)\s+(\S+)/);
  return matches && { scheme: matches[1], value: matches[2] };
}

const AUTH_HEADER = "authorization";
const BEARER_AUTH_SCHEME = 'bearer';
const JWT_AUTH_SCHEME = "JWT";

export class Extract {
  public static fromHeader(name: string) {
    return function (request) {
      return request?.headers?.[name] ?? null;
    }
  }

  public static fromCookie(name: string, signed: boolean = false) {
    return function (request: Request): string | null {
      const cookies = request[signed ? 'signedCookies' : 'cookies'];
      if (!cookies) {
        throw new TypeError('Maybe you forgot to use cookie-parser?');
      }
      return cookies?.[name] ?? null;
    }
  }

  public static fromBodyField(name: string) {
    return function (request: Request) {
      return request?.body?.[name] ?? null;
    };
  }

  public static fromUrlQueryParameter(name: string) {
    return function (request: Request) {
      const url = parse(request.url, true);
      return url.query?.[name] ?? null;
    };
  }

  public static fromAuthHeaderWithScheme(scheme: string) {
    const schemeLower = scheme.toLowerCase();
    return function (request: Request) {
      if (request.headers[AUTH_HEADER]) {
        const authParams = parseAuthHeader(request.headers[AUTH_HEADER]);
        if (schemeLower === authParams?.scheme?.toLowerCase()) return authParams?.value ?? null;
      }
      return null;
    };
  }

  public static fromAuthHeaderAsBearerToken() {
    return Extract.fromAuthHeaderWithScheme(BEARER_AUTH_SCHEME);
  }

  public static fromAuthHeaderAsJwtToken() {
    return Extract.fromAuthHeaderWithScheme(JWT_AUTH_SCHEME);
  }

  public static fromExtractors(extractors) {
    if (!Array.isArray(extractors)) throw new TypeError('extractors.fromExtractors expects an array');
    return function (request: Request) {
      let token = null, index = 0;
      while(!token && index < extractors.length) {
        token = extractors[index].call(this, request);
        index ++;
      }
      return token;
    }
  }
}
