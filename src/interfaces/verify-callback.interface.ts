import {VerifiedCallback} from "./verified-callback.interface";

export interface VerifyCallback {
  (payload: any, done: VerifiedCallback): void;
}

