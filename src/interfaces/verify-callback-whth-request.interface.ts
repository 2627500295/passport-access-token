import {VerifiedCallback} from "./verified-callback.interface";
import {Request} from "express";

export interface VerifyCallbackWithRequest {
  (req: Request, payload: any, done: VerifiedCallback): void;
}