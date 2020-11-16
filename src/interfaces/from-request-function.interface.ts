import {Request} from "express";

export interface FromRequestFunction {
  (req: Request): string | null;
}